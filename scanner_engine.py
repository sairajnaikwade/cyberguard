"""
CyberGuard — Scanner engine
Wraps python-nmap and performs CVE lookups against NIST NVD.

Improvements:
- Extracts product + version from Nmap for precise NVD queries
- Prefers CPE-based matching when available
- Filters CVEs published within last 10 years (configurable)
- Removes duplicate CVEs across all services
- Attaches confidence score (0–100) and match_type (version_specific | generic)
- Risk scoring weights version-specific CVEs higher
"""

import nmap
import socket
import re
import requests
import threading
import time
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from models import db, ScanResult, NvdCache

# ── Constants ────────────────────────────────────────────────────────────────
NVD_API        = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
SEVERITY_SCORE = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}

# How many years back to include CVEs (0 = no filter)
CVE_MAX_AGE_YEARS = int(os.environ.get('CVE_MAX_AGE_YEARS', '10'))

# How many CVEs to fetch per query
NVD_RESULTS_PER_PAGE = int(os.environ.get('NVD_RESULTS_PER_PAGE', '10'))

# Mandatory delay between NVD API calls (seconds) to respect rate limits
NVD_RATE_LIMIT_DELAY = 6


def query_shodan_host(ip: str) -> dict:
    shodan_key = os.environ.get('SHODAN_API_KEY')
    if not shodan_key:
        return {}
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {'key': shodan_key}
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip':          data.get('ip_str'),
                'isp':         data.get('isp'),
                'asn':         data.get('asn'),
                'org':         data.get('org'),
                'country':     data.get('country_name'),
                'city':        data.get('city'),
                'ports':       data.get('ports', []),
                'hostnames':   data.get('hostnames', []),
                'last_update': data.get('last_update'),
            }
    except Exception:
        pass
    return {}


def send_critical_email_alert(user_email: str, scan_target: str, critical_cves: list):
    smtp_server   = os.environ.get('SMTP_SERVER', 'localhost')
    try:
        smtp_port = int(os.environ.get('SMTP_PORT', '1025'))
    except ValueError:
        smtp_port = 1025
    smtp_user     = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    smtp_from     = os.environ.get('SMTP_FROM', 'alerts@cyberguard.local')

    msg             = MIMEMultipart()
    msg['From']     = smtp_from
    msg['To']       = user_email
    msg['Subject']  = f"🛡 [CyberGuard Alert] Critical Vulnerabilities Detected on {scan_target}"

    body = (
        f"Hello,\n\nCyberGuard has detected {len(critical_cves)} critical vulnerability/vulnerabilities "
        f"during a scan on your target: {scan_target}.\n\nCritical CVEs Detected:\n"
    )
    for cve in critical_cves:
        body += f"\n- {cve['cve']} (CVSS: {cve['cvss']}, Confidence: {cve.get('confidence', 0)}%): {cve['desc']}\n"
    body += "\nPlease review these findings immediately in the CyberGuard dashboard.\n\nBest regards,\nCyberGuard Security Team\n"

    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=5)
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(smtp_from, user_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"SMTP Error: failed to send email to {user_email}: {e}")


# ── Date filter helper ────────────────────────────────────────────────────────
def _is_recent_cve(published_str: str | None, max_age_years: int) -> bool:
    """Return True if the CVE was published within max_age_years. Always True if max_age_years=0."""
    if max_age_years <= 0 or not published_str:
        return True
    try:
        # NVD uses ISO-8601 e.g. "2021-08-17T15:15:00.000"
        pub_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        if pub_date.tzinfo is None:
            pub_date = pub_date.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_years * 365)
        return pub_date >= cutoff
    except Exception:
        return True


# ── CVE score / severity helpers ─────────────────────────────────────────────
def _extract_cvss(cve_data: dict) -> tuple[float, str]:
    """Extract base CVSS score and severity from NVD CVE object."""
    metrics  = cve_data.get('metrics', {})
    cvss_v31 = metrics.get('cvssMetricV31', [])
    cvss_v30 = metrics.get('cvssMetricV30', [])
    cvss_v2  = metrics.get('cvssMetricV2', [])

    base_score = 0.0
    if cvss_v31:
        base_score = cvss_v31[0].get('cvssData', {}).get('baseScore', 0.0)
    elif cvss_v30:
        base_score = cvss_v30[0].get('cvssData', {}).get('baseScore', 0.0)
    elif cvss_v2:
        base_score = cvss_v2[0].get('cvssData', {}).get('baseScore', 0.0)

    if base_score >= 9.0:
        severity = 'critical'
    elif base_score >= 7.0:
        severity = 'high'
    elif base_score >= 4.0:
        severity = 'medium'
    else:
        severity = 'low'

    return base_score, severity


# ── Confidence scoring ────────────────────────────────────────────────────────
def _compute_confidence(match_type: str, has_version: bool, cvss_score: float) -> int:
    """
    Returns a confidence score 0–100.
    - version_specific + CPE match: 85–100
    - version_specific keyword:      60–84
    - generic (service only):        20–59
    CVSS acts as a minor modifier.
    """
    if match_type == 'version_specific':
        base = 80 if has_version else 65
    else:
        base = 35

    # Add up to 15 pts based on CVSS (higher = more relevant typically)
    cvss_bonus = int(min(cvss_score / 10.0 * 15, 15))
    return min(100, base + cvss_bonus)


# ── NVD API query (single call) ───────────────────────────────────────────────
def _nvd_fetch(params: dict, retries: int = 3) -> list:
    """Perform a single NVD API call and return raw 'vulnerabilities' list."""
    time.sleep(NVD_RATE_LIMIT_DELAY)
    for attempt in range(retries):
        try:
            resp = requests.get(NVD_API, params=params, timeout=12)
            if resp.status_code == 200:
                return resp.json().get('vulnerabilities', [])
            elif resp.status_code in (403, 503):
                time.sleep(NVD_RATE_LIMIT_DELAY)
            else:
                time.sleep(2)
        except Exception:
            time.sleep(2)
    return []


# ── Parse raw NVD items into vuln dicts ──────────────────────────────────────
def _parse_nvd_items(
    raw_items: list,
    port: int,
    service_name: str,
    match_type: str,
    has_version: bool,
    max_age_years: int = CVE_MAX_AGE_YEARS,
) -> list[dict]:
    """Convert NVD raw items into normalised vuln dicts with confidence/match_type."""
    results = []
    for item in raw_items:
        cve_data = item.get('cve', {})
        cve_id   = cve_data.get('id')
        if not cve_id:
            continue

        # Date filter
        published = cve_data.get('published')
        if not _is_recent_cve(published, max_age_years):
            continue

        # Description (prefer English)
        descriptions = cve_data.get('descriptions', [])
        desc_val = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            descriptions[0].get('value', 'No description available.') if descriptions else 'No description available.'
        )

        base_score, severity = _extract_cvss(cve_data)
        confidence = _compute_confidence(match_type, has_version, base_score)

        results.append({
            'cve':        cve_id,
            'desc':       desc_val,
            'severity':   severity,
            'cvss':       base_score,
            'port':       port,
            'service':    service_name,
            'match_type': match_type,
            'confidence': confidence,
            'published':  published or '',
        })
    return results


# ── Main CVE lookup per service ───────────────────────────────────────────────
def get_vulns_for_service(
    service_name: str,
    product: str = '',
    version: str = '',
    port: int = 0,
) -> list[dict]:
    """
    Query NVD for CVEs related to the given service.

    Strategy (in priority order):
    1. CPE-based lookup if product is known (version_specific, highest confidence)
    2. Product + version keyword search (version_specific)
    3. Product-only search (generic, only if product differs from service)
    4. Service-name fallback keyword search (generic, lowest confidence)

    Results are cached per lookup key.
    """
    service_clean = service_name.lower().strip().split('-')[0]
    product_clean = product.lower().strip()
    version_clean = version.lower().strip()
    has_version   = bool(version_clean)

    # Build a stable cache key covering all query parameters
    cache_key = f"svc:{service_clean}|prod:{product_clean}|ver:{version_clean}"

    # ── 1. Check database cache ───────────────────────────────────────────────
    try:
        cached_mapping = db.session.get(NvdCache, cache_key)
        if cached_mapping:
            cve_ids = json.loads(cached_mapping.data_json)
            vulns   = []
            for cve_id in cve_ids:
                cached_cve = db.session.get(NvdCache, cve_id)
                if cached_cve:
                    entry = json.loads(cached_cve.data_json)
                    # Reattach port/service (may differ per scan)
                    entry['port']    = port
                    entry['service'] = service_name
                    vulns.append(entry)
            return vulns
    except Exception:
        pass

    collected: list[dict] = []

    # ── 2. CPE-based lookup (most precise) ───────────────────────────────────
    if product_clean:
        # Build CPE 2.3 search name: cpe:2.3:a:*:<product>:<version>:*
        cpe_keyword = product_clean
        if version_clean:
            cpe_keyword = f"{product_clean} {version_clean}"

        cpe_items = _nvd_fetch({
            'keywordSearch': cpe_keyword,
            'resultsPerPage': NVD_RESULTS_PER_PAGE,
        })
        parsed = _parse_nvd_items(
            cpe_items, port, service_name,
            match_type='version_specific',
            has_version=has_version,
        )
        collected.extend(parsed)

    # ── 3. Service-name generic fallback ─────────────────────────────────────
    # Only run if product search didn't find results OR no product info
    if not collected or not product_clean:
        svc_items = _nvd_fetch({
            'keywordSearch': service_clean,
            'resultsPerPage': NVD_RESULTS_PER_PAGE,
        })
        parsed = _parse_nvd_items(
            svc_items, port, service_name,
            match_type='generic',
            has_version=has_version,
        )
        # Don't add duplicates already in collected
        existing_ids = {v['cve'] for v in collected}
        for p in parsed:
            if p['cve'] not in existing_ids:
                collected.append(p)
                existing_ids.add(p['cve'])

    # ── 4. Cache results ──────────────────────────────────────────────────────
    cve_ids_list = []
    for vuln_entry in collected:
        cve_id = vuln_entry['cve']
        cve_ids_list.append(cve_id)
        # Store each CVE entry without port/service (these vary per scan)
        storable = {k: v for k, v in vuln_entry.items() if k not in ('port', 'service')}
        try:
            db.session.merge(NvdCache(cve_id=cve_id, data_json=json.dumps(storable)))
        except Exception:
            pass

    try:
        db.session.merge(NvdCache(cve_id=cache_key, data_json=json.dumps(cve_ids_list)))
        db.session.commit()
    except Exception:
        pass

    return collected


# ── Port / host constants ─────────────────────────────────────────────────────
COMMON_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
    8080: 'http-alt', 8443: 'https-alt', 27017: 'mongodb',
}

VALID_HOST_RE = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}'                  # IPv4
    r'|([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'       # hostname
    r'|localhost'
    r')$'
)

SCAN_ARGS = {
    'quick': '-T4 --open -F',
    'full':  '-T4 --open -p 1-65535',
    'vuln':  '-T4 --open -sV --script=banner,version',
}


# ── Validation ────────────────────────────────────────────────────────────────
def validate_target(target: str) -> tuple[bool, str]:
    target = target.strip()
    if not target:
        return False, 'Target cannot be empty.'
    if len(target) > 253:
        return False, 'Target too long.'
    if not VALID_HOST_RE.match(target):
        return False, 'Invalid IP address or hostname.'
    return True, ''


def resolve_host(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ── Core scan ─────────────────────────────────────────────────────────────────
def run_scan(scan_id: int, app):
    """Run in a background thread. Updates ScanResult in-place."""
    with app.app_context():
        scan = ScanResult.query.get(scan_id)
        if not scan:
            return

        scan.status = 'running'
        db.session.commit()

        try:
            resolved = resolve_host(scan.target)
            if not resolved:
                raise ValueError(f'Cannot resolve host: {scan.target}')
            scan.resolved_ip = resolved

            nm   = nmap.PortScanner()
            args = SCAN_ARGS.get(scan.scan_type, SCAN_ARGS['quick'])
            nm.scan(hosts=resolved, arguments=args)

            ports_data: list[dict] = []
            # Use a dict keyed by CVE-ID to deduplicate across all ports/services
            vulns_map:  dict[str, dict] = {}

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        pinfo        = nm[host][proto][port]
                        service_name = pinfo.get('name', COMMON_PORTS.get(port, 'unknown'))
                        product      = pinfo.get('product', '')
                        version      = pinfo.get('version', '')

                        port_entry = {
                            'port':    port,
                            'proto':   proto,
                            'state':   pinfo.get('state', 'unknown'),
                            'service': service_name,
                            'product': product,
                            'version': version,
                        }
                        ports_data.append(port_entry)

                        if pinfo.get('state') == 'open':
                            for v in get_vulns_for_service(
                                service_name,
                                product=product,
                                version=version,
                                port=port,
                            ):
                                cve_id = v['cve']
                                if cve_id not in vulns_map:
                                    vulns_map[cve_id] = v
                                else:
                                    # Keep the entry with higher confidence
                                    if v.get('confidence', 0) > vulns_map[cve_id].get('confidence', 0):
                                        vulns_map[cve_id] = v

            vulns_data = list(vulns_map.values())

            scan.ports      = ports_data
            scan.vulns      = vulns_data
            scan.risk_score = _calculate_risk(vulns_data, ports_data)

            if scan.resolved_ip:
                scan.shodan_data = query_shodan_host(scan.resolved_ip)

            critical_cves = [v for v in vulns_data if v.get('severity') == 'critical']
            if critical_cves and scan.user and scan.user.email:
                send_critical_email_alert(scan.user.email, scan.target, critical_cves)

            scan.status = 'done'

        except Exception as exc:
            scan.status    = 'error'
            scan.error_msg = str(exc)

        finally:
            scan.finished_at = datetime.utcnow()
            db.session.commit()


def _calculate_risk(vulns: list, ports: list) -> float:
    """
    Risk score 0–10.
    - version_specific CVEs contribute 1.3× weight vs generic (1.0×)
    - CVSS average is weighted by match type
    - Open port count adds a small bonus
    """
    if not vulns and not ports:
        return 0.0

    weighted_sum   = 0.0
    weighted_count = 0.0
    for v in vulns:
        w = 1.3 if v.get('match_type') == 'version_specific' else 1.0
        weighted_sum   += v.get('cvss', 0) * w
        weighted_count += w

    avg_cvss   = (weighted_sum / weighted_count) if weighted_count else 0.0
    open_count = sum(1 for p in ports if p.get('state') == 'open')
    score      = min(10.0, avg_cvss * 0.7 + min(open_count * 0.1, 3.0))
    return round(score, 1)


# ── Background launcher ───────────────────────────────────────────────────────
def launch_scan(scan_id: int, app):
    t = threading.Thread(target=run_scan, args=(scan_id, app), daemon=True)
    t.start()

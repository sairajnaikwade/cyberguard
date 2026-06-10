"""
CyberGuard — Scanner engine
Wraps python-nmap and performs CVE lookups against NIST NVD.
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
from datetime import datetime
from models import db, ScanResult, NvdCache

# ── Constants ────────────────────────────────────────────────────────────────
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
SEVERITY_SCORE = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}


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
            parsed_data = {
                'ip': data.get('ip_str'),
                'isp': data.get('isp'),
                'asn': data.get('asn'),
                'org': data.get('org'),
                'country': data.get('country_name'),
                'city': data.get('city'),
                'ports': data.get('ports', []),
                'hostnames': data.get('hostnames', []),
                'last_update': data.get('last_update'),
            }
            return parsed_data
    except Exception:
        pass
    return {}


def send_critical_email_alert(user_email: str, scan_target: str, critical_cves: list):
    smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
    try:
        smtp_port = int(os.environ.get('SMTP_PORT', '1025'))
    except ValueError:
        smtp_port = 1025
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    smtp_from = os.environ.get('SMTP_FROM', 'alerts@cyberguard.local')

    msg = MIMEMultipart()
    msg['From'] = smtp_from
    msg['To'] = user_email
    msg['Subject'] = f"🛡 [CyberGuard Alert] Critical Vulnerabilities Detected on {scan_target}"

    body = f"""Hello,

CyberGuard has detected {len(critical_cves)} critical vulnerability/vulnerabilities during a scan on your target: {scan_target}.

Critical CVEs Detected:
"""
    for cve in critical_cves:
        body += f"\n- {cve['cve']} (CVSS: {cve['cvss']}): {cve['desc']}\n"

    body += """
Please review these findings immediately in the CyberGuard dashboard.

Best regards,
CyberGuard Security Team
"""
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=5)
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(smtp_from, user_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"SMTP Error: failed to send email to {user_email}: {e}")


def get_vulns_for_service(service: str) -> list[dict]:
    service_clean = service.lower().strip()
    if not service_clean:
        return []

    # 1. Check database cache for service keyword mapping
    cache_key = f"keyword:{service_clean}"
    try:
        cached_mapping = db.session.get(NvdCache, cache_key)
        if cached_mapping:
            cve_ids = json.loads(cached_mapping.data_json)
            vulns = []
            for cve_id in cve_ids:
                cached_cve = db.session.get(NvdCache, cve_id)
                if cached_cve:
                    vulns.append(json.loads(cached_cve.data_json))
            return vulns
    except Exception:
        pass

    # 2. Live API query
    url = NVD_API
    params = {
        'keywordSearch': service_clean,
        'resultsPerPage': 5
    }

    # Mandatory 6-second rate limit delay before requesting NVD API
    time.sleep(6)

    retries = 3
    data = None
    for attempt in range(retries):
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                break
            elif response.status_code in (403, 503):
                # Rate limited or server busy, wait longer and retry
                time.sleep(6)
            else:
                # Other transient errors
                time.sleep(2)
        except Exception:
            time.sleep(2)

    if not data or 'vulnerabilities' not in data:
        return []

    cves_found = data['vulnerabilities']
    vulns_parsed = []
    cve_ids_list = []

    for item in cves_found:
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id')
        if not cve_id:
            continue

        cve_ids_list.append(cve_id)

        # Extract description
        descriptions = cve_data.get('descriptions', [])
        desc_val = descriptions[0].get('value', '') if descriptions else 'No description available.'

        # Extract CVSS score (support v3.1, v3.0, and v2 fallbacks)
        metrics = cve_data.get('metrics', {})
        cvss_v31 = metrics.get('cvssMetricV31', [])
        cvss_v30 = metrics.get('cvssMetricV30', [])
        cvss_v2 = metrics.get('cvssMetricV2', [])

        base_score = 0.0
        if cvss_v31:
            base_score = cvss_v31[0].get('cvssData', {}).get('baseScore', 0.0)
        elif cvss_v30:
            base_score = cvss_v30[0].get('cvssData', {}).get('baseScore', 0.0)
        elif cvss_v2:
            base_score = cvss_v2[0].get('cvssData', {}).get('baseScore', 0.0)

        # Map CVSS score to severity
        if base_score >= 9.0:
            severity = 'critical'
        elif base_score >= 7.0:
            severity = 'high'
        elif base_score >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'

        vuln_entry = {
            'cve': cve_id,
            'desc': desc_val,
            'severity': severity,
            'cvss': base_score
        }

        # Cache this individual CVE
        cve_cache_entry = NvdCache(
            cve_id=cve_id,
            data_json=json.dumps(vuln_entry)
        )
        db.session.merge(cve_cache_entry)
        vulns_parsed.append(vuln_entry)

    # Cache the service keyword mapping
    keyword_cache_entry = NvdCache(
        cve_id=cache_key,
        data_json=json.dumps(cve_ids_list)
    )
    db.session.merge(keyword_cache_entry)
    db.session.commit()

    return vulns_parsed

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


# ── Validation ───────────────────────────────────────────────────────────────
def validate_target(target: str) -> tuple[bool, str]:
    target = target.strip()
    if not target:
        return False, 'Target cannot be empty.'
    if len(target) > 253:
        return False, 'Target too long.'
    if not VALID_HOST_RE.match(target):
        return False, 'Invalid IP address or hostname.'
    # Block private ranges in production — allow in dev
    return True, ''


def resolve_host(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# ── Core scan ────────────────────────────────────────────────────────────────
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

            nm = nmap.PortScanner()
            args = SCAN_ARGS.get(scan.scan_type, SCAN_ARGS['quick'])
            nm.scan(hosts=resolved, arguments=args)

            ports_data = []
            vulns_data = []

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        pinfo = nm[host][proto][port]
                        service_name = pinfo.get('name', COMMON_PORTS.get(port, 'unknown'))
                        port_entry = {
                            'port':    port,
                            'proto':   proto,
                            'state':   pinfo.get('state', 'unknown'),
                            'service': service_name,
                            'product': pinfo.get('product', ''),
                            'version': pinfo.get('version', ''),
                        }
                        ports_data.append(port_entry)

                        # Match known vulns by service
                        if pinfo.get('state') == 'open':
                            svc_key = service_name.lower().split('-')[0]
                            for v in get_vulns_for_service(svc_key):
                                vuln = dict(v)
                                vuln['port'] = port
                                vuln['service'] = service_name
                                if not any(x['cve'] == vuln['cve'] for x in vulns_data):
                                    vulns_data.append(vuln)

            scan.ports    = ports_data
            scan.vulns    = vulns_data
            scan.risk_score = _calculate_risk(vulns_data, ports_data)

            # Query Shodan if resolved IP is available
            if scan.resolved_ip:
                scan.shodan_data = query_shodan_host(scan.resolved_ip)

            # Send critical email alerts if critical CVEs are found
            critical_cves = [v for v in vulns_data if v.get('severity') == 'critical']
            if critical_cves and scan.user and scan.user.email:
                send_critical_email_alert(scan.user.email, scan.target, critical_cves)

            scan.status   = 'done'

        except Exception as exc:
            scan.status    = 'error'
            scan.error_msg = str(exc)

        finally:
            scan.finished_at = datetime.utcnow()
            db.session.commit()


def _calculate_risk(vulns: list, ports: list) -> float:
    if not vulns and not ports:
        return 0.0
    base = sum(v.get('cvss', 0) for v in vulns)
    open_count = sum(1 for p in ports if p.get('state') == 'open')
    score = min(10.0, (base / max(len(vulns), 1)) * 0.7 + min(open_count * 0.1, 3.0))
    return round(score, 1)


# ── Background launcher ──────────────────────────────────────────────────────
def launch_scan(scan_id: int, app):
    t = threading.Thread(target=run_scan, args=(scan_id, app), daemon=True)
    t.start()

from models import User, ScanResult, NvdCache
from datetime import datetime, timedelta

def test_user_password_hashing(db):
    user = User(username='hashuser', email='hash@example.com')
    user.set_password('mysecretpassword123')
    assert user.password_hash != 'mysecretpassword123'
    assert user.check_password('mysecretpassword123') is True
    assert user.check_password('wrongpass') is False

def test_scan_result_properties(db):
    user = User(username='scanuser', email='scan@example.com')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()
    
    ports = [{'port': 80, 'proto': 'tcp', 'state': 'open', 'service': 'http'}]
    vulns = [{'cve': 'CVE-2021-1234', 'severity': 'critical', 'cvss': 9.8, 'desc': 'RCE'}]
    
    start_time = datetime.utcnow() - timedelta(seconds=120)
    end_time = datetime.utcnow()
    
    scan = ScanResult(
        user_id=user.id,
        target='example.com',
        scan_type='vuln',
        status='done',
        started_at=start_time,
        finished_at=end_time,
        risk_score=9.8
    )
    scan.ports = ports
    scan.vulns = vulns
    db.session.add(scan)
    db.session.commit()
    
    # Reload from DB
    loaded = ScanResult.query.first()
    assert loaded.ports == ports
    assert loaded.vulns == vulns
    assert len(loaded.open_ports) == 1
    assert loaded.duration_seconds == 120
    
    # Severity counts
    counts = loaded.severity_counts()
    assert counts['critical'] == 1
    assert counts['high'] == 0
    assert counts['medium'] == 0
    assert counts['low'] == 0

def test_nvd_cache_repr(db):
    entry = NvdCache(cve_id='CVE-test', data_json='{}')
    assert repr(entry) == '<NvdCache CVE-test>'

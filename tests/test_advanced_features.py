import os
import json
import socket
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest
from flask import url_for
from app import create_app, celery_init_app
from models import db, User, ScanResult, ScheduledScan, NvdCache
from scanner_engine import (
    query_shodan_host,
    send_critical_email_alert,
    get_vulns_for_service,
    validate_target,
    resolve_host,
    run_scan,
    _calculate_risk,
    launch_scan
)

# ── Celery Task Context Tests ────────────────────────────────────────────────
def test_celery_task_context(app):
    celery_app = celery_init_app(app)
    
    called = []
    class MyTask(celery_app.Task):
        def run(self):
            from flask import current_app
            assert current_app.name == app.name
            called.append(True)
            
    task_inst = MyTask()
    task_inst()
    assert called == [True]


# ── Shodan threat intel tests ────────────────────────────────────────────────
@patch.dict(os.environ, {'SHODAN_API_KEY': 'testkey'})
@patch('requests.get')
def test_query_shodan_host_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'ip_str': '8.8.8.8',
        'isp': 'Google',
        'asn': 'AS15169',
        'org': 'Google LLC',
        'country_name': 'United States',
        'city': 'Mountain View',
        'ports': [80, 443],
        'hostnames': ['dns.google'],
        'last_update': '2026-06-10T12:00:00'
    }
    mock_get.return_value = mock_resp
    
    res = query_shodan_host('8.8.8.8')
    assert res['isp'] == 'Google'
    assert res['asn'] == 'AS15169'
    assert res['ports'] == [80, 443]

@patch.dict(os.environ, {}, clear=True)
def test_query_shodan_host_no_key():
    res = query_shodan_host('8.8.8.8')
    assert res == {}

@patch.dict(os.environ, {'SHODAN_API_KEY': 'testkey'})
@patch('requests.get')
def test_query_shodan_host_error(mock_get):
    mock_get.side_effect = Exception("API down")
    res = query_shodan_host('8.8.8.8')
    assert res == {}


# ── Critical Email Alert Tests ───────────────────────────────────────────────
@patch('smtplib.SMTP')
def test_send_critical_email_alert_success(mock_smtp):
    mock_smtp_inst = MagicMock()
    mock_smtp.return_value = mock_smtp_inst
    
    send_critical_email_alert('user@example.com', '127.0.0.1', [{'cve': 'CVE-1', 'cvss': 9.8, 'desc': 'Critical'}])
    
    mock_smtp.assert_called_once_with('localhost', 1025, timeout=5)
    mock_smtp_inst.sendmail.assert_called_once()
    mock_smtp_inst.quit.assert_called_once()

@patch.dict(os.environ, {'SMTP_USER': 'user', 'SMTP_PASSWORD': 'password', 'SMTP_PORT': 'xyz'})
@patch('smtplib.SMTP')
def test_send_critical_email_alert_with_auth(mock_smtp):
    mock_smtp_inst = MagicMock()
    mock_smtp.return_value = mock_smtp_inst
    
    send_critical_email_alert('user@example.com', '127.0.0.1', [{'cve': 'CVE-1', 'cvss': 9.8, 'desc': 'Critical'}])
    mock_smtp_inst.login.assert_called_once_with('user', 'password')

@patch('smtplib.SMTP')
def test_send_critical_email_alert_exception(mock_smtp):
    mock_smtp.side_effect = Exception("SMTP error")
    # Should not raise exception
    send_critical_email_alert('user@example.com', '127.0.0.1', [{'cve': 'CVE-1', 'cvss': 9.8, 'desc': 'Critical'}])


# ── NVD CVE Lookup & Caching Tests ───────────────────────────────────────────
def test_get_vulns_for_service_empty():
    assert get_vulns_for_service('') == []
    assert get_vulns_for_service('   ') == []

def test_get_vulns_for_service_cache_hit(db):
    # Cache key format changed to: svc:<service>|prod:<product>|ver:<version>
    cache_key = 'svc:http|prod:|ver:'
    keyword_cache = NvdCache(cve_id=cache_key, data_json=json.dumps(['CVE-2021-1234']))
    cve_cache = NvdCache(cve_id='CVE-2021-1234', data_json=json.dumps({
        'cve': 'CVE-2021-1234', 'desc': 'Vulnerability description', 'severity': 'high', 'cvss': 7.5,
        'match_type': 'generic', 'confidence': 40, 'published': ''
    }))
    db.session.add(keyword_cache)
    db.session.add(cve_cache)
    db.session.commit()

    vulns = get_vulns_for_service('http')
    assert len(vulns) == 1
    assert vulns[0]['cve'] == 'CVE-2021-1234'
    assert vulns[0]['severity'] == 'high'

@patch('time.sleep')
@patch('requests.get')
@patch('models.db.session.get')
def test_get_vulns_for_service_db_error(mock_db_get, mock_api_get, mock_sleep, db):
    mock_db_get.side_effect = Exception("DB error")
    mock_api_get.side_effect = Exception("API error")
    assert get_vulns_for_service('http') == []



@patch('time.sleep')
@patch('requests.get')
def test_get_vulns_for_service_api_success(mock_get, mock_sleep, db):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'vulnerabilities': [
            {
                'cve': {
                    'id': 'CVE-2022-0001',
                    'descriptions': [{'value': 'Critical vulnerability'}],
                    'metrics': {
                        'cvssMetricV31': [{'cvssData': {'baseScore': 9.8}}]
                    }
                }
            },
            {
                'cve': {
                    'id': 'CVE-2022-0002',
                    'descriptions': [{'value': 'High vulnerability'}],
                    'metrics': {
                        'cvssMetricV30': [{'cvssData': {'baseScore': 8.5}}]
                    }
                }
            },
            {
                'cve': {
                    'id': 'CVE-2022-0003',
                    'descriptions': [{'value': 'Medium vulnerability'}],
                    'metrics': {
                        'cvssMetricV2': [{'cvssData': {'baseScore': 5.0}}]
                    }
                }
            },
            {
                'cve': {
                    'id': 'CVE-2022-0004',
                    'descriptions': [{'value': 'Low vulnerability'}],
                    'metrics': {}
                }
            }
        ]
    }
    mock_get.return_value = mock_resp
    
    vulns = get_vulns_for_service('ftp')
    assert len(vulns) == 4
    # Results sorted by confidence descending; check all 4 severities are present
    severities = {v['severity'] for v in vulns}
    assert 'critical' in severities
    assert 'high' in severities
    assert 'medium' in severities
    assert 'low' in severities

    # Check cache was populated (new key format)
    cache_key = 'svc:ftp|prod:|ver:'
    cache_keyword = NvdCache.query.get(cache_key)
    assert cache_keyword is not None
    assert 'CVE-2022-0001' in json.loads(cache_keyword.data_json)

@patch('time.sleep')
@patch('requests.get')
def test_get_vulns_for_service_api_retry_then_success(mock_get, mock_sleep, db):
    mock_resp_fail = MagicMock()
    mock_resp_fail.status_code = 403
    
    mock_resp_ok = MagicMock()
    mock_resp_ok.status_code = 200
    mock_resp_ok.json.return_value = {'vulnerabilities': []}
    
    mock_get.side_effect = [mock_resp_fail, mock_resp_ok]
    
    vulns = get_vulns_for_service('mysql')
    assert vulns == []
    assert mock_get.call_count == 2

@patch('time.sleep')
@patch('requests.get')
def test_get_vulns_for_service_api_all_fail(mock_get, mock_sleep, db):
    mock_get.side_effect = Exception("NVD down")
    vulns = get_vulns_for_service('postgres')
    assert vulns == []


# ── Host Resolution & Target Validation Tests ────────────────────────────────
def test_resolve_host_success():
    with patch('socket.gethostbyname', return_value='127.0.0.1'):
        assert resolve_host('localhost') == '127.0.0.1'

def test_resolve_host_fail():
    with patch('socket.gethostbyname', side_effect=socket.gaierror):
        assert resolve_host('invalid-host-name-xyz') is None

def test_validate_target():
    assert validate_target('')[0] is False
    assert validate_target('a' * 300)[0] is False
    assert validate_target('1.2.3.4')[0] is True


# ── Risk Score Logic Tests ───────────────────────────────────────────────────
def test_calculate_risk():
    assert _calculate_risk([], []) == 0.0

    # No match_type → defaults to weight 1.0 (generic)
    # weighted_sum = (9.8 + 8.0) * 1.0 = 17.8, weighted_count = 2.0
    # avg_cvss = 8.9, open_count = 1
    # score = min(10.0, 8.9 * 0.7 + min(1 * 0.1, 3.0)) = min(10.0, 6.23 + 0.1) = 6.3
    vulns = [{'cvss': 9.8}, {'cvss': 8.0}]
    ports = [{'state': 'open'}, {'state': 'closed'}]
    assert _calculate_risk(vulns, ports) == 6.3

    # version_specific CVEs get 1.3x weight — score should be higher
    vs_vulns = [{'cvss': 9.8, 'match_type': 'version_specific'}, {'cvss': 8.0, 'match_type': 'version_specific'}]
    vs_score = _calculate_risk(vs_vulns, ports)
    assert vs_score >= _calculate_risk(vulns, ports)


# ── Background Scan Launcher Tests ───────────────────────────────────────────
@patch('threading.Thread')
def test_launch_scan(mock_thread, app):
    launch_scan(1, app)
    mock_thread.assert_called_once()


# ── Core Scanning engine tests ───────────────────────────────────────────────
@patch('scanner_engine.resolve_host', return_value='127.0.0.1')
@patch('nmap.PortScanner')
@patch('scanner_engine.get_vulns_for_service')
@patch('scanner_engine.query_shodan_host')
@patch('scanner_engine.send_critical_email_alert')
def test_run_scan_success(mock_email, mock_shodan, mock_vulns, mock_nmap, mock_resolve, db, app):
    user = User(username='test_scanner_user_success', email='scanuser@example.com')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()
    
    scan = ScanResult(user_id=user.id, target='127.0.0.1', scan_type='quick', status='pending')
    db.session.add(scan)
    db.session.commit()
    
    mock_nm_inst = MagicMock()
    mock_nmap.return_value = mock_nm_inst
    mock_nm_inst.all_hosts.return_value = ['127.0.0.1']
    mock_nm_inst.__getitem__.return_value.all_protocols.return_value = ['tcp']
    mock_nm_inst.__getitem__.return_value.__getitem__.return_value.keys.return_value = [80]
    mock_nm_inst.__getitem__.return_value.__getitem__.return_value.__getitem__.return_value = {
        'state': 'open',
        'name': 'http',
        'product': 'Apache',
        'version': '2.4.41'
    }
    
    mock_vulns.return_value = [
        {'cve': 'CVE-2022-9999', 'desc': 'Mock CVE', 'severity': 'critical', 'cvss': 9.8}
    ]
    mock_shodan.return_value = {'isp': 'Mock ISP'}
    
    run_scan(scan.id, app)
    
    db.session.expire_all()
    scan_updated = ScanResult.query.get(scan.id)
    assert scan_updated.status == 'done'
    assert scan_updated.resolved_ip == '127.0.0.1'
    assert len(scan_updated.ports) == 1
    assert scan_updated.ports[0]['port'] == 80
    assert len(scan_updated.vulns) == 1
    assert scan_updated.vulns[0]['cve'] == 'CVE-2022-9999'
    assert scan_updated.shodan_data == {'isp': 'Mock ISP'}
    assert scan_updated.risk_score > 0
    
    mock_email.assert_called_once_with('scanuser@example.com', '127.0.0.1', scan_updated.vulns)


@patch('scanner_engine.resolve_host', return_value=None)
def test_run_scan_resolve_fail(mock_resolve, db, app):
    user = User(username='test_scanner_user_fail', email='scanuser@example.com')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()
    
    scan = ScanResult(user_id=user.id, target='unresolvable.com', scan_type='quick', status='pending')
    db.session.add(scan)
    db.session.commit()
    
    run_scan(scan.id, app)
    
    db.session.expire_all()
    scan_updated = ScanResult.query.get(scan.id)
    assert scan_updated.status == 'error'
    assert 'Cannot resolve host' in scan_updated.error_msg


# ── CSV & PDF Reports Tests ──────────────────────────────────────────────────
def test_export_csv_success(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    scan = ScanResult(
        user_id=user.id, target='127.0.0.1', scan_type='quick', status='done',
        started_at=datetime.utcnow(), finished_at=datetime.utcnow()
    )
    scan.ports = [{'port': 80, 'proto': 'tcp', 'state': 'open', 'service': 'http', 'product': 'Apache', 'version': '1.0'}]
    scan.vulns = [{'cve': 'CVE-2022-0001', 'severity': 'critical', 'cvss': 9.8, 'desc': 'RCE', 'port': 80, 'service': 'http'}]
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get(f'/reports/csv/{scan.id}')
    assert response.status_code == 200
    assert response.mimetype == 'text/csv'
    assert b"CyberGuard Vulnerability Scanner" in response.data
    assert b"CVE-2022-0001" in response.data

def test_export_csv_unauthorized(client, db):
    response = client.get('/reports/csv/1')
    assert response.status_code == 302 # Redirect to login

def test_export_csv_wrong_user(auth_client, db):
    other_user = User(username='other_user', email='other@example.com')
    other_user.set_password('Password123')
    db.session.add(other_user)
    db.session.commit()
    
    scan = ScanResult(user_id=other_user.id, target='127.0.0.1', status='done')
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get(f'/reports/csv/{scan.id}')
    assert response.status_code == 404

def test_export_pdf_success(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    scan = ScanResult(
        user_id=user.id, target='127.0.0.1', scan_type='quick', status='done',
        started_at=datetime.utcnow(), finished_at=datetime.utcnow()
    )
    scan.ports = [{'port': 80, 'proto': 'tcp', 'state': 'open', 'service': 'http'}]
    scan.vulns = [{'cve': 'CVE-2022-0001', 'severity': 'critical', 'cvss': 9.8, 'desc': 'RCE'}]
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get(f'/reports/pdf/{scan.id}')
    assert response.status_code == 200
    assert response.mimetype == 'application/pdf'

def test_export_pdf_no_vulns(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    scan = ScanResult(
        user_id=user.id, target='127.0.0.1', scan_type='quick', status='done',
        started_at=datetime.utcnow(), finished_at=datetime.utcnow()
    )
    scan.ports = []
    scan.vulns = []
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get(f'/reports/pdf/{scan.id}')
    assert response.status_code == 200
    assert response.mimetype == 'application/pdf'


# ── Scheduler Check Job Tests ────────────────────────────────────────────────
def test_scheduler_job(db):
    from sqlalchemy.pool import StaticPool
    with patch('apscheduler.schedulers.background.BackgroundScheduler') as mock_sched_cls:
        test_app = create_app()
        test_app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SQLALCHEMY_ENGINE_OPTIONS': {
                'poolclass': StaticPool,
                'connect_args': {'check_same_thread': False}
            },
            'WTF_CSRF_ENABLED': False,
            'RATELIMIT_ENABLED': False
        })
        add_job_call = mock_sched_cls.return_value.add_job.call_args
        job_func = add_job_call[0][0] # first positional arg is check_scheduled_scans
        
    with test_app.app_context():
        db.create_all()
        # Setup scheduled scan that is active and due
        user = User(username='sched_job_user', email='sched@example.com')
        user.set_password('Password123')
        db.session.add(user)
        db.session.commit()
        
        sched = ScheduledScan(
            user_id=user.id,
            target='127.0.0.1',
            scan_type='quick',
            interval_hours=24,
            is_active=True,
            next_run_at=datetime.utcnow() - timedelta(minutes=1)
        )
        db.session.add(sched)
        db.session.commit()
        
        with patch('celery_worker.scan_task.delay') as mock_delay:
            job_func()
            assert mock_delay.call_count == 1
            # Check last run is updated and next_run_at pushed forward
            assert sched.last_run_at is not None
            assert sched.next_run_at > datetime.utcnow()


# ── Rate Limiting Error Handler Tests ────────────────────────────────────────
def test_rate_limit_handler_json(db):
    from app import create_app
    test_app = create_app()
    test_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'RATELIMIT_ENABLED': True
    })
    
    with test_app.app_context():
        db.create_all()
        user = User(username='limiteruser', email='limiter@example.com')
        user.set_password('Password123')
        db.session.add(user)
        db.session.commit()
        
    client = test_app.test_client()
    client.post('/auth/login', data={'username': 'limiteruser', 'password': 'Password123'})
    
    # Post /auth/register 6 times (limit is 5 per hour) to trigger 429
    with patch('celery_worker.scan_task.delay'):
        for i in range(6):
            response = client.post('/auth/register', data={
                'username': f'user{i}',
                'email': f'user{i}@example.com',
                'password': 'Password123',
                'confirm_password': 'Password123'
            }, headers={'Accept': 'application/json'})
            
        assert response.status_code == 429
        assert response.is_json
        assert 'Rate limit exceeded' in response.get_json()['error']

def test_rate_limit_handler_html(db):
    from app import create_app
    test_app = create_app()
    test_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'RATELIMIT_ENABLED': True
    })
    
    with test_app.app_context():
        db.create_all()
        
    client = test_app.test_client()
    for i in range(6):
        response = client.post('/auth/register', data={
            'username': f'user{i}',
            'email': f'user{i}@example.com',
            'password': 'Password123',
            'confirm_password': 'Password123'
        }, follow_redirects=True)
        
    assert b"Rate limit exceeded. Please try again later." in response.data


# ── Extra Controller Path Tests ──────────────────────────────────────────────
def test_user_or_ip_limit_key_anonymous(client):
    # Triggers anonymous route hit for /scan, which calls user_or_ip_limit_key
    response = client.post('/scan', data={'target': '127.0.0.1'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Sign in" in response.data

@patch('celery_worker.scan_task.delay')
def test_new_scan_invalid_types_and_target_validation(mock_delay, auth_client, db):
    # Invalid scan type gets reset to 'quick'
    response = auth_client.post('/scan', data={'target': '127.0.0.1', 'scan_type': 'invalid'}, follow_redirects=True)
    assert response.status_code == 200
    scan = ScanResult.query.order_by(ScanResult.started_at.desc()).first()
    assert scan.scan_type == 'quick'
    
    # Target validation failures redirect back
    response = auth_client.post('/scan', data={'target': '', 'scan_type': 'quick'}, follow_redirects=False)
    assert response.status_code == 302
    assert response.location.endswith('/scan')

def test_history_pagination(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    for i in range(5):
        scan = ScanResult(user_id=user.id, target=f'127.0.0.{i}', status='done')
        db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get('/history?page=1')
    assert response.status_code == 200
    assert b"127.0.0.0" in response.data

def test_delete_scan_result(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    scan = ScanResult(user_id=user.id, target='127.0.0.1', status='done')
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.post(f'/scan/{scan.id}/delete', follow_redirects=True)
    assert b"Scan deleted." in response.data
    assert ScanResult.query.get(scan.id) is None

def test_new_schedule_validation_errors(auth_client, db):
    # Invalid target
    response = auth_client.post('/schedules/new', data={
        'target': 'invalid-host!!!', 'scan_type': 'quick', 'interval_hours': '24'
    }, follow_redirects=True)
    assert b"Invalid IP address or hostname." in response.data
    
    # Invalid interval fallback
    response = auth_client.post('/schedules/new', data={
        'target': '127.0.0.1', 'scan_type': 'quick', 'interval_hours': 'not-an-int'
    }, follow_redirects=True)
    assert b"Scan scheduled for 127.0.0.1 every 24 hours." in response.data
    
    # Invalid scan type fallback
    response = auth_client.post('/schedules/new', data={
        'target': '127.0.0.2', 'scan_type': 'invalid-type', 'interval_hours': '12'
    }, follow_redirects=True)
    assert b"Scan scheduled for 127.0.0.2 every 12 hours." in response.data
    sched = ScheduledScan.query.filter_by(target='127.0.0.2').first()
    assert sched.scan_type == 'quick'

def test_admin_toggle_own_role(admin_client, db):
    admin_user = User.query.filter_by(username='adminuser').first()
    response = admin_client.post(f'/admin/user/{admin_user.id}/toggle-admin', follow_redirects=True)
    assert b"You cannot remove your own admin status." in response.data
    assert admin_user.is_admin is True

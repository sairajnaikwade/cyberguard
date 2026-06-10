from models import ScanResult, ScheduledScan, User
from unittest.mock import patch

def test_dashboard_access(auth_client):
    response = auth_client.get('/')
    assert response.status_code == 200
    assert b"Dashboard" in response.data

def test_target_validation(auth_client):
    # Test blank target
    response = auth_client.post('/scan', data={'target': '', 'scan_type': 'quick'}, follow_redirects=True)
    assert b"Target cannot be empty." in response.data

    # Test invalid domain
    response = auth_client.post('/scan', data={'target': 'not-a-valid-domain!!!', 'scan_type': 'quick'}, follow_redirects=True)
    assert b"Invalid IP address or hostname." in response.data

@patch('celery_worker.scan_task.delay')
def test_create_scan_success(mock_delay, auth_client, db):
    response = auth_client.post('/scan', data={'target': '127.0.0.1', 'scan_type': 'quick'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Scan started for 127.0.0.1." in response.data
    
    scan = ScanResult.query.first()
    assert scan is not None
    assert scan.target == '127.0.0.1'
    assert scan.scan_type == 'quick'
    assert scan.status == 'pending'
    
    mock_delay.assert_called_once_with(scan.id)

def test_scan_status_endpoint(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    scan = ScanResult(user_id=user.id, target='localhost', scan_type='quick', status='running', risk_score=2.0)
    db.session.add(scan)
    db.session.commit()
    
    response = auth_client.get(f'/scan/{scan.id}/status')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'running'
    assert json_data['risk_score'] == 2.0
    assert json_data['open_ports'] == 0

def test_list_and_create_schedules(auth_client, db):
    response = auth_client.get('/schedules')
    assert response.status_code == 200
    assert b"Recurring Scan Schedules" in response.data

    # Create new schedule
    response = auth_client.post('/schedules/new', data={
        'target': '127.0.0.1',
        'scan_type': 'quick',
        'interval_hours': '24'
    }, follow_redirects=True)
    assert b"Scan scheduled for 127.0.0.1 every 24 hours." in response.data
    
    sched = ScheduledScan.query.first()
    assert sched is not None
    assert sched.target == '127.0.0.1'
    assert sched.interval_hours == 24
    assert sched.is_active is True

def test_toggle_and_delete_schedules(auth_client, db):
    user = User.query.filter_by(username='testuser').first()
    sched = ScheduledScan(user_id=user.id, target='127.0.0.1', scan_type='quick', interval_hours=24)
    db.session.add(sched)
    db.session.commit()
    
    # Toggle
    response = auth_client.post(f'/schedules/{sched.id}/toggle', follow_redirects=True)
    assert b"Schedule for 127.0.0.1 deactivated." in response.data
    assert sched.is_active is False
    
    # Delete
    response = auth_client.post(f'/schedules/{sched.id}/delete', follow_redirects=True)
    assert b"Scheduled scan for 127.0.0.1 deleted." in response.data
    assert ScheduledScan.query.count() == 0

def test_admin_dashboard_anonymous(client, db):
    response = client.get('/admin/', follow_redirects=True)
    assert b"Sign in" in response.data

def test_admin_dashboard_non_admin(auth_client):
    response = auth_client.get('/admin/')
    assert response.status_code == 403

def test_admin_dashboard_admin(admin_client):
    response = admin_client.get('/admin/')
    assert response.status_code == 200
    assert b"Admin Dashboard" in response.data

def test_admin_toggle_role_and_delete(admin_client, db):
    user = User(username='otheruser', email='other@example.com')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()
    
    scan = ScanResult(user_id=user.id, target='example.com', scan_type='quick', status='done')
    db.session.add(scan)
    db.session.commit()
    
    # Toggle admin role
    response = admin_client.post(f'/admin/user/{user.id}/toggle-admin', follow_redirects=True)
    assert b"User otheruser promoted to Admin." in response.data
    assert user.is_admin is True

    # Delete scan result
    response = admin_client.post(f'/admin/scan/{scan.id}/delete', follow_redirects=True)
    assert b"deleted successfully." in response.data
    assert ScanResult.query.count() == 0

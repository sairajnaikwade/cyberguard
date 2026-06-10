from models import User

def test_register_success(client, db):
    response = client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'Password123',
        'confirm_password': 'Password123'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Account created! Please log in." in response.data
    
    user = User.query.filter_by(username='newuser').first()
    assert user is not None
    assert user.email == 'new@example.com'
    assert user.check_password('Password123') is True

def test_register_validation_failures(client, db):
    # Short username
    response = client.post('/auth/register', data={
        'username': 'ab',
        'email': 'new@example.com',
        'password': 'Password123',
        'confirm_password': 'Password123'
    }, follow_redirects=True)
    assert b"Username must be 3\xe2\x80\x9380 characters." in response.data
    
    # Non-matching passwords
    response = client.post('/auth/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'Password123',
        'confirm_password': 'different'
    }, follow_redirects=True)
    assert b"Passwords do not match." in response.data

def test_login_success(client, db):
    user = User(username='loginuser', email='login@example.com')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()
    
    response = client.post('/auth/login', data={
        'username': 'loginuser',
        'password': 'Password123'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"New Scan" in response.data  # Verify redirection to dashboard

def test_login_failure(client, db):
    response = client.post('/auth/login', data={
        'username': 'wronguser',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b"Invalid username or password." in response.data

def test_logout(auth_client):
    response = auth_client.get('/auth/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b"You have been logged out." in response.data

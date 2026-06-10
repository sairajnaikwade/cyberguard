import pytest
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import db as _db, User

from sqlalchemy.pool import StaticPool

@pytest.fixture(scope='session')
def app():
    # Override settings for testing
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['SECRET_KEY'] = 'test-secret-key-12345'
    os.environ['FLASK_DEBUG'] = 'false'
    
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'poolclass': StaticPool,
            'connect_args': {'check_same_thread': False}
        },
        'WTF_CSRF_ENABLED': False,
        'RATELIMIT_ENABLED': False  # disable rate limits for standard unit tests to prevent HTTP 429 in tests
    })
    
    return app

@pytest.fixture(scope='function')
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.close()
        _db.drop_all()

@pytest.fixture(autouse=True)
def reset_rate_limiter(app):
    from extensions import limiter
    limiter.reset()


@pytest.fixture(scope='function')
def client(app, db):
    return app.test_client()

@pytest.fixture(scope='function')
def auth_client(client, db):
    # Register and log in a standard user
    username = 'testuser'
    email = 'test@example.com'
    password = 'Password123'
    
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Log in
    client.post('/auth/login', data={'username': username, 'password': password})
    return client

@pytest.fixture(scope='function')
def admin_client(client, db):
    # Register and log in an admin user
    username = 'adminuser'
    email = 'admin@example.com'
    password = 'Password123'
    
    user = User(username=username, email=email, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Log in
    client.post('/auth/login', data={'username': username, 'password': password})
    return client

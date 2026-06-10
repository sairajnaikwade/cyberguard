"""
CyberGuard Vulnerability Scanner
Main Flask application entry point
"""

from flask import Flask, jsonify, flash, redirect, url_for, request
from flask_login import LoginManager
from models import db, User, NvdCache, ScheduledScan
from routes.auth import auth_bp
from routes.scanner import scanner_bp
from routes.reports import reports_bp
from celery import Celery, Task
from extensions import limiter
from flask_limiter.errors import RateLimitExceeded
import os

def celery_init_app(app: Flask) -> Celery:
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app = Celery(app.name, task_cls=FlaskTask)
    celery_app.config_from_object(app.config.get("CELERY", {}))
    celery_app.set_default()
    app.extensions["celery"] = celery_app
    return celery_app


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyberguard-dev-secret-change-in-prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 'sqlite:///cyberguard.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    app.config.from_mapping(
        CELERY=dict(
            broker_url=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
            result_backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
            task_ignore_result=True,
        ),
    )

    db.init_app(app)
    from flask_migrate import Migrate
    Migrate(app, db)
    limiter.init_app(app)

    @app.errorhandler(RateLimitExceeded)
    def ratelimit_handler(e):
        if request.path.endswith('/status') or request.is_json or request.accept_mimetypes.accept_json:
            return jsonify(error="Rate limit exceeded", message=str(e.description or "Too many requests")), 429
        flash("Rate limit exceeded. Please try again later.", "danger")
        return redirect(request.referrer or url_for('scanner.dashboard'))

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(scanner_bp, url_prefix='/')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    from routes.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # APScheduler configuration
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler()

    def check_scheduled_scans():
        with app.app_context():
            from models import db, ScheduledScan, ScanResult
            from celery_worker import scan_task
            from datetime import datetime, timedelta

            now = datetime.utcnow()
            due_scans = ScheduledScan.query.filter(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run_at <= now
            ).all()

            for sched in due_scans:
                scan = ScanResult(
                    user_id=sched.user_id,
                    target=sched.target,
                    scan_type=sched.scan_type,
                    status='pending'
                )
                db.session.add(scan)
                db.session.commit()

                scan_task.delay(scan.id)

                sched.last_run_at = now
                sched.next_run_at = now + timedelta(hours=sched.interval_hours)
                db.session.commit()

    scheduler.add_job(check_scheduled_scans, 'interval', seconds=30)
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        scheduler.start()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true', host='0.0.0.0', port=5000)

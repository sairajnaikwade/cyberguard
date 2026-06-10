"""
CyberGuard — SQLAlchemy models
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin      = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    scans         = db.relationship('ScanResult', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target       = db.Column(db.String(255), nullable=False)
    resolved_ip  = db.Column(db.String(45))
    scan_type    = db.Column(db.String(50), default='quick')
    status       = db.Column(db.String(20), default='pending')   # pending | running | done | error
    error_msg    = db.Column(db.Text)
    ports_json   = db.Column(db.Text, default='[]')              # JSON list of port dicts
    vulns_json   = db.Column(db.Text, default='[]')              # JSON list of vuln dicts
    shodan_data_json = db.Column(db.Text, default='{}')           # JSON string of Shodan data
    risk_score   = db.Column(db.Float, default=0.0)
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at  = db.Column(db.DateTime)

    @property
    def ports(self):
        return json.loads(self.ports_json or '[]')

    @ports.setter
    def ports(self, value):
        self.ports_json = json.dumps(value)

    @property
    def vulns(self):
        return json.loads(self.vulns_json or '[]')

    @vulns.setter
    def vulns(self, value):
        self.vulns_json = json.dumps(value)

    @property
    def shodan_data(self):
        return json.loads(self.shodan_data_json or '{}')

    @shodan_data.setter
    def shodan_data(self, value):
        self.shodan_data_json = json.dumps(value)

    @property
    def open_ports(self):
        return [p for p in self.ports if p.get('state') == 'open']

    @property
    def duration_seconds(self):
        if self.finished_at and self.started_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None

    def severity_counts(self):
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulns:
            sev = v.get('severity', 'low').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def __repr__(self):
        return f'<ScanResult {self.target} [{self.status}]>'


class NvdCache(db.Model):
    __tablename__ = 'nvd_cache'
    cve_id     = db.Column(db.String(100), primary_key=True)
    data_json  = db.Column(db.Text, nullable=False)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<NvdCache {self.cve_id}>'


class ScheduledScan(db.Model):
    __tablename__ = 'scheduled_scans'
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target         = db.Column(db.String(255), nullable=False)
    scan_type      = db.Column(db.String(50), default='quick')
    interval_hours = db.Column(db.Integer, default=24)
    last_run_at    = db.Column(db.DateTime)
    next_run_at    = db.Column(db.DateTime, default=datetime.utcnow)
    is_active      = db.Column(db.Boolean, default=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('scheduled_scans', lazy=True, cascade='all, delete-orphan'))

    def __repr__(self):
        return f'<ScheduledScan {self.target} [{self.interval_hours}h]>'

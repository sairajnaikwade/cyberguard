from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from models import db, User, ScanResult, ScheduledScan
from functools import wraps

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    users = User.query.all()
    scans = ScanResult.query.order_by(ScanResult.started_at.desc()).all()
    scheduled = ScheduledScan.query.all()
    
    total_users = len(users)
    total_scans = len(scans)
    total_vulns = sum(len(s.vulns) for s in scans)
    
    return render_template(
        'admin/dashboard.html',
        users=users,
        scans=scans,
        scheduled=scheduled,
        total_users=total_users,
        total_scans=total_scans,
        total_vulns=total_vulns
    )

@admin_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan #{scan_id} deleted successfully.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/user/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    if user_id == current_user.id:
        flash("You cannot remove your own admin status.", "danger")
        return redirect(url_for('admin.dashboard'))
        
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    status = "promoted to Admin" if user.is_admin else "demoted from Admin"
    flash(f"User {user.username} {status}.", "success")
    return redirect(url_for('admin.dashboard'))

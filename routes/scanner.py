"""
CyberGuard — Scanner routes (dashboard, new scan, history, status polling)
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from models import db, ScanResult, ScheduledScan
from scanner_engine import validate_target
from datetime import datetime
from extensions import limiter
from flask_limiter.util import get_remote_address

scanner_bp = Blueprint('scanner', __name__)


@scanner_bp.route('/')
@login_required
def dashboard():
    recent = (ScanResult.query
              .filter_by(user_id=current_user.id)
              .order_by(ScanResult.started_at.desc())
              .limit(5).all())
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    total_vulns = sum(len(s.vulns) for s in ScanResult.query.filter_by(user_id=current_user.id).all())
    return render_template('scanner/dashboard.html',
                           recent=recent,
                           total_scans=total_scans,
                           total_vulns=total_vulns)


def user_or_ip_limit_key():
    if current_user and current_user.is_authenticated:
        return str(current_user.id)
    return get_remote_address()


@scanner_bp.route('/scan', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour", methods=["POST"], key_func=user_or_ip_limit_key)
def new_scan():
    if request.method == 'POST':
        target    = request.form.get('target', '').strip()
        scan_type = request.form.get('scan_type', 'quick')

        if scan_type not in ('quick', 'full', 'vuln'):
            scan_type = 'quick'

        valid, err = validate_target(target)
        if not valid:
            flash(err, 'danger')
            return redirect(url_for('scanner.new_scan'))

        scan = ScanResult(
            user_id   = current_user.id,
            target    = target,
            scan_type = scan_type,
            status    = 'pending',
        )
        db.session.add(scan)
        db.session.commit()

        from celery_worker import scan_task
        scan_task.delay(scan.id)
        flash(f'Scan started for {target}.', 'info')
        return redirect(url_for('scanner.scan_detail', scan_id=scan.id))

    return render_template('scanner/new_scan.html')


@scanner_bp.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template('scanner/scan_detail.html', scan=scan)


@scanner_bp.route('/scan/<int:scan_id>/status')
@login_required
def scan_status(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'status':     scan.status,
        'risk_score': scan.risk_score,
        'open_ports': len(scan.open_ports),
        'vulns':      len(scan.vulns),
        'error':      scan.error_msg,
    })


@scanner_bp.route('/history')
@login_required
def history():
    page  = request.args.get('page', 1, type=int)
    scans = (ScanResult.query
             .filter_by(user_id=current_user.id)
             .order_by(ScanResult.started_at.desc())
             .paginate(page=page, per_page=15))
    return render_template('scanner/history.html', scans=scans)


@scanner_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted.', 'success')
    return redirect(url_for('scanner.history'))


@scanner_bp.route('/schedules', methods=['GET'])
@login_required
def list_schedules():
    schedules = ScheduledScan.query.filter_by(user_id=current_user.id).order_by(ScheduledScan.created_at.desc()).all()
    return render_template('scanner/schedules.html', schedules=schedules)


@scanner_bp.route('/schedules/new', methods=['POST'])
@login_required
def new_schedule():
    target = request.form.get('target', '').strip()
    scan_type = request.form.get('scan_type', 'quick')
    try:
        interval_hours = int(request.form.get('interval_hours', '24'))
    except ValueError:
        interval_hours = 24

    if scan_type not in ('quick', 'full', 'vuln'):
        scan_type = 'quick'

    valid, err = validate_target(target)
    if not valid:
        flash(err, 'danger')
        return redirect(url_for('scanner.list_schedules'))

    sched = ScheduledScan(
        user_id=current_user.id,
        target=target,
        scan_type=scan_type,
        interval_hours=interval_hours,
        next_run_at=datetime.utcnow()
    )
    db.session.add(sched)
    db.session.commit()
    flash(f'Scan scheduled for {target} every {interval_hours} hours.', 'success')
    return redirect(url_for('scanner.list_schedules'))


@scanner_bp.route('/schedules/<int:schedule_id>/toggle', methods=['POST'])
@login_required
def toggle_schedule(schedule_id):
    sched = ScheduledScan.query.filter_by(id=schedule_id, user_id=current_user.id).first_or_404()
    sched.is_active = not sched.is_active
    db.session.commit()
    status = "activated" if sched.is_active else "deactivated"
    flash(f'Schedule for {sched.target} {status}.', 'success')
    return redirect(url_for('scanner.list_schedules'))


@scanner_bp.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@login_required
def delete_schedule(schedule_id):
    sched = ScheduledScan.query.filter_by(id=schedule_id, user_id=current_user.id).first_or_404()
    db.session.delete(sched)
    db.session.commit()
    flash(f'Scheduled scan for {sched.target} deleted.', 'success')
    return redirect(url_for('scanner.list_schedules'))

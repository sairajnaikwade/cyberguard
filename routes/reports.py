"""
CyberGuard — Report generation routes (CSV + PDF)
"""

import csv
import io
from flask import Blueprint, send_file, abort
from flask_login import login_required, current_user
from models import ScanResult
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

reports_bp = Blueprint('reports', __name__)

# ── CSV ───────────────────────────────────────────────────────────────────────
@reports_bp.route('/csv/<int:scan_id>')
@login_required
def export_csv(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['CyberGuard Vulnerability Scanner — Scan Report'])
    writer.writerow(['Target', scan.target, 'Resolved IP', scan.resolved_ip or 'N/A'])
    writer.writerow(['Scan type', scan.scan_type, 'Risk score', scan.risk_score])
    writer.writerow(['Status', scan.status, 'Started', scan.started_at])
    writer.writerow([])

    writer.writerow(['PORT', 'PROTOCOL', 'STATE', 'SERVICE', 'PRODUCT', 'VERSION'])
    for p in scan.ports:
        writer.writerow([p['port'], p['proto'], p['state'],
                         p['service'], p.get('product', ''), p.get('version', '')])
    writer.writerow([])

    writer.writerow(['CVE', 'PORT', 'SERVICE', 'SEVERITY', 'CVSS', 'DESCRIPTION'])
    for v in scan.vulns:
        writer.writerow([v['cve'], v.get('port', ''), v.get('service', ''),
                         v['severity'], v.get('cvss', ''), v['desc']])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'cyberguard_scan_{scan_id}.csv'
    )


# ── PDF ───────────────────────────────────────────────────────────────────────
DARK_BG   = colors.HexColor('#0d1117')
GREEN     = colors.HexColor('#00ff88')
RED       = colors.HexColor('#ff4444')
ORANGE    = colors.HexColor('#ff8c00')
BLUE      = colors.HexColor('#4da6ff')
GRAY      = colors.HexColor('#8b949e')
WHITE     = colors.white
CELL_BG   = colors.HexColor('#161b22')
HEAD_BG   = colors.HexColor('#21262d')

SEV_COLOR = {
    'critical': colors.HexColor('#ff4444'),
    'high':     colors.HexColor('#ff8c00'),
    'medium':   colors.HexColor('#ffd700'),
    'low':      colors.HexColor('#00ff88'),
}


@reports_bp.route('/pdf/<int:scan_id>')
@login_required
def export_pdf(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle('title', fontSize=22, textColor=GREEN,
                                 alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=4)
    sub_style   = ParagraphStyle('sub',   fontSize=11, textColor=GRAY,
                                 alignment=TA_CENTER, spaceAfter=12)
    h2_style    = ParagraphStyle('h2',    fontSize=13, textColor=BLUE,
                                 fontName='Helvetica-Bold', spaceBefore=10, spaceAfter=6)
    body_style  = ParagraphStyle('body',  fontSize=9,  textColor=WHITE, leading=14)

    # Header
    story.append(Paragraph('CyberGuard Vulnerability Scanner', title_style))
    story.append(Paragraph('Automated Security Scan Report', sub_style))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GREEN))
    story.append(Spacer(1, 8))

    # Summary table
    sev = scan.severity_counts()
    summary_data = [
        ['Target', scan.target,         'Resolved IP',  scan.resolved_ip or 'N/A'],
        ['Scan type', scan.scan_type,   'Risk score',   str(scan.risk_score)],
        ['Status', scan.status,         'Open ports',   str(len(scan.open_ports))],
        ['Critical', str(sev['critical']), 'High',      str(sev['high'])],
        ['Medium', str(sev['medium']),  'Low',          str(sev['low'])],
    ]
    t = Table(summary_data, colWidths=[35*mm, 60*mm, 35*mm, 50*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), CELL_BG),
        ('TEXTCOLOR',  (0,0), (-1,-1), WHITE),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('FONTNAME',   (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',   (2,0), (2,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR',  (0,0), (0,-1), BLUE),
        ('TEXTCOLOR',  (2,0), (2,-1), BLUE),
        ('GRID',       (0,0), (-1,-1), 0.3, GRAY),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [CELL_BG, HEAD_BG]),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Open ports
    story.append(Paragraph('Open Ports', h2_style))
    open_ports = scan.open_ports
    if open_ports:
        port_data = [['Port', 'Protocol', 'Service', 'Product', 'Version']]
        for p in open_ports:
            port_data.append([str(p['port']), p['proto'], p['service'],
                               p.get('product',''), p.get('version','')])
        pt = Table(port_data, colWidths=[20*mm, 22*mm, 30*mm, 50*mm, 58*mm])
        pt.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0),  HEAD_BG),
            ('TEXTCOLOR',   (0,0), (-1,0),  GREEN),
            ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 8),
            ('TEXTCOLOR',   (0,1), (-1,-1), WHITE),
            ('BACKGROUND',  (0,1), (-1,-1), CELL_BG),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CELL_BG, HEAD_BG]),
            ('GRID',        (0,0), (-1,-1), 0.3, GRAY),
            ('TOPPADDING',  (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0),(-1,-1), 4),
        ]))
        story.append(pt)
    else:
        story.append(Paragraph('No open ports found.', body_style))

    story.append(Spacer(1, 10))

    # Vulnerabilities
    story.append(Paragraph('Vulnerabilities', h2_style))
    if scan.vulns:
        vuln_data = [['CVE', 'Port', 'Service', 'Severity', 'CVSS', 'Description']]
        for v in scan.vulns:
            vuln_data.append([v['cve'], str(v.get('port','')), v.get('service',''),
                               v['severity'].upper(), str(v.get('cvss','')), v['desc']])
        vt = Table(vuln_data, colWidths=[28*mm, 14*mm, 22*mm, 20*mm, 14*mm, 82*mm])
        ts_cmds = [
            ('BACKGROUND',  (0,0), (-1,0),  HEAD_BG),
            ('TEXTCOLOR',   (0,0), (-1,0),  RED),
            ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 7.5),
            ('TEXTCOLOR',   (0,1), (-1,-1), WHITE),
            ('BACKGROUND',  (0,1), (-1,-1), CELL_BG),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [CELL_BG, HEAD_BG]),
            ('GRID',        (0,0), (-1,-1), 0.3, GRAY),
            ('TOPPADDING',  (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0),(-1,-1), 4),
        ]
        # Color severity cells
        for i, v in enumerate(scan.vulns, start=1):
            c = SEV_COLOR.get(v['severity'].lower(), WHITE)
            ts_cmds.append(('TEXTCOLOR', (3,i), (3,i), c))
            ts_cmds.append(('FONTNAME',  (3,i), (3,i), 'Helvetica-Bold'))
        vt.setStyle(TableStyle(ts_cmds))
        story.append(vt)
    else:
        story.append(Paragraph('No vulnerabilities detected.', body_style))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GRAY))
    story.append(Paragraph(
        f'Generated by CyberGuard — {scan.finished_at or scan.started_at}',
        ParagraphStyle('footer', fontSize=8, textColor=GRAY, alignment=TA_CENTER, spaceBefore=6)
    ))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True,
                     download_name=f'cyberguard_scan_{scan_id}.pdf')

from app import create_app, celery_init_app
from scanner_engine import run_scan

app = create_app()
celery_app = celery_init_app(app)

@celery_app.task(name='celery_worker.scan_task')
def scan_task(scan_id: int):
    run_scan(scan_id, app)

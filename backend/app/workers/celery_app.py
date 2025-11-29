"""
Celery configuration for background tasks
"""
from celery import Celery
from kombu import Queue
import os

# Redis URL
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Create Celery app
celery_app = Celery(
    "owasp_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.workers.tasks"]
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3300,  # 55 min soft limit
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_queues=(
        Queue('default'),
        Queue('scans', routing_key='scan.#'),
        Queue('reports', routing_key='report.#'),
    ),
    task_default_queue='default',
    task_routes={
        'app.workers.tasks.run_scan': {'queue': 'scans'},
        'app.workers.tasks.generate_report': {'queue': 'reports'},
    },
)
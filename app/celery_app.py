from celery import Celery

celery_app = Celery(
    'model_scanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/1',
)

celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='Asia/Shanghai',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=60,
    task_soft_time_limit=50,
)

# 显式注册任务模块，确保 Celery Worker 启动时加载
celery_app.autodiscover_tasks(['app.tasks'])

from celery import Celery
from app import create_app

flask_app = create_app()

def make_celery(app):
    broker_url = app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    backend_url = app.config.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

    celery = Celery(
        app.import_name,
        broker=broker_url,
        backend=backend_url,
        include=["tasks"]
    )

    celery.conf.update(
        task_serializer='json',
        result_serializer='json',
        accept_content=['json']
    )

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

celery = make_celery(flask_app)

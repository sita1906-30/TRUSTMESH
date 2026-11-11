"""
TRUSTMESH Production WSGI Entry Point (Phase 4, Task 5)

Serves the Flask WSGI application for production servers such as Gunicorn on Azure App Service.
Usage:
    gunicorn --bind=0.0.0.0:8000 --workers=2 --threads=4 wsgi:app
"""

from app import app

if __name__ == "__main__":
    app.run()


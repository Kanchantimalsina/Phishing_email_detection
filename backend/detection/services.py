import os

from django.conf import settings
from rest_framework import status

from .analyzer import analyze_email, load_model


def detect_email(sender='', subject='', body='', mode='hybrid'):
    """Single entry point used by API views and legacy wrappers."""
    return analyze_email(sender=sender, subject=subject, body=body, mode=mode)


def detection_health():
    """Return health payload and HTTP status for detection dependencies."""
    _model, _vectorizer, model_available = load_model()

    model_path = getattr(settings, 'ML_MODEL_PATH', '')
    payload = {
        'status': 'ok' if model_available else 'warning',
        'model_available': bool(model_available),
        'model_name': os.path.basename(model_path) if model_path else 'phishing_model.pkl',
    }

    response_status = (
        status.HTTP_200_OK if model_available else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return payload, response_status

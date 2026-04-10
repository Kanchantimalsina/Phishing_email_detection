from .analyzer import analyze_email


def detect_email(sender='', subject='', body='', mode='hybrid'):
    """Single entry point used by API views and legacy wrappers."""
    return analyze_email(sender=sender, subject=subject, body=body, mode=mode)

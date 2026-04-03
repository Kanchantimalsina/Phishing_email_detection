"""Legacy compatibility wrapper for old imports.

Use detection.services.detect_email for all new code paths.
"""

from .services import detect_email


def analyze_email(sender, subject, body):
    return detect_email(sender=sender, subject=subject, body=body)

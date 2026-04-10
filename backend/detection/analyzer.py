"""
PhisGuard Core Detection Engine
Combines rule-based analysis + ML model.
"""

import re
import os
import joblib
from functools import lru_cache
from django.conf import settings
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from rest_framework import serializers

from .models import DetectionRule
from .rules import (
    extract_urls,
    is_url_suspicious,
    check_sender,
    check_urgent_keywords,
    check_attachments,
    calculate_rule_score,
    get_verdict,
    get_recommendations,
)


class EmailCheckSerializer(serializers.Serializer):
    """Validation layer for detection requests with backward-compatible keys."""

    email_text = serializers.CharField(required=False, allow_blank=True, default='')
    sender = serializers.CharField(required=False, allow_blank=True, default='')
    subject = serializers.CharField(required=False, allow_blank=True, default='')
    body = serializers.CharField(required=False, allow_blank=True, default='')

    # Legacy keys used by some clients.
    sender_email = serializers.CharField(required=False, allow_blank=True, default='')
    email_subject = serializers.CharField(required=False, allow_blank=True, default='')
    email_body = serializers.CharField(required=False, allow_blank=True, default='')

    def validate(self, attrs):
        attrs['sender'] = attrs.get('sender') or attrs.get('sender_email', '')
        attrs['subject'] = attrs.get('subject') or attrs.get('email_subject', '')
        attrs['body'] = attrs.get('body') or attrs.get('email_body', '')
        return attrs


# -----------------------------
# ML FEATURE ENGINEERING
# -----------------------------

def _clean_text(text: str) -> str:
    text = (text or '').lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\W', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    words = [word for word in text.split() if word not in ENGLISH_STOP_WORDS]
    return ' '.join(words)


def _url_feature_row(text: str) -> list[int]:
    urls = extract_urls(text)
    has_https = int(any(url.startswith('https') for url in urls))
    has_ip = int(any(re.search(r'\d+\.\d+\.\d+\.\d+', url) for url in urls))
    suspicious_words = int(
        any(
            word in url.lower()
            for word in ['login', 'verify', 'secure', 'update']
            for url in urls
        )
    )
    return [len(urls), has_https, has_ip, suspicious_words]


# -----------------------------
# LOAD ML MODEL (CACHED)
# -----------------------------

@lru_cache(maxsize=1)
def load_model():
    try:
        model_path = getattr(settings, "ML_MODEL_PATH", "")
        vectorizer_path = getattr(settings, "VECTORIZER_PATH", "")
        model = joblib.load(model_path) if os.path.exists(model_path) else None
        vectorizer = joblib.load(vectorizer_path) if os.path.exists(vectorizer_path) else None
        return model, vectorizer, model is not None and vectorizer is not None
    except Exception:
        return None, None, False


# -----------------------------
# ML PREDICTION
# -----------------------------

def get_ml_score(text: str) -> float:
    model, vectorizer, available = load_model()

    if not available:
        return 0.0

    try:
        cleaned_text = _clean_text(text)
        text_features = vectorizer.transform([cleaned_text])
        url_features = csr_matrix([_url_feature_row(text)])
        features = hstack([text_features, url_features])

        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features)[0]
            return float(proba[1])
    except Exception:
        pass

    return 0.0


# SCORE COMBINATION

def combine_scores(rule_score: float, ml_score: float, mode="hybrid") -> float:
    ml_score = ml_score * 100

    if mode == "rule":
        return rule_score

    if mode == "ml":
        return ml_score if ml_score else rule_score

    if ml_score <= 0:
        return rule_score

    # hybrid
    return (rule_score * 0.3) + (ml_score * 0.7)


def _apply_configurable_rules(sender: str, subject: str, body: str, urls: list[str]) -> list[dict]:
    text = f"{subject} {body}".lower()
    sender_l = (sender or '').lower()
    urls_l = [url.lower() for url in urls]
    custom_indicators = []

    try:
        active_rules = DetectionRule.objects.filter(is_active=True)
    except Exception:
        # During bootstrap/migration gaps, skip configurable rules gracefully.
        return custom_indicators

    for rule in active_rules:
        pattern = (rule.pattern or '').strip().lower()
        if not pattern:
            continue

        matched = False
        if rule.category == 'sender':
            matched = pattern in sender_l
        elif rule.category == 'url':
            matched = any(pattern in url for url in urls_l)
        elif rule.category in ['keyword', 'attachment']:
            matched = pattern in text
        else:
            matched = pattern in text or pattern in sender_l or any(pattern in url for url in urls_l)

        if not matched:
            continue

        custom_indicators.append(
            {
                'category': rule.category,
                'description': rule.description or f'Configurable rule matched: {rule.name}',
                'severity': rule.severity,
                'weight': rule.weight,
                'value': pattern,
            }
        )

    return custom_indicators


# MAIN ANALYSIS FUNCTION

def analyze_email(sender=None, subject=None, body=None, mode="hybrid"):
    sender = sender or ""
    subject = subject or ""
    body = body or ""
    text = f"{subject} {body}"

    indicators = []

    # 1. Rule-based checks
    indicators += check_sender(sender, body)
    indicators += check_urgent_keywords(body, subject)

    urls = extract_urls(text)

    for url in urls[:20]:
        flags = is_url_suspicious(url)
        for f in flags:
            indicators.append({
                "category": "url",
                "description": f["reason"],
                "severity": f["severity"],
                "value": url[:200],
            })

    indicators += check_attachments(body)
    indicators += _apply_configurable_rules(sender, subject, body, urls)

    # Limit indicators (UI-friendly)
    indicators = indicators[:15]

    # 2. Rule score
    rule_score = calculate_rule_score(indicators)

    # 3. ML score
    ml_confidence = get_ml_score(text)

    # 4. Final score
    final_score = combine_scores(rule_score, ml_confidence, mode)
    final_score = min(final_score, 100)

    # 5. Verdict
    verdict = get_verdict(final_score)

    # 6. Recommendations
    recommendations = get_recommendations(verdict, indicators)
    reasons = [ind.get("description", "") for ind in indicators if ind.get("description")]

    return {
        "verdict": verdict,
        "risk_score": round(final_score, 1),
        "rule_score": round(rule_score, 1),
        "ml_confidence": round(ml_confidence, 4),
        "analysis_mode": mode,
        "indicators": indicators,
        "reasons": reasons,
        "recommendations": recommendations,
        "urls_found": urls[:20],
    }
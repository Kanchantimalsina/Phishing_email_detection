"""
PhisGuard Core Detection Engine
Combines rule-based analysis + ML model.
"""

import re
import os
import joblib
from functools import lru_cache
from django.conf import settings
from rest_framework import serializers

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
# TEXT CLEANING (FOR ML)
# -----------------------------

def clean_text(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\W", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


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

        return model, vectorizer, model is not None
    except Exception:
        return None, None, False


# -----------------------------
# ML PREDICTION
# -----------------------------

def get_ml_score(text: str) -> float:
    model, vectorizer, available = load_model()

    if not available or not vectorizer:
        return 0.0

    try:
        cleaned = clean_text(text)
        features = vectorizer.transform([cleaned])

        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features)[0]
            return float(proba[-1])  # phishing probability
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

    # hybrid
    return (rule_score * 0.5) + (ml_score * 0.5)


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

    return {
        "verdict": verdict,
        "risk_score": round(final_score, 1),
        "rule_score": round(rule_score, 1),
        "ml_confidence": round(ml_confidence, 4),
        "analysis_mode": mode,
        "indicators": indicators,
        "recommendations": recommendations,
        "urls_found": urls[:20],
    }
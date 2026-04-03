import re
from pathlib import Path

import joblib
from django.conf import settings


class MLEngine:
    def __init__(self):
        self.model = None
        self.vectorizer = None

        base_dir = Path(getattr(settings, 'BASE_DIR', Path.cwd()))
        model_candidates = [
            Path(getattr(settings, 'ML_MODEL_PATH', '')),
            base_dir / 'ml_model' / 'phishing_model.pkl',
            base_dir / 'detection' / 'ml_model' / 'phishing_model.pkl',
        ]
        vectorizer_candidates = [
            Path(getattr(settings, 'VECTORIZER_PATH', '')),
            base_dir / 'ml_model' / 'tfidf_vectorizer.pkl',
            base_dir / 'detection' / 'ml_model' / 'tfidf_vectorizer.pkl',
            base_dir / 'detection' / 'ml_model' / 'vectorizer.pkl',
        ]

        self.model = _load_first_existing(model_candidates)
        self.vectorizer = _load_first_existing(vectorizer_candidates)

    @property
    def is_ready(self):
        return self.model is not None and self.vectorizer is not None

    def clean_text(self, text):
        text = (text or '').lower()
        text = re.sub(r"http\S+|www\S+", " URL ", text)
        text = re.sub(r"\W", " ", text)
        return text.strip()

    def get_score(self, text):
        if not self.is_ready:
            return 0.0
        
        cleaned = self.clean_text(text)
        text_features = self.vectorizer.transform([cleaned])
        
        # Simple prediction (Probability of being phishing)
        try:
            proba = self.model.predict_proba(text_features)[0]
            return float(proba[1]) * 100
        except Exception:
            return 0.0


def _load_first_existing(path_candidates):
    for candidate in path_candidates:
        if not str(candidate):
            continue
        if candidate.exists():
            try:
                return joblib.load(candidate)
            except Exception:
                continue
    return None
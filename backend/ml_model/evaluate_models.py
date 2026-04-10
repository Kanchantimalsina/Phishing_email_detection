import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import re
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

URL_PATTERN = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")

LABEL_TRUTHY = {"1", "true", "phishing", "malicious", "spam", "yes"}
LABEL_FALSY = {"0", "false", "safe", "legit", "ham", "no", "benign"}


@dataclass
class EvaluationResult:
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float]
    confusion_matrix: List[List[int]]


def _clean_text(text: str) -> str:
    text = (text or "").lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\W", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    words = [word for word in text.split() if word not in ENGLISH_STOP_WORDS]
    return " ".join(words)


def _extract_urls(text: str) -> List[str]:
    return URL_PATTERN.findall(text or "")


def _url_feature_row(text: str) -> List[int]:
    urls = _extract_urls(text)
    has_https = int(any(url.startswith("https") for url in urls))
    has_ip = int(any(IP_PATTERN.search(url) for url in urls))
    suspicious_words = int(
        any(
            word in url.lower()
            for url in urls
            for word in ["login", "verify", "secure", "update", "password", "bank"]
        )
    )
    return [len(urls), has_https, has_ip, suspicious_words]


def _normalize_label(raw: str) -> Optional[int]:
    value = str(raw).strip().lower()
    if value in LABEL_TRUTHY:
        return 1
    if value in LABEL_FALSY:
        return 0
    return None


def _pick_value(row: Dict[str, str], keys: List[str]) -> str:
    for key in keys:
        if key in row and str(row[key]).strip():
            return str(row[key]).strip()
    return ""


def load_dataset(csv_path: Path) -> Tuple[List[str], List[int]]:
    texts: List[str] = []
    labels: List[int] = []

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV appears empty or missing a header row.")

        for row in reader:
            label_raw = _pick_value(row, ["label", "target", "class", "verdict", "is_phishing"])
            label = _normalize_label(label_raw)
            if label is None:
                continue

            combined_text = _pick_value(row, ["text", "email_text", "content", "email_body", "body"])
            if not combined_text:
                sender = _pick_value(row, ["sender", "sender_email", "from"])
                subject = _pick_value(row, ["subject", "email_subject", "title"])
                body = _pick_value(row, ["body", "email_body", "message", "content"])
                combined_text = f"{sender} {subject} {body}".strip()

            if not combined_text:
                continue

            texts.append(combined_text)
            labels.append(label)

    if len(texts) < 40:
        raise ValueError(
            f"Not enough valid rows after parsing labels/text ({len(texts)} rows). "
            "Provide at least ~40 labeled rows for meaningful evaluation."
        )

    if len(set(labels)) < 2:
        raise ValueError("Dataset must contain at least 2 classes (phishing and safe).")

    return texts, labels


def build_feature_matrices(
    train_texts: List[str],
    test_texts: List[str],
) -> Tuple[csr_matrix, csr_matrix, TfidfVectorizer]:
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=6000, min_df=2)

    cleaned_train = [_clean_text(t) for t in train_texts]
    cleaned_test = [_clean_text(t) for t in test_texts]

    x_train_text = vectorizer.fit_transform(cleaned_train)
    x_test_text = vectorizer.transform(cleaned_test)

    x_train_url = csr_matrix([_url_feature_row(t) for t in train_texts])
    x_test_url = csr_matrix([_url_feature_row(t) for t in test_texts])

    x_train = hstack([x_train_text, x_train_url])
    x_test = hstack([x_test_text, x_test_url])
    return x_train, x_test, vectorizer


def _evaluate_predictions(
    model_name: str,
    y_true: List[int],
    y_pred: List[int],
    y_score: Optional[List[float]],
) -> EvaluationResult:
    roc_auc = None
    if y_score is not None:
        try:
            roc_auc = roc_auc_score(y_true, y_score)
        except ValueError:
            roc_auc = None

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    return EvaluationResult(
        model_name=model_name,
        accuracy=accuracy_score(y_true, y_pred),
        precision=precision_score(y_true, y_pred, zero_division=0),
        recall=recall_score(y_true, y_pred, zero_division=0),
        f1=f1_score(y_true, y_pred, zero_division=0),
        roc_auc=roc_auc,
        confusion_matrix=matrix,
    )


def evaluate_candidate_models(
    x_train: csr_matrix,
    x_test: csr_matrix,
    y_train: List[int],
    y_test: List[int],
) -> List[EvaluationResult]:
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=2500,
            class_weight="balanced",
            random_state=42,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "Linear SVM": LinearSVC(class_weight="balanced", random_state=42),
        "Multinomial NB": MultinomialNB(alpha=0.6),
    }

    results: List[EvaluationResult] = []
    for model_name, model in models.items():
        model.fit(x_train, y_train)
        y_pred = model.predict(x_test)

        y_score = None
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(x_test)[:, 1]
        elif hasattr(model, "decision_function"):
            y_score = model.decision_function(x_test)

        results.append(_evaluate_predictions(model_name, y_test, y_pred, y_score))

    return sorted(results, key=lambda item: item.f1, reverse=True)


def evaluate_production_model(
    model_path: Path,
    vectorizer_path: Path,
    test_texts: List[str],
    y_test: List[int],
) -> Optional[EvaluationResult]:
    if not model_path.exists() or not vectorizer_path.exists():
        return None

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    cleaned_test = [_clean_text(t) for t in test_texts]
    x_test_text = vectorizer.transform(cleaned_test)
    x_test_url = csr_matrix([_url_feature_row(t) for t in test_texts])
    x_test = hstack([x_test_text, x_test_url])

    y_pred = model.predict(x_test)
    y_score = model.predict_proba(x_test)[:, 1] if hasattr(model, "predict_proba") else None

    return _evaluate_predictions("Current Production Model", y_test, y_pred, y_score)


def _fmt(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.4f}"


def write_outputs(
    output_dir: Path,
    dataset_path: Path,
    total_rows: int,
    train_rows: int,
    test_rows: int,
    results: List[EvaluationResult],
    protocol_note: str,
) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"evaluation_{stamp}.json"
    md_path = output_dir / f"evaluation_{stamp}.md"

    payload = {
        "dataset": str(dataset_path),
        "generated_at": datetime.now().isoformat(),
        "rows": {
            "total": total_rows,
            "train": train_rows,
            "test": test_rows,
        },
        "protocol": protocol_note,
        "results": [
            {
                "model": r.model_name,
                "accuracy": r.accuracy,
                "precision": r.precision,
                "recall": r.recall,
                "f1": r.f1,
                "roc_auc": r.roc_auc,
                "confusion_matrix": r.confusion_matrix,
            }
            for r in results
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Experimental Evaluation Report",
        "",
        f"Dataset: `{dataset_path}`",
        f"Generated: `{datetime.now().isoformat()}`",
        "",
        "## Dataset Protocol",
        "",
        protocol_note,
        "",
        f"- Total rows used: **{total_rows}**",
        f"- Train rows: **{train_rows}**",
        f"- Test rows: **{test_rows}**",
        "",
        "## Model Comparison",
        "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for result in results:
        lines.append(
            f"| {result.model_name} | {_fmt(result.accuracy)} | {_fmt(result.precision)} | {_fmt(result.recall)} | {_fmt(result.f1)} | {_fmt(result.roc_auc)} |"
        )

    lines.extend([
        "",
        "## Confusion Matrices",
        "",
        "Format: `[[TN, FP], [FN, TP]]`",
        "",
    ])

    for result in results:
        lines.append(f"- **{result.model_name}**: `{result.confusion_matrix}`")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train and compare phishing classifiers with standard evaluation metrics."
    )
    parser.add_argument("--dataset", required=True, help="Path to labeled CSV dataset")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio (default: 0.2)")
    parser.add_argument(
        "--output-dir",
        default="ml_model/experiments",
        help="Directory to write evaluation outputs",
    )
    parser.add_argument(
        "--model-path",
        default="ml_model/phishing_model.pkl",
        help="Existing production model path for optional comparison",
    )
    parser.add_argument(
        "--vectorizer-path",
        default="ml_model/tfidf_vectorizer.pkl",
        help="Existing production vectorizer path for optional comparison",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    dataset_path = Path(args.dataset).resolve()
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    texts, labels = load_dataset(dataset_path)

    x_train_texts, x_test_texts, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=args.test_size,
        random_state=42,
        stratify=labels,
    )

    x_train, x_test, _ = build_feature_matrices(x_train_texts, x_test_texts)
    results = evaluate_candidate_models(x_train, x_test, y_train, y_test)

    production_result = evaluate_production_model(
        Path(args.model_path),
        Path(args.vectorizer_path),
        x_test_texts,
        y_test,
    )
    if production_result is not None:
        results.append(production_result)
        results = sorted(results, key=lambda item: item.f1, reverse=True)

    protocol_note = (
        "This evaluation uses a stratified train/test split with random_state=42 and "
        "reports Accuracy, Precision, Recall, F1, ROC-AUC, and confusion matrix. "
        "Feature engineering combines TF-IDF text features with URL-derived structural features."
    )

    json_path, md_path = write_outputs(
        Path(args.output_dir),
        dataset_path,
        total_rows=len(texts),
        train_rows=len(y_train),
        test_rows=len(y_test),
        results=results,
        protocol_note=protocol_note,
    )

    print("Evaluation complete.")
    print(f"JSON output: {json_path}")
    print(f"Markdown output: {md_path}")


if __name__ == "__main__":
    main()

# Experimental Evaluation Protocol

Use this protocol for your final year report to present reproducible ML evaluation.

## 1. Dataset Format

Prepare a CSV with at least:
- One label column: label, target, class, verdict, or is_phishing
- One text source:
- Direct text column: text, email_text, content, email_body, body
- Or split columns: sender/sender_email, subject/email_subject, body/email_body

Label values accepted:
- Phishing class: 1, true, phishing, malicious, spam, yes
- Safe class: 0, false, safe, legit, ham, no, benign

## 2. Run Evaluation Script

From backend folder:

```powershell
python ml_model/evaluate_models.py --dataset path/to/your_dataset.csv
```

Optional flags:

```powershell
python ml_model/evaluate_models.py --dataset path/to/your_dataset.csv --test-size 0.2 --output-dir ml_model/experiments
```

## 3. Outputs Generated

The script creates:
- JSON: machine-readable metrics
- Markdown: report-ready section with
- Model comparison table
- Accuracy, Precision, Recall, F1, ROC-AUC
- Confusion matrix for each model in format [[TN, FP], [FN, TP]]

## 4. Recommended Report Section Template

Include this in your thesis/report:
- Dataset source and size
- Train/test protocol (stratified split, random_state=42)
- Feature engineering details (TF-IDF + URL features)
- Model comparison table
- Confusion matrix interpretation
- Best model justification using F1 and Recall

## 5. Viva Talking Points

- Why use Precision/Recall/F1 instead of only Accuracy.
- Tradeoff between catching phishing (high recall) and reducing false alarms (precision).
- Why confusion matrix gives operational insight beyond a single metric.

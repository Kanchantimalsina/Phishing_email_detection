# PhisGuard Backend Setup & Deployment Guide

## Quick Start

### 1. Prerequisites
- Python 3.9+
- PostgreSQL 12+ (or SQLite for development)
- pip/virtualenv

### 2. Initial Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.\.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file from template
cp .env.example .env
```

### 3. Configure Environment Variables

Edit `.env` file:
```env
SECRET_KEY=<generate-with-command-below>
DEBUG=True
DB_ENGINE=django.db.backends.postgresql
DB_NAME=phishing_db
DB_USER=postgres
DB_PASSWORD=your-secure-password
DB_HOST=localhost
DB_PORT=5432
```

Generate a strong SECRET_KEY:
```bash
python manage.py shell -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### 4. Database Setup

#### Option A: PostgreSQL (Recommended for Production)

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE phishing_db;
CREATE USER phishing_user WITH PASSWORD 'secure-password-here';
ALTER ROLE phishing_user SET client_encoding TO 'utf8';
ALTER ROLE phishing_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE phishing_user SET default_transaction_deferrable TO on;
ALTER ROLE phishing_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE phishing_db TO phishing_user;
\q
EOF

# Update DB_USER and DB_PASSWORD in .env
```

#### Option B: SQLite (Quick Development Setup)

```bash
# Change settings.py database engine temporarily:
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }
```

### 5. Run Migrations

```bash
# Apply all migrations
python manage.py migrate

# Create superuser for admin panel
python manage.py createsuperuser

# Or use non-interactive command:
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
User.objects.create_superuser(
    email='admin@phisguard.local',
    username='admin',
    full_name='Admin User',
    password='AdminPass123!'
)
"
```

### 6. Verify Backend

```bash
# Run verification script
python verify_backend.py

# Expected output: All checks passed
```

### 7. Start Development Server

```bash
# Run the server
python manage.py runserver

# Server will be available at:
# http://127.0.0.1:8000/
# Admin panel: http://127.0.0.1:8000/admin/
# API root: http://127.0.0.1:8000/api/
```

## API Endpoints

### Authentication & Access Model

- Django admin login: `http://127.0.0.1:8000/admin/login/`
- Admin API access: authenticated staff/superuser session or authenticated JWT user with admin privileges
- Analyst API access: authenticated user in `analyst` group or admin/staff user
- Public endpoints (`analyze`, `history`, `detail`, `stats`) do not require authentication

> Note: `/api/users/*` endpoints are not part of this backend currently.

### Detection

**Predict Phishing:**
```
POST /api/detection/predict/
Body: {
  "email_text": "full email text",
  OR
  "sender_email": "sender@example.com",
  "email_subject": "Subject line",
  "email_body": "Email body text"
}
Response: {
  "id": 1,
  "sender_email": "sender@example.com",
  "subject": "Subject line",
  "email_body": "Email body text",
  "source": "manual",
  "verdict": "phishing" | "suspicious" | "safe",
  "risk_score": 75,
  "rule_score": 60,
  "ml_confidence": 0.82,
  "analysis_mode": "hybrid",
  "indicators": [...],
  "recommendations": [...],
  "urls_found": [...],
  "analyzed_at": "2026-04-04T12:34:56Z"
}
```

**Get Analysis History:**
```
GET /api/detection/history/
Query: ?page=1&page_size=50
Response: {
  "count": 123,
  "page": 1,
  "page_size": 50,
  "has_next": true,
  "results": [...]
}
```

**Get Analysis Detail:**
```
GET /api/detection/history/{id}/
```

**Get Dashboard Stats:**
```
GET /api/detection/stats/
Response: {
  "total_analyzed": 10,
  "phishing_detected": 2,
  "suspicious_emails": 3,
  "safe_emails": 5,
  "average_risk_score": 41
}
```

### Admin Endpoints (Auth Required)

```text
GET    /api/detection/admin/session/
GET    /api/detection/admin/users/
GET    /api/detection/admin/analytics/?days=30
GET    /api/detection/admin/alerts/?days=30
GET    /api/detection/admin/logs/?limit=100
GET    /api/detection/admin/reports/download/?days=30
GET    /api/detection/admin/model-versions/
POST   /api/detection/admin/model-versions/
POST   /api/detection/admin/model-versions/{id}/activate/
GET    /api/detection/admin/rules/
POST   /api/detection/admin/rules/
PATCH  /api/detection/admin/rules/{id}/
```

## Running Tests

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test users
python manage.py test detection

# Run with verbose output
python manage.py test --verbosity=2

# Run and keep test database
python manage.py test --keepdb
```

## Experimental Evaluation (Final Year Report)

To generate model comparison, confusion matrix, precision, recall, and F1 score:

```bash
python ml_model/evaluate_models.py --dataset path/to/your_dataset.csv
```

Outputs are written under `backend/ml_model/experiments/` as:
- JSON metrics file
- Markdown report section ready to paste into your documentation

Reference protocol and accepted dataset columns:
- `backend/ml_model/EVALUATION_PROTOCOL.md`

## Security Considerations

1. **Never commit `.env` file** - It's in .gitignore
2. **Regenerate SECRET_KEY** for each environment
3. **Use strong passwords** in production
4. **Set DEBUG=False** in production
5. **Update ALLOWED_HOSTS** with your domain
6. **Use HTTPS** in production (set SECURE_SSL_REDIRECT=True)
7. **Rotate JWT tokens** regularly
8. **Monitor logs** for suspicious activity

## Troubleshooting

### "No module named 'django'"
```bash
pip install -r requirements.txt
```

### "PostgreSQL connection refused"
```bash
# Check PostgreSQL is running:
psycopg2-binary==2.9.11
# On Windows: Services → PostgreSQL
# On Mac: brew services list
# On Linux: sudo systemctl status postgresql
```

### "Database does not exist"
```bash
# Create the configured database first
python manage.py migrate
```

### "Model file not found"
- Ensure `backend/ml_model/phishing_model.pkl` exists
- Or set `model_available: false` and use rules-only mode

### "Static files not collected"
```bash
python manage.py collectstatic --noinput
```

## Production Deployment

### Using Gunicorn

```bash
pip install gunicorn

# Start server
gunicorn \
  --workers 4 \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  backend.wsgi:application
```

### Using Docker

See the main project's Docker configuration (if available).

## Monitoring & Maintenance

- Check logs regularly: `tail -f logs/django.log`
- Monitor database size and performance
- Rotate access logs monthly
- Backup database daily
- Update dependencies monthly

## Support

For issues, check:
1. Backend logs in `logs/` directory
2. Database connection settings in `.env`
3. Django error messages in browser (if DEBUG=True)
4. Test suite: `python manage.py test`

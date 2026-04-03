"""
Rule-based phishing detection logic.
Separated from ML code for maintainability.
"""
import re
from urllib.parse import urlparse


URGENT_KEYWORDS = [
    'urgent', 'immediately', 'act now', 'verify now', 'verify your account',
    'click here', 'confirm your', 'update your', 'suspended', 'locked',
    'limited time', 'expires', 'action required', 'your account has been',
    'unauthorized access', 'security alert', 'login attempt', 'reset your password',
    'verify identity', 'unusual activity', 'payment failed', 'invoice attached',
    'you have won', 'congratulations', 'free gift', 'claim now', 'winner',
    'OTP', 'one-time password', 'pin', 'bank details', 'credit card',
]

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'tiny.cc',
    'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at',
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.jar', '.js',
    '.xlsx', '.docx', '.zip', '.rar', '.iso', '.dmg',
]

LEGITIMATE_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
    'apple.com', 'amazon.com', 'paypal.com', 'facebook.com',
]

URL_PATTERN = re.compile(
    r'https?://[^\s<>"{}|\\^`\[\]]+',
    re.IGNORECASE
)

IP_IN_URL = re.compile(r'https?://\d{1,3}(\.\d{1,3}){3}')


def extract_urls(text: str) -> list[str]:
    return URL_PATTERN.findall(text)


def is_url_suspicious(url: str) -> list[dict]:
    flags = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # IP address instead of domain
        if IP_IN_URL.match(url):
            flags.append({'reason': 'IP address used instead of domain name', 'severity': 'high'})

        # URL shortener
        for short in SUSPICIOUS_DOMAINS:
            if short in domain:
                flags.append({'reason': f'URL shortener detected: {short}', 'severity': 'medium'})

        # Misleading subdomain (e.g. paypal.com.evil.com)
        for legit in LEGITIMATE_DOMAINS:
            if legit in domain and not domain.endswith(legit):
                flags.append({'reason': f'Subdomain mimicking {legit}', 'severity': 'high'})

        # Excessive hyphens in domain
        if domain.count('-') >= 3:
            flags.append({'reason': 'Excessive hyphens in domain (possible spoofing)', 'severity': 'medium'})

        # Non-HTTPS
        if parsed.scheme == 'http':
            flags.append({'reason': 'Non-secure HTTP link', 'severity': 'low'})

        # Very long URL
        if len(url) > 150:
            flags.append({'reason': 'Unusually long URL', 'severity': 'low'})

        # Special characters in URL
        if '%' in url and url.count('%') > 3:
            flags.append({'reason': 'URL contains multiple encoded characters', 'severity': 'medium'})

    except Exception:
        flags.append({'reason': 'Malformed URL', 'severity': 'medium'})

    return flags


def check_sender(sender: str, body: str) -> list[dict]:
    indicators = []
    if not sender:
        return indicators

    body = body or ''
    sender_lower = sender.lower()

    # Check for free email domains sending as corporate
    free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    for provider in free_providers:
        if provider in sender_lower:
            # Check if they claim to be a bank/company in the body
            impersonation_keywords = ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'ebay']
            for brand in impersonation_keywords:
                if brand in body.lower():
                    indicators.append({
                        'category': 'sender',
                        'description': f'Sender uses {provider} but email body mentions {brand} - possible impersonation',
                        'severity': 'high',
                        'value': sender,
                    })

    # Mismatched display name
    if '<' in sender and '>' in sender:
        display_name = sender[:sender.index('<')].strip().lower()
        email_addr = sender[sender.index('<') + 1:sender.index('>')].strip().lower()
        domain_from_name = display_name.replace(' ', '').replace(',', '').replace('.', '')
        email_domain = email_addr.split('@')[-1].replace('.', '') if '@' in email_addr else ''
        if domain_from_name and email_domain and domain_from_name not in email_domain and email_domain not in domain_from_name:
            indicators.append({
                'category': 'sender',
                'description': 'Display name does not match sender email address',
                'severity': 'high',
                'value': sender,
            })

    return indicators


def check_urgent_keywords(body: str, subject: str) -> list[dict]:
    indicators = []
    combined_text = f"{subject or ''} {body or ''}".lower()
    found_keywords = []
    for keyword in URGENT_KEYWORDS:
        if keyword.lower() in combined_text:
            found_keywords.append(keyword)

    if found_keywords:
        severity = 'high' if len(found_keywords) >= 3 else 'medium' if len(found_keywords) >= 1 else 'low'
        indicators.append({
            'category': 'keyword',
            'description': f'Urgent/manipulative language detected: {", ".join(found_keywords[:5])}',
            'severity': severity,
            'value': ', '.join(found_keywords[:5]),
        })
    return indicators


def check_attachments(body: str) -> list[dict]:
    indicators = []
    body_lower = (body or '').lower()
    for ext in DANGEROUS_EXTENSIONS:
        if ext in body_lower:
            indicators.append({
                'category': 'attachment',
                'description': f'Potentially dangerous file type referenced: {ext}',
                'severity': 'high' if ext in ['.exe', '.bat', '.cmd', '.vbs', '.ps1'] else 'medium',
                'value': ext,
            })
    return indicators


def calculate_rule_score(indicators: list[dict]) -> float:
    """Compute rule-based risk score (0-100) from extracted indicators."""
    severity_weights = {'high': 20, 'medium': 10, 'low': 5}
    score = 0
    for ind in indicators:
        score += severity_weights.get(ind.get('severity', 'low'), 5)
    return float(min(score, 100))


def get_verdict(risk_score: float) -> str:
    if risk_score >= 60:
        return 'phishing'
    if risk_score >= 30:
        return 'suspicious'
    return 'safe'


def get_recommendations(verdict: str, indicators: list[dict]) -> list[dict]:
    recs = []
    categories = {ind['category'] for ind in indicators}

    if verdict in ['phishing', 'suspicious']:
        recs.append({
            'title': 'Do Not Click Any Links',
            'description': 'Avoid clicking any links in this email. If you need to visit a website, type the URL directly into your browser.',
            'priority': 1,
        })
        recs.append({
            'title': 'Do Not Provide Personal Information',
            'description': 'Never share passwords, OTPs, bank details, or personal data through email links.',
            'priority': 1,
        })

    if 'sender' in categories:
        recs.append({
            'title': 'Verify the Sender Independently',
            'description': 'Contact the organization directly using official contact information from their website, not the email.',
            'priority': 1,
        })

    if 'attachment' in categories:
        recs.append({
            'title': 'Do Not Open Attachments',
            'description': 'Dangerous file types can install malware. Do not open attachments from unverified senders.',
            'priority': 1,
        })

    if 'url' in categories:
        recs.append({
            'title': 'Inspect Links Before Clicking',
            'description': 'Hover over links to see the actual URL. Check for misspellings or suspicious domains.',
            'priority': 2,
        })

    recs.append({
        'title': 'Report This Email',
        'description': 'Report the email as phishing to your email provider and, if impersonating an organization, notify that organization.',
        'priority': 2,
    })

    if verdict == 'safe':
        recs = [{
            'title': 'Stay Vigilant',
            'description': 'This email appears safe, but always be cautious. Do not share sensitive information unless you are 100% sure.',
            'priority': 3,
        }]

    return recs

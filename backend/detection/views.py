import csv
from datetime import timedelta

from django.db.models import Avg
from django.db.models import Count
from django.db.models import Max
from django.db.models import Q
from django.db.models.functions import TruncDate
from django.http import HttpResponse
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .analyzer import EmailCheckSerializer
from .models import DetectionRule
from .models import EmailAnalysis
from .models import ModelVersion
from .serializers import DetectionRuleSerializer
from .serializers import EmailAnalysisSerializer
from .serializers import ModelVersionSerializer
from .services import detect_email


def _extract_detection_inputs(validated_data):
    """Normalize supported request keys for the detection engine."""
    email_text = validated_data.get('email_text', '')
    sender = validated_data.get('sender', '')
    subject = validated_data.get('subject', '')

    # Keep compatibility with existing serializer that provides email_text only.
    body = validated_data.get('body') or email_text
    return sender, subject, body


def _extract_installation_id(request):
    return (
        request.data.get('installation_id')
        or request.data.get('device_id')
        or request.query_params.get('installation_id')
        or request.query_params.get('device_id')
        or ''
    ).strip()


def _normalize_email(value):
    return (value or '').strip().lower()


def _extract_user_email(request):
    user = _session_user(request)
    return (
        _normalize_email(request.data.get('user_email'))
        or _normalize_email(request.headers.get('X-User-Email'))
        or _normalize_email(request.query_params.get('user_email'))
        or _normalize_email(getattr(user, 'email', ''))
    )


def _extract_request_ip(request):
    forwarded_for = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    return forwarded_for or (request.META.get('REMOTE_ADDR') or '').strip()


def _analytics_queryset():
    queryset = EmailAnalysis.objects.all()
    excluded_emails = getattr(settings, 'PHISGUARD_ANALYTICS_EXCLUDED_EMAILS', set())
    excluded_ips = getattr(settings, 'PHISGUARD_ANALYTICS_EXCLUDED_IPS', set())

    if excluded_emails:
        queryset = queryset.exclude(user_email__in=excluded_emails)

    if excluded_ips:
        queryset = queryset.exclude(request_ip__in=excluded_ips)

    return queryset


def _history_queryset_for_request(request):
    installation_id = _extract_installation_id(request)
    scope = (request.query_params.get('scope') or 'all').strip().lower()

    # Default behavior: show all records from DB so history survives refresh/restart.
    if scope != 'installation':
        return EmailAnalysis.objects.all()

    if not installation_id:
        return EmailAnalysis.objects.none()

    return EmailAnalysis.objects.filter(installation_id=installation_id)


def _run_detection(serializer):
    sender, subject, body = _extract_detection_inputs(serializer.validated_data)
    return detect_email(sender=sender, subject=subject, body=body)


def _build_analysis_record_payload(request, serializer, result):
    sender, subject, body = _extract_detection_inputs(serializer.validated_data)
    installation_id = _extract_installation_id(request)
    return {
        'installation_id': installation_id,
        'user_email': _extract_user_email(request),
        'request_ip': _extract_request_ip(request),
        'sender_email': sender,
        'subject': subject,
        'email_body': body,
        'source': request.data.get('source', 'manual') or 'manual',
        'verdict': result.get('verdict', 'safe'),
        'risk_score': result.get('risk_score', 0),
        'rule_score': result.get('rule_score', 0),
        'ml_confidence': result.get('ml_confidence', 0),
        'analysis_mode': result.get('analysis_mode', 'hybrid'),
        'indicators': result.get('indicators', []),
        'recommendations': result.get('recommendations', []),
        'urls_found': result.get('urls_found', []),
    }


def _session_user(request):
    raw_request = getattr(request, '_request', None)
    if raw_request is None:
        return None
    return getattr(raw_request, 'user', None)


def _is_analyst_user(user):
    if not user or not user.is_authenticated:
        return False
    if user.is_staff or user.is_superuser:
        return True
    return user.groups.filter(name__iexact='analyst').exists()


def _require_admin_login(request):
    user = _session_user(request)
    if user and user.is_authenticated and (user.is_staff or user.is_superuser):
        return None

    return Response(
        {
            'error': 'Admin access required. Sign in at /admin/ with an admin account.',
        },
        status=status.HTTP_403_FORBIDDEN,
    )


def _require_analyst_login(request):
    user = _session_user(request)
    if _is_analyst_user(user):
        return None
    return Response(
        {
            'error': 'Analyst access required. Sign in with an analyst or admin account.',
        },
        status=status.HTTP_403_FORBIDDEN,
    )


def _parse_days(request, default=30, minimum=7, maximum=180):
    raw_days = request.query_params.get('days')
    if raw_days in (None, ''):
        days = default
    else:
        try:
            days = int(raw_days)
        except (TypeError, ValueError):
            raise ValueError('days must be an integer.')
    return max(minimum, min(days, maximum))


def _parse_limit(request, default=100, minimum=20, maximum=500):
    raw_limit = request.query_params.get('limit')
    if raw_limit in (None, ''):
        limit = default
    else:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            raise ValueError('limit must be an integer.')
    return max(minimum, min(limit, maximum))


def _mask_email(sender_email):
    if not sender_email or '@' not in sender_email:
        return 'redacted'

    local, domain = sender_email.split('@', 1)
    if len(local) <= 2:
        masked_local = '*' * len(local)
    else:
        masked_local = f'{local[0]}***{local[-1]}'
    return f'{masked_local}@{domain}'


def _build_phishing_trend(base_queryset, start_date, days):
    current_period = base_queryset.filter(analyzed_at__gte=start_date)
    previous_start = start_date - timedelta(days=days)
    previous_period = base_queryset.filter(analyzed_at__gte=previous_start, analyzed_at__lt=start_date)

    current_phishing = current_period.filter(verdict='phishing').count()
    previous_phishing = previous_period.filter(verdict='phishing').count()

    if previous_phishing == 0:
        trend_pct = 100.0 if current_phishing > 0 else 0.0
    else:
        trend_pct = ((current_phishing - previous_phishing) / previous_phishing) * 100.0

    if trend_pct > 1:
        direction = 'up'
    elif trend_pct < -1:
        direction = 'down'
    else:
        direction = 'flat'

    if direction == 'up':
        summary = f'Phishing attacks increased by {abs(round(trend_pct, 1))}% versus previous {days}-day window.'
    elif direction == 'down':
        summary = f'Phishing attacks decreased by {abs(round(trend_pct, 1))}% versus previous {days}-day window.'
    else:
        summary = f'Phishing attack volume is stable versus previous {days}-day window.'

    return {
        'current_phishing': current_phishing,
        'previous_phishing': previous_phishing,
        'phishing_trend_pct': round(trend_pct, 1),
        'direction': direction,
        'summary': summary,
    }



class DetectionPredictView(APIView):
    """
    Main endpoint for PhisGuard analysis. 
    Processes sender, subject, and body through Rule + ML engines.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        installation_id = _extract_installation_id(request)
        if not installation_id:
            return Response(
                {'error': 'installation_id (or device_id) is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = EmailCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid detection payload.', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = _run_detection(serializer)
        analysis = EmailAnalysis.objects.create(
            **_build_analysis_record_payload(request, serializer, result)
        )

        return Response(
            EmailAnalysisSerializer(analysis).data,
            status=status.HTTP_200_OK,
        )


class AnalysisHistoryView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = _history_queryset_for_request(request)
        try:
            page = max(1, int(request.query_params.get('page') or 1))
            page_size = max(1, min(int(request.query_params.get('page_size') or 50), 200))
        except (TypeError, ValueError):
            return Response({'error': 'page and page_size must be integers.'}, status=status.HTTP_400_BAD_REQUEST)

        total = queryset.count()
        offset = (page - 1) * page_size
        items = queryset[offset:offset + page_size]
        has_next = offset + page_size < total

        return Response(
            {
                'count': total,
                'page': page,
                'page_size': page_size,
                'has_next': has_next,
                'results': EmailAnalysisSerializer(items, many=True).data,
            }
        )


class AnalysisDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, analysis_id):
        try:
            analysis = EmailAnalysis.objects.get(id=analysis_id)
        except EmailAnalysis.DoesNotExist:
            return Response({'error': 'Analysis not found.'}, status=status.HTTP_404_NOT_FOUND)

        return Response(EmailAnalysisSerializer(analysis).data)


class DetectionStatsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = _history_queryset_for_request(request)

        total_analyzed = queryset.count()
        phishing_detected = queryset.filter(verdict='phishing').count()
        suspicious_emails = queryset.filter(verdict='suspicious').count()
        safe_emails = queryset.filter(verdict='safe').count()

        average_risk_score = round(queryset.aggregate(avg_risk=Avg('risk_score'))['avg_risk'] or 0)

        return Response(
            {
                'total_analyzed': total_analyzed,
                'phishing_detected': phishing_detected,
                'suspicious_emails': suspicious_emails,
                'safe_emails': safe_emails,
                'average_risk_score': average_risk_score,
            }
        )


class AdminUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _require_admin_login(request)
        if denied:
            return denied

        users = (
            _analytics_queryset().exclude(user_email='').values('user_email')
            .annotate(
                total_analyses=Count('id'),
                phishing_count=Count('id', filter=Q(verdict='phishing')),
                suspicious_count=Count('id', filter=Q(verdict='suspicious')),
                safe_count=Count('id', filter=Q(verdict='safe')),
                avg_risk=Avg('risk_score'),
                last_seen=Max('analyzed_at'),
            )
            .order_by('-last_seen')
        )

        payload = []
        for user in users:
            payload.append(
                {
                    'user_email': user['user_email'],
                    'total_analyses': user['total_analyses'] or 0,
                    'phishing_count': user['phishing_count'] or 0,
                    'suspicious_count': user['suspicious_count'] or 0,
                    'safe_count': user['safe_count'] or 0,
                    'avg_risk': round(float(user['avg_risk'] or 0), 2),
                    'last_seen': user['last_seen'],
                }
            )

        return Response(payload)


class AdminSessionView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        user = _session_user(request)
        if not user or not user.is_authenticated:
            return Response(
                {
                    'authenticated': False,
                    'is_admin': False,
                    'username': '',
                }
            )

        is_admin = bool(user.is_staff or user.is_superuser)
        return Response(
            {
                'authenticated': True,
                'is_admin': is_admin,
                'username': getattr(user, 'username', ''),
            }
        )


class AdminFlaggedCasesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _require_admin_login(request)
        if denied:
            return denied

        queryset = EmailAnalysis.objects.filter(verdict__in=['phishing', 'suspicious'])
        status_filter = (request.query_params.get('status') or '').strip().lower()
        if status_filter:
            queryset = queryset.filter(flagged_status=status_filter)
        return Response(EmailAnalysisSerializer(queryset[:200], many=True).data)


class AdminFlaggedCaseReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, analysis_id):
        denied = _require_admin_login(request)
        if denied:
            return denied

        try:
            analysis = EmailAnalysis.objects.get(id=analysis_id)
        except EmailAnalysis.DoesNotExist:
            return Response({'error': 'Analysis not found.'}, status=status.HTTP_404_NOT_FOUND)

        action = (request.data.get('action') or 'reviewed').strip().lower()
        reviewed_by = (request.data.get('reviewed_by') or 'analyst').strip()[:150]
        notes = (request.data.get('analyst_notes') or '').strip()

        if action != 'reviewed':
            return Response({'error': 'action must be: reviewed'}, status=status.HTTP_400_BAD_REQUEST)

        analysis.reviewed_by = reviewed_by
        analysis.analyst_notes = notes
        analysis.reviewed_at = timezone.now()
        analysis.flagged_status = 'reviewed'
        analysis.save(update_fields=['reviewed_by', 'analyst_notes', 'reviewed_at', 'flagged_status'])

        return Response(EmailAnalysisSerializer(analysis).data)


class AdminModelVersionListCreateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = ModelVersion.objects.all()
        return Response(ModelVersionSerializer(queryset, many=True).data)

    def post(self, request):
        denied = _require_admin_login(request)
        if denied:
            return denied

        serializer = ModelVersionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': 'Invalid model version payload.', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        instance = serializer.save()
        if instance.is_active:
            ModelVersion.objects.exclude(id=instance.id).update(is_active=False)
        return Response(ModelVersionSerializer(instance).data, status=status.HTTP_201_CREATED)


class AdminModelVersionActivateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, model_id):
        denied = _require_admin_login(request)
        if denied:
            return denied

        try:
            model_version = ModelVersion.objects.get(id=model_id)
        except ModelVersion.DoesNotExist:
            return Response({'error': 'Model version not found.'}, status=status.HTTP_404_NOT_FOUND)

        ModelVersion.objects.exclude(id=model_version.id).update(is_active=False)
        model_version.is_active = True
        model_version.save(update_fields=['is_active', 'updated_at'])
        return Response(ModelVersionSerializer(model_version).data)


class AdminRuleListCreateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = DetectionRule.objects.all()
        category = (request.query_params.get('category') or '').strip().lower()
        if category:
            queryset = queryset.filter(category__iexact=category)
        return Response(DetectionRuleSerializer(queryset, many=True).data)

    def post(self, request):
        denied = _require_admin_login(request)
        if denied:
            return denied

        serializer = DetectionRuleSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': 'Invalid rule payload.', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        instance = serializer.save()
        return Response(DetectionRuleSerializer(instance).data, status=status.HTTP_201_CREATED)


class AdminRuleDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, rule_id):
        denied = _require_admin_login(request)
        if denied:
            return denied

        try:
            rule = DetectionRule.objects.get(id=rule_id)
        except DetectionRule.DoesNotExist:
            return Response({'error': 'Rule not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DetectionRuleSerializer(rule, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response({'error': 'Invalid rule update.', 'details': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        return Response(serializer.data)


def _analytics_payload(request):
    base_queryset = _analytics_queryset()
    days = _parse_days(request)
    start_date = timezone.now() - timedelta(days=days - 1)
    period_queryset = base_queryset.filter(analyzed_at__gte=start_date)
    trend = _build_phishing_trend(base_queryset, start_date, days)

    total_users = base_queryset.exclude(user_email='').values('user_email').distinct().count()
    active_users = period_queryset.exclude(user_email='').values('user_email').distinct().count()
    inactive_users = max(total_users - active_users, 0)

    # Daily threats
    daily_rows = (
        period_queryset.annotate(day=TruncDate('analyzed_at'))
        .values('day')
        .annotate(
            total=Count('id'),
            phishing=Count('id', filter=Q(verdict='phishing')),
            suspicious=Count('id', filter=Q(verdict='suspicious')),
            safe=Count('id', filter=Q(verdict='safe')),
        )
        .order_by('day')
    )

    daily_threats = [
        {
            'day': item['day'].isoformat(),
            'total': item['total'],
            'phishing': item['phishing'],
            'suspicious': item['suspicious'],
            'safe': item['safe'],
        }
        for item in daily_rows
    ]

    # Category attacks
    category_counter = {}
    for analysis in period_queryset.only('indicators'):
        for ind in analysis.indicators or []:
            category = (ind.get('category') or 'other').lower()
            category_counter[category] = category_counter.get(category, 0) + 1

    category_attacks = [
        {'category': category, 'count': count}
        for category, count in sorted(category_counter.items(), key=lambda x: x[1], reverse=True)
    ]

    # User-wise risk analysis
    user_rows = (
        base_queryset.exclude(user_email='').values('user_email')
        .annotate(
            total_analyses=Count('id'),
            phishing_count=Count('id', filter=Q(verdict='phishing')),
            suspicious_count=Count('id', filter=Q(verdict='suspicious')),
            avg_risk=Avg('risk_score'),
        )
        .order_by('-avg_risk')[:10]
    )
    user_stats = [
        {
            'user_email': row['user_email'],
            'total_analyses': row['total_analyses'] or 0,
            'phishing_count': row['phishing_count'] or 0,
            'suspicious_count': row['suspicious_count'] or 0,
            'avg_risk': round(float(row['avg_risk'] or 0), 1),
            'risk_tier': 'high' if (row['avg_risk'] or 0) >= 60 else 'medium' if (row['avg_risk'] or 0) >= 30 else 'low',
        }
        for row in user_rows
    ]

    top_targeted_rows = (
        base_queryset.exclude(user_email='').values('user_email')
        .annotate(
            phishing_count=Count('id', filter=Q(verdict='phishing')),
            suspicious_count=Count('id', filter=Q(verdict='suspicious')),
            avg_risk=Avg('risk_score'),
        )
        .filter(phishing_count__gt=0)
        .order_by('-phishing_count', '-avg_risk')[:5]
    )

    top_targeted_users = [
        {
            'user_email': row['user_email'],
            'phishing_count': row['phishing_count'] or 0,
            'suspicious_count': row['suspicious_count'] or 0,
            'avg_risk': round(float(row['avg_risk'] or 0), 1),
        }
        for row in top_targeted_rows
    ]

    # Top keywords (threat patterns)
    keyword_counter = {}
    for analysis in period_queryset.only('indicators'):
        for ind in analysis.indicators or []:
            if ind.get('category') == 'keyword':
                keyword = (ind.get('value') or 'unknown').lower()[:50]
                keyword_counter[keyword] = keyword_counter.get(keyword, 0) + 1

    top_keywords = [
        {'keyword': kw, 'count': count}
        for kw, count in sorted(keyword_counter.items(), key=lambda x: x[1], reverse=True)[:15]
    ]

    # Suspicious domains (threat patterns)
    domain_counter = {}
    for analysis in period_queryset.only('urls_found'):
        for url in analysis.urls_found or []:
            try:
                from urllib.parse import urlparse

                domain = urlparse(url).netloc.lower()
                if domain:
                    domain_counter[domain] = domain_counter.get(domain, 0) + 1
            except Exception:
                pass

    suspicious_domains = [
        {'domain': domain, 'count': count}
        for domain, count in sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)[:15]
    ]

    return {
        'daily_threats': daily_threats,
        'category_attacks': category_attacks,
        'user_stats': user_stats,
        'user_overview': {
            'active_users': active_users,
            'inactive_users': inactive_users,
        },
        'top_targeted_users': top_targeted_users,
        'top_keywords': top_keywords,
        'suspicious_domains': suspicious_domains,
        'insights': trend,
        'summary': {
            'total_analyzed': base_queryset.count(),
            'total_users': total_users,
            'active_rules': DetectionRule.objects.filter(is_active=True).count(),
            'phishing_detected': base_queryset.filter(verdict='phishing').count(),
            'suspicious_emails': base_queryset.filter(verdict='suspicious').count(),
            'safe_emails': base_queryset.filter(verdict='safe').count(),
            'avg_risk_score': round(base_queryset.aggregate(avg_risk=Avg('risk_score'))['avg_risk'] or 0, 1),
        },
    }


class AdminAnalyticsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            payload = _analytics_payload(request)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(payload)


class AdminAlertsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        now = timezone.now()
        day_window = now - timedelta(hours=24)
        try:
            days = _parse_days(request, default=30)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        start_date = now - timedelta(days=days - 1)
        base_queryset = _analytics_queryset()
        trend = _build_phishing_trend(base_queryset, start_date, days)

        last_day_queryset = base_queryset.filter(analyzed_at__gte=day_window)
        high_risk_hits = last_day_queryset.filter(risk_score__gte=80).count()

        risky_users = (
            base_queryset.exclude(user_email='')
            .values('user_email')
            .annotate(avg_risk=Avg('risk_score'), total=Count('id'))
            .filter(avg_risk__gte=65, total__gte=5)
            .count()
        )

        alerts = []
        if high_risk_hits > 0:
            alerts.append(
                {
                    'type': 'high_risk_detection',
                    'severity': 'high',
                    'title': 'High-risk phishing detected',
                    'message': f'{high_risk_hits} emails scored >= 80 risk in the last 24 hours.',
                    'metric_value': high_risk_hits,
                    'generated_at': now,
                }
            )

        if risky_users > 0:
            alerts.append(
                {
                    'type': 'risky_user_behavior',
                    'severity': 'medium',
                    'title': 'Risky user behavior observed',
                    'message': f'{risky_users} users have persistent high average risk (>= 65).',
                    'metric_value': risky_users,
                    'generated_at': now,
                }
            )

        if trend['phishing_trend_pct'] >= 20:
            alerts.append(
                {
                    'type': 'phishing_trend_spike',
                    'severity': 'high',
                    'title': 'Phishing spike detected',
                    'message': trend['summary'],
                    'metric_value': trend['phishing_trend_pct'],
                    'generated_at': now,
                }
            )

        if not alerts:
            alerts.append(
                {
                    'type': 'system_status',
                    'severity': 'low',
                    'title': 'No active alerts',
                    'message': 'No high-risk or trend-based anomalies detected in the current window.',
                    'metric_value': 0,
                    'generated_at': now,
                }
            )

        return Response({'alerts': alerts})


class AdminLogsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            limit = _parse_limit(request)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        logs_queryset = EmailAnalysis.objects.order_by('-analyzed_at')[:limit]
        logs = [
            {
                'id': row.id,
                'installation_id': (row.installation_id or '')[:16],
                'sender_email': _mask_email(row.sender_email),
                'subject': row.subject,
                'verdict': row.verdict,
                'risk_score': row.risk_score,
                'analysis_mode': row.analysis_mode,
                'flagged_status': row.flagged_status,
                'analyzed_at': row.analyzed_at,
            }
            for row in logs_queryset
        ]

        last_24_hours = timezone.now() - timedelta(hours=24)
        recent_queryset = _analytics_queryset().filter(analyzed_at__gte=last_24_hours)
        performance = {
            'processed_last_24h': recent_queryset.count(),
            'avg_risk_last_24h': round(recent_queryset.aggregate(avg_risk=Avg('risk_score'))['avg_risk'] or 0, 1),
            'high_risk_last_24h': recent_queryset.filter(risk_score__gte=80).count(),
        }

        return Response({'logs': logs, 'performance': performance})


class AdminReportDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _require_admin_login(request)
        if denied:
            return denied

        try:
            days = _parse_days(request)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        start_date = timezone.now() - timedelta(days=days - 1)
        queryset = EmailAnalysis.objects.filter(analyzed_at__gte=start_date).order_by('-analyzed_at')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="admin_report_{days}d.csv"'

        writer = csv.writer(response)
        writer.writerow(
            [
                'analysis_id',
                'analyzed_at',
                'installation_id',
                'sender_email_masked',
                'subject',
                'verdict',
                'risk_score',
                'rule_score',
                'ml_confidence',
                'analysis_mode',
                'flagged_status',
            ]
        )

        for row in queryset.iterator():
            writer.writerow(
                [
                    row.id,
                    row.analyzed_at.isoformat() if row.analyzed_at else '',
                    row.installation_id,
                    _mask_email(row.sender_email),
                    row.subject,
                    row.verdict,
                    row.risk_score,
                    row.rule_score,
                    row.ml_confidence,
                    row.analysis_mode,
                    row.flagged_status,
                ]
            )

        return response


class AnalystFlaggedCasesView(AdminFlaggedCasesView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _require_analyst_login(request)
        if denied:
            return denied

        queryset = EmailAnalysis.objects.filter(verdict__in=['phishing', 'suspicious'])
        status_filter = (request.query_params.get('status') or '').strip().lower()
        if status_filter:
            queryset = queryset.filter(flagged_status=status_filter)
        return Response(EmailAnalysisSerializer(queryset[:200], many=True).data)


class AnalystFlaggedCaseReviewView(AdminFlaggedCaseReviewView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, analysis_id):
        denied = _require_analyst_login(request)
        if denied:
            return denied

        try:
            analysis = EmailAnalysis.objects.get(id=analysis_id)
        except EmailAnalysis.DoesNotExist:
            return Response({'error': 'Analysis not found.'}, status=status.HTTP_404_NOT_FOUND)

        action = (request.data.get('action') or 'reviewed').strip().lower()
        reviewed_by = (request.data.get('reviewed_by') or 'analyst').strip()[:150]
        notes = (request.data.get('analyst_notes') or '').strip()

        if action != 'reviewed':
            return Response({'error': 'action must be: reviewed'}, status=status.HTTP_400_BAD_REQUEST)

        analysis.reviewed_by = reviewed_by
        analysis.analyst_notes = notes
        analysis.reviewed_at = timezone.now()
        analysis.flagged_status = 'reviewed'
        analysis.save(update_fields=['reviewed_by', 'analyst_notes', 'reviewed_at', 'flagged_status'])

        return Response(EmailAnalysisSerializer(analysis).data)


class AnalystAnalyticsView(AdminAnalyticsView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _require_analyst_login(request)
        if denied:
            return denied
        try:
            payload = _analytics_payload(request)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(payload)
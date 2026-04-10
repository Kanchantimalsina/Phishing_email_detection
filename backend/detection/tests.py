from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from .models import EmailAnalysis


class AccessControlTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.admin_user = User.objects.create_user(
            username='admin_user',
            email='admin_user@example.com',
            password='StrongPass123!',
            is_staff=True,
        )
        self.regular_user = User.objects.create_user(
            username='regular_user',
            email='regular_user@example.com',
            password='StrongPass123!',
        )
        self.analyst_user = User.objects.create_user(
            username='analyst_user',
            email='analyst_user@example.com',
            password='StrongPass123!',
        )
        analyst_group, _ = Group.objects.get_or_create(name='analyst')
        self.analyst_user.groups.add(analyst_group)

        EmailAnalysis.objects.create(
            installation_id='inst-1',
            sender_email='suspicious@example.com',
            subject='Urgent Login Required',
            email_body='Please verify your account',
            source='manual',
            verdict='phishing',
            risk_score=88,
            rule_score=65,
            ml_confidence=92,
            analysis_mode='hybrid',
            indicators=[{'category': 'keyword', 'value': 'urgent'}],
            recommendations=['Do not click links'],
            urls_found=['https://bad.example.com'],
        )

    def test_admin_endpoint_rejects_header_role_spoof_for_anonymous(self):
        response = self.client.get(
            reverse('admin-users'),
            HTTP_X_PHISGUARD_ROLE='admin',
        )
        self.assertIn(response.status_code, [401, 403])

    def test_admin_endpoint_rejects_authenticated_non_admin(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(reverse('admin-users'))
        self.assertEqual(response.status_code, 403)

    def test_admin_endpoint_allows_staff(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(reverse('admin-users'))
        self.assertEqual(response.status_code, 200)

    def test_admin_analytics_rejects_invalid_days(self):
        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(reverse('admin-analytics'), {'days': 'abc'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('days', str(response.data).lower())

    def test_analyst_endpoint_requires_analyst_or_admin(self):
        self.client.force_authenticate(user=self.regular_user)
        denied = self.client.get(reverse('analyst-analytics'))
        self.assertEqual(denied.status_code, 403)

        self.client.force_authenticate(user=self.analyst_user)
        allowed = self.client.get(reverse('analyst-analytics'))
        self.assertEqual(allowed.status_code, 200)


class HistoryPaginationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        for idx in range(3):
            EmailAnalysis.objects.create(
                installation_id='inst-history',
                sender_email=f'sender{idx}@example.com',
                subject=f'Subject {idx}',
                email_body='Body',
                source='manual',
                verdict='safe',
                risk_score=10,
                rule_score=5,
                ml_confidence=20,
                analysis_mode='hybrid',
            )

    def test_history_returns_paginated_shape(self):
        response = self.client.get(reverse('detection-history'), {'page': 1, 'page_size': 2})
        self.assertEqual(response.status_code, 200)
        self.assertIn('results', response.data)
        self.assertEqual(response.data['count'], 3)
        self.assertEqual(len(response.data['results']), 2)


class EmailBasedAnalyticsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.admin_user = User.objects.create_user(
            username='admin_analytics',
            email='admin_analytics@example.com',
            password='StrongPass123!',
            is_staff=True,
        )

    @override_settings(
        PHISGUARD_ANALYTICS_EXCLUDED_EMAILS={'owner@company.com'},
        PHISGUARD_ANALYTICS_EXCLUDED_IPS={'127.0.0.1'},
    )
    def test_analytics_counts_unique_user_email_excluding_internal_traffic(self):
        EmailAnalysis.objects.create(
            installation_id='dev-1',
            user_email='customer@example.com',
            request_ip='10.10.10.10',
            sender_email='phish@example.com',
            verdict='safe',
            risk_score=10,
            rule_score=5,
            ml_confidence=25,
            analysis_mode='hybrid',
        )
        EmailAnalysis.objects.create(
            installation_id='dev-2',
            user_email='customer@example.com',
            request_ip='10.10.10.11',
            sender_email='phish2@example.com',
            verdict='phishing',
            risk_score=90,
            rule_score=70,
            ml_confidence=90,
            analysis_mode='hybrid',
        )
        EmailAnalysis.objects.create(
            installation_id='internal-1',
            user_email='owner@company.com',
            request_ip='10.0.0.5',
            sender_email='owner@company.com',
            verdict='safe',
            risk_score=1,
            rule_score=1,
            ml_confidence=1,
            analysis_mode='hybrid',
        )
        EmailAnalysis.objects.create(
            installation_id='internal-2',
            user_email='another@internal.com',
            request_ip='127.0.0.1',
            sender_email='another@internal.com',
            verdict='safe',
            risk_score=1,
            rule_score=1,
            ml_confidence=1,
            analysis_mode='hybrid',
        )

        self.client.force_authenticate(user=self.admin_user)
        response = self.client.get(reverse('admin-analytics'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['summary']['total_users'], 1)
        self.assertEqual(response.data['user_overview']['active_users'], 1)
        self.assertEqual(len(response.data['user_stats']), 1)
        self.assertEqual(response.data['user_stats'][0]['user_email'], 'customer@example.com')

from django.urls import path

from .views import AdminAnalyticsView
from .views import AdminAlertsView
from .views import AdminLogsView
from .views import AdminModelVersionActivateView
from .views import AdminModelVersionListCreateView
from .views import AdminReportDownloadView
from .views import AdminRuleDetailView
from .views import AdminRuleListCreateView
from .views import AdminSessionView
from .views import AdminUsersView
from .views import AnalystAnalyticsView
from .views import AnalystFlaggedCaseReviewView
from .views import AnalystFlaggedCasesView
from .views import AnalysisDetailView
from .views import AnalysisHistoryView
from .views import DetectionPredictView
from .views import DetectionStatsView


urlpatterns = [
    path('analyze/', DetectionPredictView.as_view(), name='detection-analyze'),
    path('predict/', DetectionPredictView.as_view(), name='detection-predict'),
    path('history/', AnalysisHistoryView.as_view(), name='detection-history'),
    path('history/<int:analysis_id>/', AnalysisDetailView.as_view(), name='detection-history-detail'),
    path('stats/', DetectionStatsView.as_view(), name='detection-stats'),

    # Admin endpoints
    path('admin/users/', AdminUsersView.as_view(), name='admin-users'),
    path('admin/session/', AdminSessionView.as_view(), name='admin-session'),
    path('admin/model-versions/', AdminModelVersionListCreateView.as_view(), name='admin-model-versions'),
    path('admin/model-versions/<int:model_id>/activate/', AdminModelVersionActivateView.as_view(), name='admin-model-version-activate'),
    path('admin/rules/', AdminRuleListCreateView.as_view(), name='admin-rules'),
    path('admin/rules/<int:rule_id>/', AdminRuleDetailView.as_view(), name='admin-rule-detail'),
    path('admin/analytics/', AdminAnalyticsView.as_view(), name='admin-analytics'),
    path('admin/alerts/', AdminAlertsView.as_view(), name='admin-alerts'),
    path('admin/logs/', AdminLogsView.as_view(), name='admin-logs'),
    path('admin/reports/download/', AdminReportDownloadView.as_view(), name='admin-report-download'),

    # Analyst endpoints
    path('analyst/flagged-cases/', AnalystFlaggedCasesView.as_view(), name='analyst-flagged-cases'),
    path('analyst/flagged-cases/<int:analysis_id>/review/', AnalystFlaggedCaseReviewView.as_view(), name='analyst-flagged-cases-review'),
    path('analyst/analytics/', AnalystAnalyticsView.as_view(), name='analyst-analytics'),
]

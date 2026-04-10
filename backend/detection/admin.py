from django.contrib import admin

from .models import DetectionRule
from .models import EmailAnalysis
from .models import ModelVersion


@admin.register(EmailAnalysis)
class EmailAnalysisAdmin(admin.ModelAdmin):
	list_display = ['id', 'installation_id', 'verdict', 'risk_score', 'flagged_status', 'analyzed_at']
	list_filter = ['verdict', 'flagged_status', 'analysis_mode', 'source']
	search_fields = ['installation_id', 'sender_email', 'subject']
	readonly_fields = ['analyzed_at', 'reviewed_at']


@admin.register(ModelVersion)
class ModelVersionAdmin(admin.ModelAdmin):
	list_display = ['id', 'name', 'version', 'is_active', 'created_at']
	list_filter = ['is_active', 'name']
	search_fields = ['name', 'version']


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
	list_display = ['id', 'name', 'category', 'severity', 'weight', 'is_active', 'updated_at']
	list_filter = ['category', 'severity', 'is_active']
	search_fields = ['name', 'pattern', 'description']

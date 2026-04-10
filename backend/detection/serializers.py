from rest_framework import serializers

from .models import EmailAnalysis
from .models import DetectionRule
from .models import ModelVersion


class EmailAnalysisSerializer(serializers.ModelSerializer):
    reasons = serializers.SerializerMethodField()

    def get_reasons(self, obj):
        return [item.get('description', '') for item in (obj.indicators or []) if item.get('description')]

    class Meta:
        model = EmailAnalysis
        fields = [
            'id',
            'installation_id',
            'user_email',
            'request_ip',
            'sender_email',
            'subject',
            'email_body',
            'source',
            'verdict',
            'risk_score',
            'rule_score',
            'ml_confidence',
            'analysis_mode',
            'indicators',
            'reasons',
            'recommendations',
            'urls_found',
            'flagged_status',
            'reviewed_by',
            'reviewed_at',
            'analyst_notes',
            'analyzed_at',
        ]


class ModelVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ModelVersion
        fields = [
            'id',
            'name',
            'version',
            'description',
            'metrics',
            'is_active',
            'created_at',
            'updated_at',
        ]


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = [
            'id',
            'name',
            'category',
            'severity',
            'pattern',
            'weight',
            'description',
            'is_active',
            'created_at',
            'updated_at',
        ]
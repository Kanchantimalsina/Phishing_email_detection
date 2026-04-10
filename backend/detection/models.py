from django.db import models


class EmailAnalysis(models.Model):
	installation_id = models.CharField(max_length=128, db_index=True)
	user_email = models.EmailField(blank=True, db_index=True)
	request_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
	sender_email = models.CharField(max_length=255, blank=True)
	subject = models.CharField(max_length=255, blank=True)
	email_body = models.TextField(blank=True)
	source = models.CharField(max_length=50, default='manual')

	verdict = models.CharField(max_length=20, default='safe')
	risk_score = models.FloatField(default=0)
	rule_score = models.FloatField(default=0)
	ml_confidence = models.FloatField(default=0)
	analysis_mode = models.CharField(max_length=20, default='hybrid')

	indicators = models.JSONField(default=list, blank=True)
	recommendations = models.JSONField(default=list, blank=True)
	urls_found = models.JSONField(default=list, blank=True)
	flagged_status = models.CharField(max_length=20, default='new')
	reviewed_by = models.CharField(max_length=150, blank=True)
	reviewed_at = models.DateTimeField(null=True, blank=True)
	analyst_notes = models.TextField(blank=True)

	analyzed_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-analyzed_at']

	def __str__(self):
		return f'{self.installation_id}:{self.verdict}:{self.risk_score}'


class ModelVersion(models.Model):
	name = models.CharField(max_length=100)
	version = models.CharField(max_length=50)
	description = models.TextField(blank=True)
	metrics = models.JSONField(default=dict, blank=True)
	is_active = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['-created_at']
		unique_together = ('name', 'version')

	def __str__(self):
		return f'{self.name}:{self.version}'


class DetectionRule(models.Model):
	name = models.CharField(max_length=120)
	category = models.CharField(max_length=50, db_index=True)
	severity = models.CharField(max_length=20, default='medium')
	pattern = models.CharField(max_length=255, blank=True)
	weight = models.FloatField(default=10)
	description = models.TextField(blank=True)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['category', '-updated_at']

	def __str__(self):
		return f'{self.category}:{self.name}'

from django.urls import path

from .views import DetectionHealthView, DetectionPredictView


urlpatterns = [
    path('health/', DetectionHealthView.as_view(), name='detection-health'),
    path('predict/', DetectionPredictView.as_view(), name='detection-predict'),
]

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .analyzer import EmailCheckSerializer
from .services import detect_email, detection_health


def _extract_detection_inputs(validated_data):
    """Normalize supported request keys for the detection engine."""
    email_text = validated_data.get('email_text', '')
    sender = validated_data.get('sender', '')
    subject = validated_data.get('subject', '')

    # Keep compatibility with existing serializer that provides email_text only.
    body = validated_data.get('body') or email_text
    return sender, subject, body


def _run_detection(serializer):
    sender, subject, body = _extract_detection_inputs(serializer.validated_data)
    return detect_email(sender=sender, subject=subject, body=body)

class DetectionPredictView(APIView):
    """
    Main endpoint for PhisGuard analysis. 
    Processes sender, subject, and body through Rule + ML engines.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid detection payload.', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = _run_detection(serializer)
        
        return Response({
            'status': 'success',
            'message': 'Analysis complete.', 
            'result': result
        }, status=status.HTTP_200_OK)


class CheckEmailView(APIView):
    """
    Alternative endpoint for legacy integrations. 
    Keeps the API clean without using 'class inheritance pass'.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid detection payload.', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = _run_detection(serializer)
        return Response(
            {
                'status': 'success',
                'message': 'Analysis complete.',
                'result': result,
            },
            status=status.HTTP_200_OK,
        )


class DetectionHealthView(APIView):
    """
    Checks if the ML model and Rule engines are initialized properly.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        payload, response_status = detection_health()
        return Response(payload, status=response_status)
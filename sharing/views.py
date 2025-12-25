"""
API Views - Thin layer that delegates to services
Views should only handle HTTP concerns (request/response) and delegate business logic to services
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import (
    FileUploadSerializer, FileResourceSerializer,
    ShareInitiateSerializer, ShareRequestSerializer,
    ShareApproveSerializer, ShareRejectSerializer, ShareRevokeSerializer,
    AuditLogSerializer, AuditLogFilterSerializer
)
from .services import FileService, ShareService, AuditLogService


def get_request_meta(request):
    """Extract request metadata for audit logging"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0]
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    
    return {
        'ip_address': ip_address,
        'user_agent': request.META.get('HTTP_USER_AGENT', '')
    }


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_file(request):
    """
    Upload a file (metadata only)
    POST /api/files/upload/
    """
    serializer = FileUploadSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'error': 'Validation failed', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Delegate to service layer
        file_resource = FileService.upload_file(
            file_name=serializer.validated_data['file_name'],
            owner=request.user,
            size=serializer.validated_data.get('size', 0),
            mime_type=serializer.validated_data.get('mime_type', 'application/octet-stream'),
            request_meta=get_request_meta(request)
        )
        
        # Serialize response
        response_serializer = FileResourceSerializer(file_resource)
        
        return Response(
            {
                'message': 'File uploaded successfully',
                'file': response_serializer.data
            },
            status=status.HTTP_201_CREATED
        )
    
    except Exception as e:
        return Response(
            {'error': 'File upload failed', 'details': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_files(request):
    """
    List all files owned by the current user
    GET /api/files/
    """
    files = FileService.get_user_files(request.user)
    serializer = FileResourceSerializer(files, many=True)
    
    return Response(
        {
            'count': len(serializer.data),
            'files': serializer.data
        },
        status=status.HTTP_200_OK
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_share(request):
    """
    Initiate a share request (forward or reverse)
    POST /api/share/initiate/
    """
    serializer = ShareInitiateSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'error': 'Validation failed', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Delegate to service layer
        share_request = ShareService.initiate_share(
            file_id=serializer.validated_data['file_id'],
            initiator=request.user,
            recipient_email=serializer.validated_data['recipient_email'],
            share_type=serializer.validated_data['share_type'],
            permission_level=serializer.validated_data.get('permission_level', 'view'),
            message=serializer.validated_data.get('message', ''),
            request_meta=get_request_meta(request)
        )
        
        # Serialize response
        response_serializer = ShareRequestSerializer(share_request)
        
        return Response(
            {
                'message': 'Share request initiated successfully',
                'share_request': response_serializer.data
            },
            status=status.HTTP_201_CREATED
        )
    
    except Exception as e:
        error_status = status.HTTP_400_BAD_REQUEST
        if 'not found' in str(e).lower():
            error_status = status.HTTP_404_NOT_FOUND
        elif 'permission' in str(e).lower() or 'only' in str(e).lower():
            error_status = status.HTTP_403_FORBIDDEN
        
        return Response(
            {'error': 'Share initiation failed', 'details': str(e)},
            status=error_status
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_share(request):
    """
    Approve a pending share request
    POST /api/share/approve/
    """
    serializer = ShareApproveSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'error': 'Validation failed', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Delegate to service layer
        share_request = ShareService.approve_share(
            share_request_id=serializer.validated_data['share_request_id'],
            approver=request.user,
            request_meta=get_request_meta(request)
        )
        
        # Serialize response
        response_serializer = ShareRequestSerializer(share_request)
        
        return Response(
            {
                'message': 'Share request approved successfully',
                'share_request': response_serializer.data
            },
            status=status.HTTP_200_OK
        )
    
    except Exception as e:
        error_status = status.HTTP_400_BAD_REQUEST
        if 'not found' in str(e).lower():
            error_status = status.HTTP_404_NOT_FOUND
        elif 'permission' in str(e).lower() or 'only' in str(e).lower():
            error_status = status.HTTP_403_FORBIDDEN
        
        return Response(
            {'error': 'Share approval failed', 'details': str(e)},
            status=error_status
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reject_share(request):
    """
    Reject a pending share request
    POST /api/share/reject/
    """
    serializer = ShareRejectSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'error': 'Validation failed', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Delegate to service layer
        share_request = ShareService.reject_share(
            share_request_id=serializer.validated_data['share_request_id'],
            rejecter=request.user,
            request_meta=get_request_meta(request)
        )
        
        # Serialize response
        response_serializer = ShareRequestSerializer(share_request)
        
        return Response(
            {
                'message': 'Share request rejected successfully',
                'share_request': response_serializer.data
            },
            status=status.HTTP_200_OK
        )
    
    except Exception as e:
        error_status = status.HTTP_400_BAD_REQUEST
        if 'not found' in str(e).lower():
            error_status = status.HTTP_404_NOT_FOUND
        elif 'permission' in str(e).lower() or 'only' in str(e).lower():
            error_status = status.HTTP_403_FORBIDDEN
        
        return Response(
            {'error': 'Share rejection failed', 'details': str(e)},
            status=error_status
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_share(request):
    """
    Revoke an approved share
    POST /api/share/revoke/
    """
    serializer = ShareRevokeSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {'error': 'Validation failed', 'details': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Delegate to service layer
        share_request = ShareService.revoke_share(
            share_request_id=serializer.validated_data['share_request_id'],
            revoker=request.user,
            request_meta=get_request_meta(request)
        )
        
        # Serialize response
        response_serializer = ShareRequestSerializer(share_request)
        
        return Response(
            {
                'message': 'Share revoked successfully',
                'share_request': response_serializer.data
            },
            status=status.HTTP_200_OK
        )
    
    except Exception as e:
        error_status = status.HTTP_400_BAD_REQUEST
        if 'not found' in str(e).lower():
            error_status = status.HTTP_404_NOT_FOUND
        elif 'permission' in str(e).lower() or 'only' in str(e).lower():
            error_status = status.HTTP_403_FORBIDDEN
        
        return Response(
            {'error': 'Share revocation failed', 'details': str(e)},
            status=error_status
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_share_requests(request):
    """
    List share requests (sent, received, or all)
    GET /api/share/requests/
    """
    filter_type = request.query_params.get('filter', 'all')
    
    if filter_type == 'sent':
        share_requests = ShareRequest.objects.filter(initiator=request.user)
    elif filter_type == 'received':
        share_requests = ShareRequest.objects.filter(recipient=request.user)
    else:
        # All requests where user is involved
        share_requests = ShareRequest.objects.filter(
            models.Q(initiator=request.user) | models.Q(recipient=request.user)
        )
    
    serializer = ShareRequestSerializer(share_requests, many=True)
    
    return Response(
        {
            'count': len(serializer.data),
            'filter': filter_type,
            'share_requests': serializer.data
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_audits(request):
    """
    Get audit logs with optional filters
    GET /api/audits/
    """
    filter_serializer = AuditLogFilterSerializer(data=request.query_params)
    
    if not filter_serializer.is_valid():
        return Response(
            {'error': 'Invalid filter parameters', 'details': filter_serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Build filters
    filters = {}
    if 'action' in filter_serializer.validated_data:
        filters['action'] = filter_serializer.validated_data['action']
    
    # Get audit logs via service
    audit_logs = AuditLogService.get_audit_logs(
        filters=filters,
        limit=filter_serializer.validated_data.get('limit', 100)
    )
    
    # Serialize response
    serializer = AuditLogSerializer(audit_logs, many=True)
    
    return Response(
        {
            'count': len(serializer.data),
            'filters': filters,
            'audit_logs': serializer.data
        },
        status=status.HTTP_200_OK
    )


# Import models for Q objects
from django.db import models

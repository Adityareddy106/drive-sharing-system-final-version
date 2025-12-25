"""
Serializers for API request/response validation
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import FileResource, ShareRequest, AuditLog


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']


class FileResourceSerializer(serializers.ModelSerializer):
    """
    Serializer for FileResource model
    """
    owner = UserSerializer(read_only=True)
    owner_email = serializers.EmailField(source='owner.email', read_only=True)
    
    class Meta:
        model = FileResource
        fields = [
            'id', 'file_id', 'file_name', 'owner', 'owner_email',
            'size', 'mime_type', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'file_id', 'created_at', 'updated_at']


class FileUploadSerializer(serializers.Serializer):
    """
    Serializer for file upload request
    """
    file_name = serializers.CharField(max_length=500, required=True)
    size = serializers.IntegerField(default=0, min_value=0, required=False)
    mime_type = serializers.CharField(
        max_length=100, 
        default='application/octet-stream',
        required=False
    )
    
    def validate_file_name(self, value):
        """Ensure file name is not empty"""
        if not value or not value.strip():
            raise serializers.ValidationError("File name cannot be empty")
        return value.strip()


class ShareRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for ShareRequest model
    """
    initiator = UserSerializer(read_only=True)
    recipient = UserSerializer(read_only=True)
    file = FileResourceSerializer(read_only=True)
    
    initiator_email = serializers.EmailField(source='initiator.email', read_only=True)
    recipient_email = serializers.EmailField(source='recipient.email', read_only=True)
    file_name = serializers.CharField(source='file.file_name', read_only=True)
    
    class Meta:
        model = ShareRequest
        fields = [
            'id', 'file', 'file_name', 'share_type', 'initiator', 'initiator_email',
            'recipient', 'recipient_email', 'permission_level', 'status',
            'message', 'requested_at', 'processed_at', 'processed_by'
        ]
        read_only_fields = [
            'id', 'requested_at', 'processed_at', 'processed_by'
        ]


class ShareInitiateSerializer(serializers.Serializer):
    """
    Serializer for initiating a share request
    """
    file_id = serializers.CharField(max_length=255, required=True)
    recipient_email = serializers.EmailField(required=True)
    share_type = serializers.ChoiceField(
        choices=['forward', 'reverse'],
        required=True
    )
    permission_level = serializers.ChoiceField(
        choices=['view', 'edit'],
        default='view',
        required=False
    )
    message = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True,
        default=''
    )
    
    def validate_file_id(self, value):
        """Ensure file_id is not empty"""
        if not value or not value.strip():
            raise serializers.ValidationError("File ID cannot be empty")
        return value.strip()
    
    def validate_recipient_email(self, value):
        """Ensure recipient_email is not empty and valid"""
        if not value or not value.strip():
            raise serializers.ValidationError("Recipient email cannot be empty")
        return value.strip().lower()


class ShareApproveSerializer(serializers.Serializer):
    """
    Serializer for approving a share request
    """
    share_request_id = serializers.IntegerField(required=True, min_value=1)


class ShareRejectSerializer(serializers.Serializer):
    """
    Serializer for rejecting a share request
    """
    share_request_id = serializers.IntegerField(required=True, min_value=1)


class ShareRevokeSerializer(serializers.Serializer):
    """
    Serializer for revoking a share
    """
    share_request_id = serializers.IntegerField(required=True, min_value=1)


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for AuditLog model
    """
    actor = UserSerializer(read_only=True)
    actor_email = serializers.EmailField(source='actor.email', read_only=True)
    file_name = serializers.CharField(source='file.file_name', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'action', 'actor', 'actor_email', 'file', 'file_name',
            'share_request', 'details', 'ip_address', 'user_agent', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class AuditLogFilterSerializer(serializers.Serializer):
    """
    Serializer for audit log filter parameters
    """
    action = serializers.ChoiceField(
        choices=[
            'upload', 'share_initiate', 'share_approve',
            'share_reject', 'share_revoke', 'permission_grant', 'permission_revoke'
        ],
        required=False
    )
    limit = serializers.IntegerField(default=100, min_value=1, max_value=1000, required=False)

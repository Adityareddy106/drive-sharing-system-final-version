"""
Business logic layer
All core business logic is centralized here, keeping views thin
"""
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError, PermissionDenied

from .models import FileResource, ShareRequest, AuditLog
from .adapters import drive_service


class FileService:
    """
    Service layer for file operations
    """
    
    @staticmethod
    @transaction.atomic
    def upload_file(file_name: str, owner: User, size: int = 0, 
                   mime_type: str = 'application/octet-stream', 
                   request_meta: dict = None) -> FileResource:
        """
        Upload a file (metadata only) and log the action
        
        Args:
            file_name: Name of the file
            owner: User who owns the file
            size: File size in bytes
            mime_type: MIME type
            request_meta: Request metadata for audit logging
        
        Returns:
            Created FileResource instance
        """
        # Simulate cloud upload via adapter
        upload_result = drive_service.upload_file(
            file_name=file_name,
            owner_email=owner.email,
            size=size,
            mime_type=mime_type
        )
        
        # Create file metadata in database
        file_resource = FileResource.objects.create(
            file_id=upload_result['file_id'],
            file_name=file_name,
            owner=owner,
            size=size,
            mime_type=mime_type
        )
        
        # Create audit log
        AuditLogService.log_action(
            action='upload',
            actor=owner,
            file=file_resource,
            details={
                'file_name': file_name,
                'file_id': upload_result['file_id'],
                'size': size,
                'mime_type': mime_type,
                'mock_response': upload_result
            },
            request_meta=request_meta
        )
        
        return file_resource
    
    @staticmethod
    def get_user_files(user: User) -> list:
        """
        Get all files owned by a user
        """
        return FileResource.objects.filter(owner=user)
    
    @staticmethod
    def get_file_by_id(file_id: str, user: User = None) -> FileResource:
        """
        Get file by ID with optional permission check
        """
        try:
            file_resource = FileResource.objects.get(file_id=file_id)
            
            # Optional: Check if user has access
            if user and file_resource.owner != user:
                # Check if user has approved share request
                has_access = ShareRequest.objects.filter(
                    file=file_resource,
                    recipient=user,
                    status='approved'
                ).exists()
                
                if not has_access:
                    raise PermissionDenied("You don't have access to this file")
            
            return file_resource
        except FileResource.DoesNotExist:
            raise ValidationError(f"File with ID {file_id} not found")


class ShareService:
    """
    Service layer for sharing workflow operations
    """
    
    @staticmethod
    @transaction.atomic
    def initiate_share(file_id: str, initiator: User, recipient_email: str,
                      share_type: str, permission_level: str = 'view',
                      message: str = '', request_meta: dict = None) -> ShareRequest:
        """
        Initiate a share request (forward or reverse)
        
        Args:
            file_id: ID of the file to share
            initiator: User initiating the share
            recipient_email: Email of the recipient
            share_type: 'forward' or 'reverse'
            permission_level: 'view' or 'edit'
            message: Optional message
            request_meta: Request metadata for audit logging
        
        Returns:
            Created ShareRequest instance
        """
        # Validate share type
        if share_type not in ['forward', 'reverse']:
            raise ValidationError("share_type must be 'forward' or 'reverse'")
        
        # Validate permission level
        if permission_level not in ['view', 'edit']:
            raise ValidationError("permission_level must be 'view' or 'edit'")
        
        # Get file
        try:
            file_resource = FileResource.objects.get(file_id=file_id)
        except FileResource.DoesNotExist:
            raise ValidationError(f"File with ID {file_id} not found")
        
        # Get recipient user
        try:
            recipient = User.objects.get(email=recipient_email)
        except User.DoesNotExist:
            raise ValidationError(f"User with email {recipient_email} not found")
        
        # Validate share type logic
        if share_type == 'forward':
            # Forward: Owner shares with another user
            if file_resource.owner != initiator:
                raise PermissionDenied("Only the file owner can initiate forward sharing")
        else:  # reverse
            # Reverse: User requests access from owner
            if file_resource.owner == initiator:
                raise ValidationError("File owner cannot request access to their own file")
            if recipient != file_resource.owner:
                raise ValidationError("In reverse sharing, recipient must be the file owner")
        
        # Check for existing active share
        existing_share = ShareRequest.objects.filter(
            file=file_resource,
            recipient=recipient,
            status__in=['pending', 'approved']
        ).first()
        
        if existing_share:
            raise ValidationError(
                f"An active share request already exists with status: {existing_share.status}"
            )
        
        # Create share request
        share_request = ShareRequest.objects.create(
            file=file_resource,
            share_type=share_type,
            initiator=initiator,
            recipient=recipient,
            permission_level=permission_level,
            message=message,
            status='pending'
        )
        
        # Create audit log
        AuditLogService.log_action(
            action='share_initiate',
            actor=initiator,
            file=file_resource,
            share_request=share_request,
            details={
                'share_type': share_type,
                'recipient_email': recipient_email,
                'permission_level': permission_level,
                'message': message
            },
            request_meta=request_meta
        )
        
        return share_request
    
    @staticmethod
    @transaction.atomic
    def approve_share(share_request_id: int, approver: User, 
                     request_meta: dict = None) -> ShareRequest:
        """
        Approve a pending share request
        
        Args:
            share_request_id: ID of the share request
            approver: User approving the request
            request_meta: Request metadata for audit logging
        
        Returns:
            Updated ShareRequest instance
        """
        # Get share request
        try:
            share_request = ShareRequest.objects.get(id=share_request_id)
        except ShareRequest.DoesNotExist:
            raise ValidationError(f"Share request with ID {share_request_id} not found")
        
        # Validate status
        if share_request.status != 'pending':
            raise ValidationError(
                f"Cannot approve share request with status: {share_request.status}"
            )
        
        # Validate approver based on share type
        if share_request.share_type == 'forward':
            # Forward: Recipient approves
            if share_request.recipient != approver:
                raise PermissionDenied("Only the recipient can approve a forward share")
        else:  # reverse
            # Reverse: Owner approves
            if share_request.file.owner != approver:
                raise PermissionDenied("Only the file owner can approve a reverse share request")
        
        # Update share request status
        share_request.status = 'approved'
        share_request.processed_at = timezone.now()
        share_request.processed_by = approver
        share_request.save()
        
        # Grant permission via mock drive service
        permission_result = drive_service.grant_permission(
            file_id=share_request.file.file_id,
            user_email=share_request.recipient.email,
            permission_level=share_request.permission_level
        )
        
        # Create audit logs
        AuditLogService.log_action(
            action='share_approve',
            actor=approver,
            file=share_request.file,
            share_request=share_request,
            details={
                'share_type': share_request.share_type,
                'recipient_email': share_request.recipient.email,
                'permission_level': share_request.permission_level
            },
            request_meta=request_meta
        )
        
        AuditLogService.log_action(
            action='permission_grant',
            actor=approver,
            file=share_request.file,
            share_request=share_request,
            details={
                'mock_response': permission_result,
                'recipient_email': share_request.recipient.email,
                'permission_level': share_request.permission_level
            },
            request_meta=request_meta
        )
        
        return share_request
    
    @staticmethod
    @transaction.atomic
    def reject_share(share_request_id: int, rejecter: User, 
                    request_meta: dict = None) -> ShareRequest:
        """
        Reject a pending share request
        
        Args:
            share_request_id: ID of the share request
            rejecter: User rejecting the request
            request_meta: Request metadata for audit logging
        
        Returns:
            Updated ShareRequest instance
        """
        # Get share request
        try:
            share_request = ShareRequest.objects.get(id=share_request_id)
        except ShareRequest.DoesNotExist:
            raise ValidationError(f"Share request with ID {share_request_id} not found")
        
        # Validate status
        if share_request.status != 'pending':
            raise ValidationError(
                f"Cannot reject share request with status: {share_request.status}"
            )
        
        # Validate rejecter based on share type
        if share_request.share_type == 'forward':
            # Forward: Recipient rejects
            if share_request.recipient != rejecter:
                raise PermissionDenied("Only the recipient can reject a forward share")
        else:  # reverse
            # Reverse: Owner rejects
            if share_request.file.owner != rejecter:
                raise PermissionDenied("Only the file owner can reject a reverse share request")
        
        # Update share request status
        share_request.status = 'rejected'
        share_request.processed_at = timezone.now()
        share_request.processed_by = rejecter
        share_request.save()
        
        # Create audit log
        AuditLogService.log_action(
            action='share_reject',
            actor=rejecter,
            file=share_request.file,
            share_request=share_request,
            details={
                'share_type': share_request.share_type,
                'recipient_email': share_request.recipient.email
            },
            request_meta=request_meta
        )
        
        return share_request
    
    @staticmethod
    @transaction.atomic
    def revoke_share(share_request_id: int, revoker: User, 
                    request_meta: dict = None) -> ShareRequest:
        """
        Revoke an approved share
        
        Args:
            share_request_id: ID of the share request
            revoker: User revoking the share
            request_meta: Request metadata for audit logging
        
        Returns:
            Updated ShareRequest instance
        """
        # Get share request
        try:
            share_request = ShareRequest.objects.get(id=share_request_id)
        except ShareRequest.DoesNotExist:
            raise ValidationError(f"Share request with ID {share_request_id} not found")
        
        # Validate status
        if share_request.status != 'approved':
            raise ValidationError(
                f"Cannot revoke share request with status: {share_request.status}. "
                "Only approved shares can be revoked."
            )
        
        # Only file owner can revoke
        if share_request.file.owner != revoker:
            raise PermissionDenied("Only the file owner can revoke access")
        
        # Update share request status
        share_request.status = 'revoked'
        share_request.processed_at = timezone.now()
        share_request.processed_by = revoker
        share_request.save()
        
        # Revoke permission via mock drive service
        revoke_result = drive_service.revoke_permission(
            file_id=share_request.file.file_id,
            user_email=share_request.recipient.email
        )
        
        # Create audit logs
        AuditLogService.log_action(
            action='share_revoke',
            actor=revoker,
            file=share_request.file,
            share_request=share_request,
            details={
                'recipient_email': share_request.recipient.email,
                'permission_level': share_request.permission_level
            },
            request_meta=request_meta
        )
        
        AuditLogService.log_action(
            action='permission_revoke',
            actor=revoker,
            file=share_request.file,
            share_request=share_request,
            details={
                'mock_response': revoke_result,
                'recipient_email': share_request.recipient.email
            },
            request_meta=request_meta
        )
        
        return share_request
    
    @staticmethod
    def get_pending_shares_for_user(user: User) -> list:
        """
        Get pending shares that require user's action
        """
        # Shares where user is recipient (forward) or owner (reverse)
        return ShareRequest.objects.filter(
            status='pending'
        ).filter(
            models.Q(recipient=user, share_type='forward') |
            models.Q(file__owner=user, share_type='reverse')
        )


class AuditLogService:
    """
    Service layer for audit logging
    """
    
    @staticmethod
    def log_action(action: str, actor: User, file: FileResource = None,
                  share_request: ShareRequest = None, details: dict = None,
                  request_meta: dict = None) -> AuditLog:
        """
        Create an audit log entry
        
        Args:
            action: Type of action
            actor: User performing the action
            file: Related file (optional)
            share_request: Related share request (optional)
            details: Additional details as JSON
            request_meta: Request metadata (IP, user agent)
        
        Returns:
            Created AuditLog instance
        """
        ip_address = None
        user_agent = ''
        
        if request_meta:
            ip_address = request_meta.get('ip_address')
            user_agent = request_meta.get('user_agent', '')
        
        audit_log = AuditLog.objects.create(
            action=action,
            actor=actor,
            file=file,
            share_request=share_request,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return audit_log
    
    @staticmethod
    def get_audit_logs(filters: dict = None, limit: int = 100):
        """
        Get audit logs with optional filters
        
        Args:
            filters: Dict of filters (action, actor, file, etc.)
            limit: Maximum number of logs to return
        
        Returns:
            QuerySet of AuditLog instances
        """
        queryset = AuditLog.objects.all()
        
        if filters:
            if 'action' in filters:
                queryset = queryset.filter(action=filters['action'])
            if 'actor' in filters:
                queryset = queryset.filter(actor=filters['actor'])
            if 'file' in filters:
                queryset = queryset.filter(file=filters['file'])
        
        return queryset[:limit]

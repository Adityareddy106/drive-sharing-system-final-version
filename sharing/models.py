from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class FileResource(models.Model):
    """
    Represents a file in the system (metadata only, no actual file storage)
    """
    file_id = models.CharField(max_length=255, unique=True, db_index=True)
    file_name = models.CharField(max_length=500)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_files')
    size = models.BigIntegerField(default=0, help_text="File size in bytes")
    mime_type = models.CharField(max_length=100, default='application/octet-stream')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'file_resources'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', '-created_at']),
            models.Index(fields=['file_id']),
        ]
    
    def __str__(self):
        return f"{self.file_name} (Owner: {self.owner.username})"


class ShareRequest(models.Model):
    """
    Represents a sharing request/permission for a file
    Supports both forward (owner shares) and reverse (user requests access) flows
    """
    
    SHARE_TYPE_CHOICES = [
        ('forward', 'Forward Share'),  # Owner shares with user
        ('reverse', 'Reverse Share'),  # User requests access from owner
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('revoked', 'Revoked'),
    ]
    
    PERMISSION_CHOICES = [
        ('view', 'View'),
        ('edit', 'Edit'),
    ]
    
    file = models.ForeignKey(FileResource, on_delete=models.CASCADE, related_name='share_requests')
    share_type = models.CharField(max_length=10, choices=SHARE_TYPE_CHOICES)
    initiator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='initiated_shares')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_shares')
    permission_level = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='view')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    
    # Metadata
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                      related_name='processed_shares')
    
    # Optional message/reason
    message = models.TextField(blank=True, default='')
    
    class Meta:
        db_table = 'share_requests'
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['file', 'status']),
            models.Index(fields=['recipient', 'status']),
            models.Index(fields=['status', '-requested_at']),
        ]
        unique_together = [['file', 'recipient', 'status']]  # Prevent duplicate active shares
    
    def __str__(self):
        return f"{self.share_type}: {self.file.file_name} -> {self.recipient.username} ({self.status})"
    
    def save(self, *args, **kwargs):
        # Auto-set processed_at when status changes from pending
        if self.pk:
            old_instance = ShareRequest.objects.get(pk=self.pk)
            if old_instance.status == 'pending' and self.status != 'pending':
                self.processed_at = timezone.now()
        super().save(*args, **kwargs)


class AuditLog(models.Model):
    """
    Comprehensive audit trail for all system actions
    """
    
    ACTION_CHOICES = [
        ('upload', 'File Upload'),
        ('share_initiate', 'Share Initiated'),
        ('share_approve', 'Share Approved'),
        ('share_reject', 'Share Rejected'),
        ('share_revoke', 'Share Revoked'),
        ('permission_grant', 'Permission Granted (Mock Drive)'),
        ('permission_revoke', 'Permission Revoked (Mock Drive)'),
    ]
    
    action = models.CharField(max_length=30, choices=ACTION_CHOICES, db_index=True)
    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    file = models.ForeignKey(FileResource, on_delete=models.SET_NULL, null=True, blank=True)
    share_request = models.ForeignKey(ShareRequest, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Detailed information
    details = models.JSONField(default=dict, help_text="Additional action details")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True, default='')
    
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['actor', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        actor_name = self.actor.username if self.actor else 'System'
        return f"{self.action} by {actor_name} at {self.timestamp}"

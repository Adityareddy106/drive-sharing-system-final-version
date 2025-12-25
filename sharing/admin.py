from django.contrib import admin
from .models import FileResource, ShareRequest, AuditLog


@admin.register(FileResource)
class FileResourceAdmin(admin.ModelAdmin):
    """
    Admin interface for FileResource model
    """
    list_display = ['file_id', 'file_name', 'owner', 'size', 'mime_type', 'created_at']
    list_filter = ['mime_type', 'created_at', 'owner']
    search_fields = ['file_name', 'file_id', 'owner__username', 'owner__email']
    readonly_fields = ['file_id', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('File Information', {
            'fields': ('file_id', 'file_name', 'size', 'mime_type')
        }),
        ('Ownership', {
            'fields': ('owner',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ShareRequest)
class ShareRequestAdmin(admin.ModelAdmin):
    """
    Admin interface for ShareRequest model
    """
    list_display = ['id', 'file', 'share_type', 'initiator', 'recipient', 
                   'permission_level', 'status', 'requested_at']
    list_filter = ['share_type', 'status', 'permission_level', 'requested_at']
    search_fields = ['file__file_name', 'initiator__username', 'recipient__username', 
                    'initiator__email', 'recipient__email']
    readonly_fields = ['requested_at', 'processed_at']
    date_hierarchy = 'requested_at'
    
    fieldsets = (
        ('Share Details', {
            'fields': ('file', 'share_type', 'permission_level', 'status')
        }),
        ('Participants', {
            'fields': ('initiator', 'recipient')
        }),
        ('Processing', {
            'fields': ('processed_by', 'processed_at')
        }),
        ('Additional Info', {
            'fields': ('message', 'requested_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """
    Admin interface for AuditLog model
    """
    list_display = ['id', 'action', 'actor', 'file', 'ip_address', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['actor__username', 'actor__email', 'file__file_name', 'ip_address']
    readonly_fields = ['action', 'actor', 'file', 'share_request', 'details', 
                      'ip_address', 'user_agent', 'timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Action Details', {
            'fields': ('action', 'actor', 'timestamp')
        }),
        ('Related Objects', {
            'fields': ('file', 'share_request')
        }),
        ('Request Info', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
        ('Additional Details', {
            'fields': ('details',),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        # Prevent manual creation of audit logs through admin
        return False
    
    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of audit logs
        return False

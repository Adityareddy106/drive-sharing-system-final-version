"""
Adapters for external services
This module contains adapters that abstract external dependencies
"""
import uuid
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class MockDriveService:
    """
    Mock adapter to simulate Google Drive or similar cloud storage behavior
    In production, this would be replaced with actual API calls to Google Drive
    """
    
    def __init__(self):
        # Simulate in-memory storage of permissions
        self.permissions = {}  # {file_id: {user_email: permission_level}}
        self.uploaded_files = {}  # {file_id: file_metadata}
    
    def upload_file(self, file_name: str, owner_email: str, size: int = 0, 
                    mime_type: str = 'application/octet-stream') -> Dict[str, any]:
        """
        Simulate file upload to cloud storage
        
        Args:
            file_name: Name of the file
            owner_email: Email of the file owner
            size: File size in bytes
            mime_type: MIME type of the file
        
        Returns:
            Dict containing file_id and upload status
        """
        file_id = str(uuid.uuid4())
        
        # Simulate file storage
        self.uploaded_files[file_id] = {
            'file_id': file_id,
            'file_name': file_name,
            'owner_email': owner_email,
            'size': size,
            'mime_type': mime_type,
            'upload_status': 'success'
        }
        
        # Initialize permissions for owner
        self.permissions[file_id] = {
            owner_email: 'owner'
        }
        
        logger.info(f"Mock upload: {file_name} (ID: {file_id}) by {owner_email}")
        
        return {
            'file_id': file_id,
            'status': 'success',
            'message': f'File {file_name} uploaded successfully',
            'size': size,
            'mime_type': mime_type
        }
    
    def grant_permission(self, file_id: str, user_email: str, 
                        permission_level: str = 'view') -> Dict[str, any]:
        """
        Simulate granting permission to a user for a file
        
        Args:
            file_id: Unique identifier of the file
            user_email: Email of the user to grant permission
            permission_level: Level of permission ('view' or 'edit')
        
        Returns:
            Dict containing permission grant status
        """
        if file_id not in self.uploaded_files:
            logger.warning(f"Mock grant permission failed: File {file_id} not found")
            return {
                'status': 'error',
                'message': f'File {file_id} not found in mock storage',
                'file_id': file_id
            }
        
        # Initialize permissions dict for file if not exists
        if file_id not in self.permissions:
            self.permissions[file_id] = {}
        
        # Grant permission
        self.permissions[file_id][user_email] = permission_level
        
        logger.info(f"Mock grant permission: {user_email} -> {permission_level} on file {file_id}")
        
        return {
            'status': 'success',
            'message': f'Permission granted to {user_email}',
            'file_id': file_id,
            'user_email': user_email,
            'permission_level': permission_level,
            'permission_id': f'perm_{uuid.uuid4().hex[:12]}'
        }
    
    def revoke_permission(self, file_id: str, user_email: str) -> Dict[str, any]:
        """
        Simulate revoking permission from a user for a file
        
        Args:
            file_id: Unique identifier of the file
            user_email: Email of the user to revoke permission
        
        Returns:
            Dict containing permission revocation status
        """
        if file_id not in self.uploaded_files:
            logger.warning(f"Mock revoke permission failed: File {file_id} not found")
            return {
                'status': 'error',
                'message': f'File {file_id} not found in mock storage',
                'file_id': file_id
            }
        
        if file_id not in self.permissions or user_email not in self.permissions[file_id]:
            logger.warning(f"Mock revoke permission: No permission exists for {user_email} on {file_id}")
            return {
                'status': 'warning',
                'message': f'No permission found for {user_email}',
                'file_id': file_id,
                'user_email': user_email
            }
        
        # Revoke permission
        del self.permissions[file_id][user_email]
        
        logger.info(f"Mock revoke permission: {user_email} from file {file_id}")
        
        return {
            'status': 'success',
            'message': f'Permission revoked from {user_email}',
            'file_id': file_id,
            'user_email': user_email
        }
    
    def get_file_permissions(self, file_id: str) -> Dict[str, any]:
        """
        Get all permissions for a file
        
        Args:
            file_id: Unique identifier of the file
        
        Returns:
            Dict containing file permissions
        """
        if file_id not in self.uploaded_files:
            return {
                'status': 'error',
                'message': f'File {file_id} not found',
                'permissions': {}
            }
        
        return {
            'status': 'success',
            'file_id': file_id,
            'permissions': self.permissions.get(file_id, {})
        }
    
    def check_permission(self, file_id: str, user_email: str) -> Optional[str]:
        """
        Check if a user has permission for a file
        
        Args:
            file_id: Unique identifier of the file
            user_email: Email of the user
        
        Returns:
            Permission level if exists, None otherwise
        """
        if file_id in self.permissions:
            return self.permissions[file_id].get(user_email)
        return None


# Singleton instance for the application
drive_service = MockDriveService()

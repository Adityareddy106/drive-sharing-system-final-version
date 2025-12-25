"""
Test suite for the sharing app
"""
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from .models import FileResource, ShareRequest, AuditLog
from .services import FileService, ShareService, AuditLogService
from .adapters import drive_service


class FileResourceModelTest(TestCase):
    """Test cases for FileResource model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_create_file_resource(self):
        """Test creating a file resource"""
        file = FileResource.objects.create(
            file_id='test-file-123',
            file_name='test.pdf',
            owner=self.user,
            size=1024,
            mime_type='application/pdf'
        )
        
        self.assertEqual(file.file_name, 'test.pdf')
        self.assertEqual(file.owner, self.user)
        self.assertEqual(file.size, 1024)
        self.assertIsNotNone(file.created_at)


class ShareRequestModelTest(TestCase):
    """Test cases for ShareRequest model"""
    
    def setUp(self):
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='testpass123'
        )
        self.recipient = User.objects.create_user(
            username='recipient',
            email='recipient@example.com',
            password='testpass123'
        )
        self.file = FileResource.objects.create(
            file_id='test-file-123',
            file_name='test.pdf',
            owner=self.owner
        )
    
    def test_create_forward_share(self):
        """Test creating a forward share request"""
        share = ShareRequest.objects.create(
            file=self.file,
            share_type='forward',
            initiator=self.owner,
            recipient=self.recipient,
            permission_level='view',
            status='pending'
        )
        
        self.assertEqual(share.share_type, 'forward')
        self.assertEqual(share.status, 'pending')
        self.assertEqual(share.initiator, self.owner)


class FileServiceTest(TestCase):
    """Test cases for FileService"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_upload_file(self):
        """Test file upload through service"""
        file_resource = FileService.upload_file(
            file_name='document.docx',
            owner=self.user,
            size=2048,
            mime_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        
        self.assertIsNotNone(file_resource.file_id)
        self.assertEqual(file_resource.file_name, 'document.docx')
        self.assertEqual(file_resource.owner, self.user)
        
        # Check audit log created
        audit_count = AuditLog.objects.filter(
            action='upload',
            actor=self.user,
            file=file_resource
        ).count()
        self.assertEqual(audit_count, 1)


class ShareServiceTest(TestCase):
    """Test cases for ShareService"""
    
    def setUp(self):
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='testpass123'
        )
        self.recipient = User.objects.create_user(
            username='recipient',
            email='recipient@example.com',
            password='testpass123'
        )
        self.file = FileResource.objects.create(
            file_id='test-file-123',
            file_name='test.pdf',
            owner=self.owner
        )
    
    def test_forward_share_initiation(self):
        """Test initiating a forward share"""
        share_request = ShareService.initiate_share(
            file_id=self.file.file_id,
            initiator=self.owner,
            recipient_email=self.recipient.email,
            share_type='forward',
            permission_level='view'
        )
        
        self.assertEqual(share_request.share_type, 'forward')
        self.assertEqual(share_request.status, 'pending')
        self.assertEqual(share_request.initiator, self.owner)
        self.assertEqual(share_request.recipient, self.recipient)
    
    def test_approve_forward_share(self):
        """Test approving a forward share"""
        # Create pending share
        share_request = ShareService.initiate_share(
            file_id=self.file.file_id,
            initiator=self.owner,
            recipient_email=self.recipient.email,
            share_type='forward'
        )
        
        # Approve as recipient
        approved_share = ShareService.approve_share(
            share_request_id=share_request.id,
            approver=self.recipient
        )
        
        self.assertEqual(approved_share.status, 'approved')
        self.assertIsNotNone(approved_share.processed_at)
        self.assertEqual(approved_share.processed_by, self.recipient)
    
    def test_revoke_share(self):
        """Test revoking an approved share"""
        # Create and approve share
        share_request = ShareService.initiate_share(
            file_id=self.file.file_id,
            initiator=self.owner,
            recipient_email=self.recipient.email,
            share_type='forward'
        )
        ShareService.approve_share(
            share_request_id=share_request.id,
            approver=self.recipient
        )
        
        # Revoke as owner
        revoked_share = ShareService.revoke_share(
            share_request_id=share_request.id,
            revoker=self.owner
        )
        
        self.assertEqual(revoked_share.status, 'revoked')


class APIEndpointTest(APITestCase):
    """Test cases for API endpoints"""
    
    def setUp(self):
        self.client = APIClient()
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )
    
    def test_upload_file_api(self):
        """Test file upload API endpoint"""
        self.client.force_authenticate(user=self.user1)
        
        response = self.client.post('/api/files/upload/', {
            'file_name': 'report.pdf',
            'size': 5120,
            'mime_type': 'application/pdf'
        })
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('file', response.data)
        self.assertEqual(response.data['file']['file_name'], 'report.pdf')
    
    def test_initiate_share_api(self):
        """Test share initiation API endpoint"""
        self.client.force_authenticate(user=self.user1)
        
        # First upload a file
        upload_response = self.client.post('/api/files/upload/', {
            'file_name': 'shared_doc.pdf'
        })
        file_id = upload_response.data['file']['file_id']
        
        # Initiate share
        response = self.client.post('/api/share/initiate/', {
            'file_id': file_id,
            'recipient_email': self.user2.email,
            'share_type': 'forward',
            'permission_level': 'view'
        })
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('share_request', response.data)
        self.assertEqual(response.data['share_request']['status'], 'pending')
    
    def test_approve_share_api(self):
        """Test share approval API endpoint"""
        # User1 uploads and shares with user2
        self.client.force_authenticate(user=self.user1)
        upload_response = self.client.post('/api/files/upload/', {
            'file_name': 'document.pdf'
        })
        file_id = upload_response.data['file']['file_id']
        
        share_response = self.client.post('/api/share/initiate/', {
            'file_id': file_id,
            'recipient_email': self.user2.email,
            'share_type': 'forward'
        })
        share_request_id = share_response.data['share_request']['id']
        
        # User2 approves
        self.client.force_authenticate(user=self.user2)
        approve_response = self.client.post('/api/share/approve/', {
            'share_request_id': share_request_id
        })
        
        self.assertEqual(approve_response.status_code, status.HTTP_200_OK)
        self.assertEqual(approve_response.data['share_request']['status'], 'approved')
    
    def test_list_audits_api(self):
        """Test audit log listing API endpoint"""
        self.client.force_authenticate(user=self.user1)
        
        # Perform some actions
        self.client.post('/api/files/upload/', {'file_name': 'test.pdf'})
        
        # Get audit logs
        response = self.client.get('/api/audits/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('audit_logs', response.data)
        self.assertGreater(response.data['count'], 0)
    
    def test_unauthorized_access(self):
        """Test that unauthenticated requests are rejected"""
        response = self.client.post('/api/files/upload/', {
            'file_name': 'test.pdf'
        })
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

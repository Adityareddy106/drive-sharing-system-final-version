# Drive Sharing System (Mock)

A Django REST Framework backend system that simulates file-sharing and permission approval workflows, similar to Google Drive.

## 🎯 Project Overview

This system implements a complete file-sharing workflow with:
- **File Upload**: Mock file uploads (metadata only)
- **Share Initiation**: Forward (owner shares) and reverse (user requests) sharing
- **Approval Workflow**: Approve/reject share requests
- **Access Revocation**: Revoke approved permissions
- **Comprehensive Audit Logging**: Track all system actions

## 🏗️ Architecture

The project follows **clean architecture principles** with clear separation of concerns:

```
sharing/
├── models.py       # Data models (FileResource, ShareRequest, AuditLog)
├── serializers.py  # Request/response validation
├── views.py        # Thin views (HTTP layer only)
├── services.py     # Business logic layer
├── adapters.py     # External service adapters (MockDriveService)
├── urls.py         # URL routing
└── admin.py        # Django admin configuration
```

### Design Principles

1. **Thin Views**: Views only handle HTTP concerns and delegate to services
2. **Service Layer**: All business logic is centralized in services
3. **Adapter Pattern**: External dependencies abstracted through adapters
4. **Comprehensive Audit**: Every action is logged for traceability

## 🚀 Setup Instructions

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd drive_sharing_system
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**
   ```bash
   python manage.py migrate
   ```

5. **Create a superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Create test users** (optional)
   ```bash
   python manage.py shell
   ```
   ```python
   from django.contrib.auth.models import User
   User.objects.create_user('alice', 'alice@example.com', 'password123')
   User.objects.create_user('bob', 'bob@example.com', 'password123')
   exit()
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

The API will be available at `http://localhost:8000/api/`

## 📚 API Documentation

All endpoints require authentication. Use Basic Auth or Session Auth with Django credentials.

### Authentication

For testing, you can use:
- **Session Auth**: Login via Django admin or browsable API
- **Basic Auth**: Include `Authorization: Basic <base64(username:password)>` header

### Endpoints

#### 1. File Upload

**Upload a file (metadata only)**

```http
POST /api/files/upload/
Content-Type: application/json

{
  "file_name": "Project Report.pdf",
  "size": 2048000,
  "mime_type": "application/pdf"
}
```

**Response:**
```json
{
  "message": "File uploaded successfully",
  "file": {
    "id": 1,
    "file_id": "a1b2c3d4-e5f6-...",
    "file_name": "Project Report.pdf",
    "owner": {
      "id": 1,
      "username": "alice",
      "email": "alice@example.com"
    },
    "size": 2048000,
    "mime_type": "application/pdf",
    "created_at": "2024-12-25T10:30:00",
    "updated_at": "2024-12-25T10:30:00"
  }
}
```

#### 2. List Files

**Get all files owned by current user**

```http
GET /api/files/
```

**Response:**
```json
{
  "count": 2,
  "files": [
    {
      "id": 1,
      "file_id": "a1b2c3d4...",
      "file_name": "Report.pdf",
      "owner": {...},
      "size": 2048000,
      "created_at": "2024-12-25T10:30:00"
    }
  ]
}
```

#### 3. Initiate Share

**Share a file (forward or reverse)**

**Forward Share** (Owner shares with user):
```http
POST /api/share/initiate/
Content-Type: application/json

{
  "file_id": "a1b2c3d4-e5f6-...",
  "recipient_email": "bob@example.com",
  "share_type": "forward",
  "permission_level": "view",
  "message": "Please review this document"
}
```

**Reverse Share** (User requests access):
```http
POST /api/share/initiate/
Content-Type: application/json

{
  "file_id": "a1b2c3d4-e5f6-...",
  "recipient_email": "alice@example.com",
  "share_type": "reverse",
  "permission_level": "view",
  "message": "I need access to this file"
}
```

**Response:**
```json
{
  "message": "Share request initiated successfully",
  "share_request": {
    "id": 1,
    "file": {...},
    "share_type": "forward",
    "initiator": {...},
    "recipient": {...},
    "permission_level": "view",
    "status": "pending",
    "message": "Please review this document",
    "requested_at": "2024-12-25T10:35:00"
  }
}
```

#### 4. Approve Share

**Approve a pending share request**

```http
POST /api/share/approve/
Content-Type: application/json

{
  "share_request_id": 1
}
```

**Response:**
```json
{
  "message": "Share request approved successfully",
  "share_request": {
    "id": 1,
    "status": "approved",
    "processed_at": "2024-12-25T10:40:00",
    "processed_by": {...}
  }
}
```

**Authorization Rules:**
- **Forward Share**: Only the recipient can approve
- **Reverse Share**: Only the file owner can approve

#### 5. Reject Share

**Reject a pending share request**

```http
POST /api/share/reject/
Content-Type: application/json

{
  "share_request_id": 1
}
```

**Response:**
```json
{
  "message": "Share request rejected successfully",
  "share_request": {
    "id": 1,
    "status": "rejected",
    "processed_at": "2024-12-25T10:45:00"
  }
}
```

#### 6. Revoke Share

**Revoke an approved share**

```http
POST /api/share/revoke/
Content-Type: application/json

{
  "share_request_id": 1
}
```

**Response:**
```json
{
  "message": "Share revoked successfully",
  "share_request": {
    "id": 1,
    "status": "revoked",
    "processed_at": "2024-12-25T10:50:00"
  }
}
```

**Authorization**: Only the file owner can revoke access

#### 7. List Share Requests

**Get share requests (sent, received, or all)**

```http
GET /api/share/requests/?filter=all
```

Query parameters:
- `filter`: `all` (default), `sent`, or `received`

**Response:**
```json
{
  "count": 3,
  "filter": "all",
  "share_requests": [...]
}
```

#### 8. Audit Logs

**Get audit logs with optional filters**

```http
GET /api/audits/?action=upload&limit=50
```

Query parameters:
- `action`: Filter by action type (upload, share_initiate, share_approve, etc.)
- `limit`: Maximum number of logs (default: 100, max: 1000)

**Response:**
```json
{
  "count": 15,
  "filters": {"action": "upload"},
  "audit_logs": [
    {
      "id": 1,
      "action": "upload",
      "actor": {
        "username": "alice",
        "email": "alice@example.com"
      },
      "file": {...},
      "details": {...},
      "ip_address": "127.0.0.1",
      "timestamp": "2024-12-25T10:30:00"
    }
  ]
}
```

## 🧪 Running Tests

Run the comprehensive test suite:

```bash
python manage.py test sharing
```

Test coverage includes:
- Model tests
- Service layer tests
- API endpoint tests
- Authentication tests

## 🔧 Mock Drive Service

The `MockDriveService` adapter simulates cloud storage operations:

```python
# sharing/adapters.py
class MockDriveService:
    def upload_file(self, file_name, owner_email, size, mime_type)
    def grant_permission(self, file_id, user_email, permission_level)
    def revoke_permission(self, file_id, user_email)
    def get_file_permissions(self, file_id)
    def check_permission(self, file_id, user_email)
```

In production, this would be replaced with actual Google Drive API calls.

## 📊 Database Schema

### FileResource
- `file_id`: Unique file identifier (UUID)
- `file_name`: Name of the file
- `owner`: Foreign key to User
- `size`: File size in bytes
- `mime_type`: MIME type
- Timestamps: `created_at`, `updated_at`

### ShareRequest
- `file`: Foreign key to FileResource
- `share_type`: 'forward' or 'reverse'
- `initiator`: User who initiated the share
- `recipient`: User receiving the share
- `permission_level`: 'view' or 'edit'
- `status`: 'pending', 'approved', 'rejected', 'revoked'
- Timestamps: `requested_at`, `processed_at`

### AuditLog
- `action`: Type of action performed
- `actor`: User who performed the action
- `file`: Related file (optional)
- `share_request`: Related share request (optional)
- `details`: JSON field with additional information
- `ip_address`: Client IP address
- `user_agent`: Client user agent
- `timestamp`: When the action occurred

## 🎨 Admin Interface

Access the Django admin at `http://localhost:8000/admin/` to:
- View and manage files
- Monitor share requests
- Inspect audit logs
- Manage users

## 📝 Example Workflow

### Forward Sharing (Owner → User)

1. **Alice uploads a file**
   ```bash
   POST /api/files/upload/
   {"file_name": "Q4_Report.pdf"}
   ```

2. **Alice shares with Bob**
   ```bash
   POST /api/share/initiate/
   {
     "file_id": "abc123...",
     "recipient_email": "bob@example.com",
     "share_type": "forward",
     "permission_level": "view"
   }
   ```

3. **Bob approves the share**
   ```bash
   POST /api/share/approve/
   {"share_request_id": 1}
   ```

4. **Mock Drive grants permission** (automatic)

### Reverse Sharing (User → Owner)

1. **Bob requests access to Alice's file**
   ```bash
   POST /api/share/initiate/
   {
     "file_id": "abc123...",
     "recipient_email": "alice@example.com",
     "share_type": "reverse",
     "message": "Need access for review"
   }
   ```

2. **Alice (owner) approves the request**
   ```bash
   POST /api/share/approve/
   {"share_request_id": 2}
   ```

3. **Mock Drive grants permission** (automatic)

## 🔐 Security Considerations

- All endpoints require authentication
- Permission checks enforce business rules
- Audit logs track all actions for accountability
- CSRF protection enabled for state-changing operations
- Input validation via serializers

## 📦 Project Structure

```
drive_sharing_system/
├── core/                      # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── sharing/                   # Main application
│   ├── models.py             # Data models
│   ├── serializers.py        # API serializers
│   ├── views.py              # API views (thin)
│   ├── services.py           # Business logic
│   ├── adapters.py           # External service adapters
│   ├── urls.py               # URL routing
│   ├── admin.py              # Admin configuration
│   └── tests.py              # Test suite
├── manage.py                  # Django management script
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🚧 Future Enhancements (Bonus Features)

The assignment includes optional bonus features for Google Drive integration:
- OAuth2 authentication with Google
- Real-time file selection using Google Picker API
- Live permission synchronization with Google Drive
- Cloud-synced revocation
- Enhanced audit logging with Google API responses

## 👤 Author

Created as part of the IUDX Backend Developer Assignment

## 📄 License

This is an assignment project for educational purposes.

# Quick Start Guide

## 1. Installation (5 minutes)

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create test users
python manage.py shell < setup_test_data.py

# Start the server
python manage.py runserver
```

The server will be running at: http://localhost:8000

## 2. Access Points

- **API Base**: http://localhost:8000/api/
- **Django Admin**: http://localhost:8000/admin/

## 3. Test Users

The system comes with 3 pre-configured test users:

| Username | Email | Password |
|----------|-------|----------|
| alice | alice@example.com | password123 |
| bob | bob@example.com | password123 |
| charlie | charlie@example.com | password123 |

## 4. Quick API Test

### Using curl:

```bash
# Upload a file (as Alice)
curl -X POST http://localhost:8000/api/files/upload/ \
  -u alice:password123 \
  -H "Content-Type: application/json" \
  -d '{"file_name": "test.pdf", "size": 1024}'

# You'll get a response with a file_id, copy it for the next step

# Share the file with Bob (replace FILE_ID)
curl -X POST http://localhost:8000/api/share/initiate/ \
  -u alice:password123 \
  -H "Content-Type: application/json" \
  -d '{
    "file_id": "FILE_ID",
    "recipient_email": "bob@example.com",
    "share_type": "forward",
    "permission_level": "view"
  }'

# You'll get a share_request_id, copy it

# Approve the share (as Bob, replace SHARE_REQUEST_ID)
curl -X POST http://localhost:8000/api/share/approve/ \
  -u bob:password123 \
  -H "Content-Type: application/json" \
  -d '{"share_request_id": SHARE_REQUEST_ID}'

# View audit logs
curl http://localhost:8000/api/audits/ -u alice:password123
```

### Using Postman:

1. Import `Postman_Collection.json` into Postman
2. Update the auth credentials (alice/password123 by default)
3. Run the requests in order:
   - Upload File
   - Initiate Forward Share
   - (Switch to Bob's credentials)
   - Approve Share

## 5. API Workflow Example

**Scenario**: Alice uploads a document and shares it with Bob

```
1. Alice uploads file
   POST /api/files/upload/
   → File created with status "uploaded"

2. Alice shares with Bob (forward share)
   POST /api/share/initiate/
   → ShareRequest created with status "pending"

3. Bob approves the share
   POST /api/share/approve/
   → ShareRequest status changes to "approved"
   → Mock Drive grants permission automatically
   → Audit logs created for all actions

4. Alice can revoke access later
   POST /api/share/revoke/
   → ShareRequest status changes to "revoked"
   → Mock Drive revokes permission
```

## 6. Running Tests

```bash
# Run all tests
python manage.py test sharing

# Run specific test class
python manage.py test sharing.tests.FileServiceTest

# Run with verbose output
python manage.py test sharing --verbosity=2
```

## 7. Checking Audit Logs

All actions are logged in the AuditLog table. You can:

1. **Via API**:
   ```bash
   curl http://localhost:8000/api/audits/ -u alice:password123
   ```

2. **Via Django Admin**:
   - Go to http://localhost:8000/admin/
   - Login with your credentials
   - Navigate to "Audit logs"

## 8. Troubleshooting

**Issue**: "Authentication credentials were not provided"
- **Solution**: Make sure you're sending authentication headers with every request

**Issue**: "User with email X not found"
- **Solution**: Create the user first or use test users (alice, bob, charlie)

**Issue**: Migration errors
- **Solution**: Delete db.sqlite3 and run `python manage.py migrate` again

## 9. Next Steps

- Explore the Django Admin interface
- Try the reverse sharing flow (user requests access)
- Test the reject and revoke workflows
- Review audit logs to see all tracked actions
- Run the test suite to understand the codebase

## 10. Key Endpoints Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /api/files/upload/ | Upload file metadata |
| GET | /api/files/ | List user's files |
| POST | /api/share/initiate/ | Initiate share (forward/reverse) |
| POST | /api/share/approve/ | Approve pending share |
| POST | /api/share/reject/ | Reject pending share |
| POST | /api/share/revoke/ | Revoke approved share |
| GET | /api/share/requests/ | List share requests |
| GET | /api/audits/ | View audit logs |

For detailed API documentation, see README.md

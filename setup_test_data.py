"""
Setup script to create test users and sample data
Run with: python manage.py shell < setup_test_data.py
"""
from django.contrib.auth.models import User

# Create test users
users_data = [
    {'username': 'alice', 'email': 'alice@example.com', 'password': 'password123'},
    {'username': 'bob', 'email': 'bob@example.com', 'password': 'password123'},
    {'username': 'charlie', 'email': 'charlie@example.com', 'password': 'password123'},
]

print("Creating test users...")
for user_data in users_data:
    user, created = User.objects.get_or_create(
        username=user_data['username'],
        email=user_data['email']
    )
    if created:
        user.set_password(user_data['password'])
        user.save()
        print(f"✓ Created user: {user.username} ({user.email})")
    else:
        print(f"- User already exists: {user.username}")

print("\nTest users ready!")
print("\nYou can now login with:")
print("  Username: alice, Password: password123")
print("  Username: bob, Password: password123")
print("  Username: charlie, Password: password123")

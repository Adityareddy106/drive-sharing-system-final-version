"""
URL routing for the sharing app
"""
from django.urls import path
from . import views

app_name = 'sharing'

urlpatterns = [
    # File endpoints
    path('files/upload/', views.upload_file, name='upload_file'),
    path('files/', views.list_files, name='list_files'),
    
    # Share endpoints
    path('share/initiate/', views.initiate_share, name='initiate_share'),
    path('share/approve/', views.approve_share, name='approve_share'),
    path('share/reject/', views.reject_share, name='reject_share'),
    path('share/revoke/', views.revoke_share, name='revoke_share'),
    path('share/requests/', views.list_share_requests, name='list_share_requests'),
    
    # Audit endpoints
    path('audits/', views.list_audits, name='list_audits'),
]

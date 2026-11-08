# backend/api/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AccountView,
    AdminAuditView,
    AdminOverviewView,
    AdminUserActionView,
    AdminUserProfileView,
    ActivitySummaryView,
    AdminDocumentListView,
    AdminDocumentDetailView,
    AdminDocumentDownloadView,
    AdminDocumentReplaceView,
    AdminShareActionView,
    AuditLogViewSet,
    FileShareViewSet,
    RegisterView,
    SecureFileViewSet,
    SharedFileViewSet,
    SharedFileRevisionViewSet,
    AuditedTokenObtainPairView,
    LogoutView,
    VersionedTokenRefreshView,
)

router = DefaultRouter()
router.register(r'files', SecureFileViewSet, basename='securefile')
router.register(r'shares', FileShareViewSet, basename='fileshare')
router.register(r'shared-with-me', SharedFileViewSet, basename='sharedfile')
router.register(r'revisions', SharedFileRevisionViewSet, basename='sharedfilerevision')
router.register(r'logs', AuditLogViewSet, basename='auditlog')

urlpatterns = [
    path('account/', AccountView.as_view(), name='account'),
    path('activity/summary/', ActivitySummaryView.as_view(), name='activity-summary'),
    path('admin/overview/', AdminOverviewView.as_view(), name='admin-overview'),
    path('admin/audit/', AdminAuditView.as_view(), name='admin-audit'),
    path('admin/documents/', AdminDocumentListView.as_view(), name='admin-documents'),
    path(
        'admin/documents/<int:pk>/',
        AdminDocumentDetailView.as_view(),
        name='admin-document-detail',
    ),
    path(
        'admin/documents/<int:pk>/download/',
        AdminDocumentDownloadView.as_view(),
        name='admin-document-download',
    ),
    path(
        'admin/documents/<int:pk>/replace/',
        AdminDocumentReplaceView.as_view(),
        name='admin-document-replace',
    ),
    path(
        'admin/shares/<int:pk>/action/',
        AdminShareActionView.as_view(),
        name='admin-share-action',
    ),
    path(
        'admin/users/<int:pk>/profile/',
        AdminUserProfileView.as_view(),
        name='admin-user-profile',
    ),
    path(
        'admin/users/<int:pk>/action/',
        AdminUserActionView.as_view(),
        name='admin-user-action',
    ),
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/', AuditedTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', VersionedTokenRefreshView.as_view(), name='token_refresh'),
]

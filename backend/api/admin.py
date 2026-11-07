from django.contrib import admin

from .models import AuditLog, FileShare, SecureFile
from .views import delete_file_share, delete_secure_file


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp',
        'actor_username',
        'action',
        'outcome',
        'file_title',
        'file_owner_username',
        'ip_address',
    )
    list_filter = ('outcome', 'action', 'timestamp')
    search_fields = (
        'actor_username',
        'file_title',
        'file_owner_username',
        'ip_address',
        'details',
    )
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)
    readonly_fields = (
        'user',
        'actor_username',
        'file',
        'file_title',
        'file_owner',
        'file_owner_username',
        'action',
        'outcome',
        'ip_address',
        'timestamp',
        'details',
        'previous_hash',
        'integrity_hash',
    )

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff

    def has_module_permission(self, request):
        return request.user.is_active and request.user.is_staff

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecureFile)
class SecureFileAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'user',
        'category',
        'file_size',
        'uploaded_at',
        'encryption_algorithm',
    )
    list_filter = ('category', 'uploaded_at')
    search_fields = ('title', 'category', 'user__username')
    readonly_fields = (
        'user',
        'title',
        'file',
        'uploaded_at',
        'file_size',
        'encryption_algorithm',
        'encryption_version',
        'passcode_hash',
    )

    def has_add_permission(self, request):
        return False

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff

    def has_module_permission(self, request):
        return request.user.is_active and request.user.is_staff

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return (
            request.user.is_active
            and request.user.is_staff
            and request.user.is_superuser
        )

    def delete_model(self, request, obj):
        delete_secure_file(request, obj, action="File Deleted by Admin")

    def delete_queryset(self, request, queryset):
        for secure_file in queryset.iterator():
            delete_secure_file(request, secure_file, action="File Deleted by Admin")


@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = (
        'file',
        'recipient',
        'permission',
        'created_at',
        'expires_at',
        'revoked_at',
        'failed_passcode_attempts',
        'passcode_locked_until',
    )
    list_filter = ('created_at', 'expires_at', 'revoked_at')
    search_fields = ('file__title', 'file__user__username', 'recipient__username')
    fields = (
        'file',
        'recipient',
        'permission',
        'created_at',
        'expires_at',
        'revoked_at',
        'failed_passcode_attempts',
        'passcode_locked_until',
    )
    readonly_fields = (
        'file',
        'recipient',
        'permission',
        'created_at',
        'expires_at',
        'revoked_at',
        'failed_passcode_attempts',
        'passcode_locked_until',
    )

    def has_add_permission(self, request):
        return False

    def has_view_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff

    def has_module_permission(self, request):
        return request.user.is_active and request.user.is_staff

    def has_change_permission(self, request, obj=None):
        return request.user.is_active and request.user.is_staff

    def has_delete_permission(self, request, obj=None):
        return (
            request.user.is_active
            and request.user.is_staff
            and request.user.is_superuser
        )

    def delete_model(self, request, obj):
        delete_file_share(request, obj)

    def delete_queryset(self, request, queryset):
        for share in queryset.iterator():
            delete_file_share(request, share)

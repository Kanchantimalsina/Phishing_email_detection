from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'full_name', 'is_staff', 'is_active', 'is_admin']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'is_admin']
    search_fields = ['username', 'email', 'full_name']
    readonly_fields = ['created_at', 'last_login', 'date_joined']

    fieldsets = UserAdmin.fieldsets + (
        ('Profile', {'fields': ('full_name', 'is_admin', 'created_at')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Profile', {'fields': ('full_name', 'email', 'is_admin')}),
    )

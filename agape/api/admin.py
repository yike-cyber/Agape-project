from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import mark_safe
from .models import User, Warrant, DisabilityRecord,Equipment
from django.conf import settings

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['first_name', 'last_name', 'email', 'role', 'profile_image_display', 'is_active','deleted']
    search_fields = ['first_name', 'last_name', 'email', 'phone_number']
    ordering = ['first_name']

    # Customize the fieldsets to add the profile_image field
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'middle_name', 'phone_number', 'profile_image')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'role')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password', 'first_name', 'last_name', 'middle_name', 'role', 'is_active', 'is_staff')}
        ),
    )

    # Custom method to display profile image
    def profile_image_display(self, obj):
        return mark_safe(f'<img src="{obj.profile_image.url}" width="50" height="50" />') if obj.profile_image else mark_safe(f'<img src="{settings.MEDIA_URL}default_profile_image/avatar.png" width="50" height="50" />')

    profile_image_display.short_description = 'Profile Image'

admin.site.register(User, CustomUserAdmin)
admin.site.register(Warrant)
admin.site.register(DisabilityRecord)

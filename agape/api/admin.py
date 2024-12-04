from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import mark_safe
from .models import User, Warrant, DisabilityRecord, Equipment
from django.conf import settings

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['first_name', 'last_name','phone_number', 'email', 'role', 'profile_image_display', 'is_active', 'deleted']
    search_fields = ['first_name', 'last_name', 'email', 'phone_number']
    ordering = ['first_name']

    # Customize the fieldsets to add the profile_image field
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'middle_name', 'phone_number', 'profile_image')}),
        ('Permissions', {'fields': ('is_active', 'deleted', 'is_staff', 'role')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password', 'first_name', 'last_name', 'middle_name', 'role', 'is_active', 'deleted', 'is_staff')}
        ),
    )

    # Custom method to display profile image
    def profile_image_display(self, obj):
        if obj.profile_image and hasattr(obj.profile_image, 'url'):
            return mark_safe(f'<img src="{obj.profile_image.url}" width="50" height="50" />')
        else:
            default_image_url = f'{settings.MEDIA_URL}default_profile_image/avatar.png'
            return mark_safe(f'<img src="{default_image_url}" width="50" height="50" />')

    profile_image_display.short_description = 'Profile Image'
    
    
class WarrantAdmin(admin.ModelAdmin):
    list_display = ['first_name', 'middle_name', 'last_name', 'phone_number', 'gender', 'id_image_preview', 'deleted']
    search_fields = ['first_name', 'last_name', 'phone_number']
    list_filter = ['gender', 'deleted']

    def id_image_preview(self, obj):
        if obj.id_image:
            return mark_safe(f'<img src="{obj.id_image.url}" width="50" height="50" />')
        return mark_safe('<img src="https://res.cloudinary.com/dacglftgb/image/upload/vdefault/avatar.png" width="50" height="50" />')
    id_image_preview.short_description = 'ID Image'


# Disability Record Admin
class DisabilityRecordAdmin(admin.ModelAdmin):
    list_display = ['get_full_name', 'gender', 'region', 'is_active', 'is_provided', 'profile_image_preview']
    search_fields = ['first_name', 'last_name', 'region', 'zone', 'city']
    list_filter = ['gender', 'region', 'is_active', 'is_provided']

    def profile_image_preview(self, obj):
        if obj.profile_image:
            return mark_safe(f'<img src="{obj.profile_image.url}" width="50" height="50" />')
        return mark_safe('<img src="https://res.cloudinary.com/dacglftgb/image/upload/vdefault/avatar.png" width="50" height="50" />')
    profile_image_preview.short_description = 'Profile Image'

admin.site.register(User, CustomUserAdmin)
admin.site.register(Warrant,WarrantAdmin)
admin.site.register(DisabilityRecord,DisabilityRecordAdmin)

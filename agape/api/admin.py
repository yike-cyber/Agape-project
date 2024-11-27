from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Warrant, DisabilityRecord

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ['first_name', 'last_name', 'email', 'role', 'profile_image', 'is_staff']
    search_fields = ['first_name', 'last_name', 'email', 'phone_number']
    ordering = ['first_name']

    # Customize the fieldsets and add_fieldsets to use email as the identifier
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'phone_number', 'profile_image')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'role')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password', 'first_name', 'last_name', 'role', 'is_active', 'is_staff')}
        ),
    )
    
    def get_search_results(self, request, queryset, search_term):
        return queryset.filter(email__icontains=search_term), False

admin.site.register(User, CustomUserAdmin)
admin.site.register(Warrant)
admin.site.register(DisabilityRecord)

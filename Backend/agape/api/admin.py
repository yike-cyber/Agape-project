from django.contrib import admin
from django.contrib.auth.admin import UserAdmin


from .models import User, Warrant, DisabilityRecord

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = [ 'first_name','middle_name', 'last_name', 'email', 'role', 'gender', 'phone_number', 'is_staff']
    search_fields = ['first_name', 'last_name', 'email','phone_number']
    ordering = ['first_name']


admin.site.register(User, CustomUserAdmin)
admin.site.register(Warrant)
admin.site.register(DisabilityRecord)

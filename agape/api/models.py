from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
from django.utils.safestring import mark_safe
from django.contrib.auth.models import BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


# Gender Choices
GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
]

# Role Choices
ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('field_worker', 'Field Worker'),
]

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.CharField(max_length = 100,unique = True)
    first_name = models.CharField(max_length=50,verbose_name = 'first name')
    middle_name = models.CharField(max_length=50,null=True,verbose_name = 'middle name')
    last_name = models.CharField(max_length=50,verbose_name = 'last name')
    gender = models.CharField(max_length=10,null=True, choices=GENDER_CHOICES)
    phone_number = models.CharField(max_length=15,null=True, unique=True)
    profile_image = models.ImageField(upload_to='user_profile_images/',default='default_profile_image/avatar.png', blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES,default='field_worker')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    
    username = None
    USERNAME_FIELD = 'email'
    
    objects = CustomUserManager()
    
    REQUIRED_FIELDS =['first_name','last_name']

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"
    
    
def profile_image(self):
    if self.profile_image:
        return mark_safe(f'<img src="{self.profile_image.url}" width="50" height="50" />')
    return mark_safe(f'<img src="{settings.MEDIA_URL}default_profile_image/avatar.png" width="50" height="50" />')


class Warrant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100,blank=True,null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    phone_number = models.CharField(max_length=15,null=True, unique=True)
    id_image = models.ImageField(upload_to='warrant_id_images/',null=True,blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class DisabilityRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    phone_number = models.CharField(max_length=15,null=True, unique=True)
    date_of_birth = models.DateField()
    region = models.CharField(max_length=100,null=True,blank=True)
    zone = models.CharField(max_length=100,null=True,blank=True)
    city = models.CharField(max_length=100,null=True,blank=True)
    woreda = models.CharField(max_length=100,null=True,blank=True)
    recorder = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='recordor')
    warrant = models.ForeignKey(Warrant, on_delete=models.SET_NULL, null=True, blank=True, related_name='disability_records')
    seat_width = models.FloatField()
    backrest_height = models.FloatField()
    seat_depth= models.FloatField()
    profile_image = models.ImageField(upload_to='disability_profile_images/',default='default_profile_image/avatar.png',blank=True)
    kebele_id_image = models.ImageField(upload_to='disability_kebele_id_images/',null=True,blank=True)
    wheelchair_type = models.CharField(max_length=100)
    is_provided = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.wheelchair_type}"
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
import uuid
from cloudinary.models import CloudinaryField
from django.utils.safestring import mark_safe
from django.conf import settings


# Gender Choices
GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
]

ROLE_CHOICES = [
    ('admin', 'Admin'),
    ('field_worker', 'Field Worker'),
]


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
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.CharField(max_length=100, unique=True)
    first_name = models.CharField(max_length=50, verbose_name='first name')
    middle_name = models.CharField(max_length=50, null=True, verbose_name='middle name')
    last_name = models.CharField(max_length=50, verbose_name='last name')
    gender = models.CharField(max_length=10, null=True, choices=GENDER_CHOICES)
    phone_number = models.CharField(max_length=15, null=True, unique=True)
    profile_image = CloudinaryField(
        'image',
        blank=True,
        null=True,
        folder ='users/profile_images'
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='field_worker')
    is_active = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    class Meta:
        ordering = ['-created_at', 'first_name']

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"

    @property
    def get_full_name(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"


class Warrant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=15, null=True, unique=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    id_image = CloudinaryField(
        'image',
        blank=True,
        null=True,
        folder = 'warrants/warrant_id_images'
    )
    deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class Equipment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    equipment_type = models.CharField(max_length=100, blank=True, null=True)
    size = models.CharField(max_length=50, null=True, blank=True)
    cause_of_need = models.CharField(max_length=100, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.equipment_type.replace('_', ' ')} - {self.size if self.size else 'Unknown Size'}"


class DisabilityRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)
    date_of_birth = models.DateField()
    phone_number = models.CharField(max_length=15, null=True, unique=True)
    region = models.CharField(max_length=100, null=True, blank=True)
    zone = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    woreda = models.CharField(max_length=100, null=True, blank=True)
    recorder = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='recordor')
    warrant = models.ForeignKey(Warrant, on_delete=models.SET_NULL, null=True, blank=True, related_name='disability_records')
    equipment = models.ForeignKey(Equipment, on_delete=models.SET_NULL, null=True, blank=True)

    hip_width = models.FloatField()
    backrest_height = models.FloatField()
    thigh_length = models.FloatField()
    profile_image = CloudinaryField(
        'image',
        blank=True,
        null=True,
        folder = 'disability_records/profile_images'
    )

    kebele_id_image = CloudinaryField('image', blank=True, null=True,folder = 'disability_records/kebele_id_images')

    is_provided = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.equipment.equipment_type if self.equipment else 'No Equipment'}"

    @property
    def get_full_name(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"
    
    
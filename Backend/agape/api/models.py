from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid

# Gender Choices
GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
    ('other', 'Other'),
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
    
    USERNAME_FIELD = 'email'
    
    REQUIRED_FIELDS =['first_name','last_name']

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"

class OneTimePassword(models.Model):
    user = models.OneToOneField(User,on_delete = models.CASCADE)
    code = models.CharField(max_length=6,unique=True)
    
    def __str__(self):
        return  f'{self.user.user_name}-passcode'

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
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_disability_records')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.wheelchair_type}"
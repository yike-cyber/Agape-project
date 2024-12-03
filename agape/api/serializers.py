from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from .models import Warrant, DisabilityRecord, Equipment
from .utils import validate_password
from django.conf import settings

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    profile_image_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'middle_name', 'last_name', 
            'gender', 'phone_number', 'profile_image','is_active', 'role', 
            'created_at', 'updated_at','profile_image_url'
        ]
    def get_profile_image_url(self, obj):
        request = self.context.get('request')
        if obj.profile_image:
            return request.build_absolute_uri(obj.profile_image.url)
        return None

class WarrantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Warrant
        fields = [
            'id', 'first_name', 'middle_name', 'last_name', 
            'gender', 'phone_number', 'id_image', 
            'deleted'
        ]

class EquipmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Equipment
        fields = [
            'id', 'equipment_type', 'size', 'cause_of_need', 
            'created_at', 'updated_at'
        ]
class DisabilityRecordSerializer(serializers.ModelSerializer):
    recorder = UserSerializer(read_only=True)
    warrant = WarrantSerializer()
    equipment = EquipmentSerializer()
    profile_image_url = serializers.SerializerMethodField()

    class Meta:
        model = DisabilityRecord
        fields = [
            'id', 'first_name', 'middle_name', 'last_name', 'gender',
            'phone_number', 'date_of_birth', 'region', 'zone', 'city',
            'woreda', 'recorder', 'warrant', 'equipment',
            'hip_width', 'backrest_height', 'thigh_length',
            'profile_image', 'kebele_id_image', 'is_provided',
            'deleted', 'is_active', 'created_at', 'updated_at', 'profile_image_url',
        ]

    def get_profile_image_url(self, obj):
        request = self.context.get('request')
        if obj.profile_image:
            return request.build_absolute_uri(obj.profile_image.url)
        return request.build_absolute_uri(settings.MEDIA_URL + 'default_profile_image/avatar.png')

    def create(self, validated_data):
        # Pop nested data
        warrant_data = validated_data.pop('warrant', None)
        equipment_data = validated_data.pop('equipment', None)

        # Create the DisabilityRecord instance
        disability_record = DisabilityRecord.objects.create(**validated_data)

        # Handle Warrant
        if warrant_data:
            warrant_serializer = WarrantSerializer(data=warrant_data,partial = True)
            warrant_serializer.is_valid(raise_exception=True)
            warrant = warrant_serializer.save()
            disability_record.warrant = warrant  # Associate with DisabilityRecord

        # Handle Equipment
        if equipment_data:
            equipment_serializer = EquipmentSerializer(data=equipment_data,partial = True)
            equipment_serializer.is_valid(raise_exception=True)
            equipment = equipment_serializer.save()
            disability_record.equipment = equipment  # Associate with DisabilityRecord

        disability_record.save()
        return disability_record

    def update(self, instance, validated_data):
        # Pop nested data
        warrant_data = validated_data.pop('warrant', None)
        equipment_data = validated_data.pop('equipment', None)

        # Update non-nested fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Update Warrant
        if warrant_data:
            if instance.warrant:
                warrant_serializer = WarrantSerializer(instance.warrant, data=warrant_data, partial=True)
            else:
                warrant_serializer = WarrantSerializer(data=warrant_data)
            warrant_serializer.is_valid(raise_exception=True)
            warrant = warrant_serializer.save()
            instance.warrant = warrant

        # Update Equipment
        if equipment_data:
            if instance.equipment:
                equipment_serializer = EquipmentSerializer(instance.equipment, data=equipment_data, partial=True)
            else:
                equipment_serializer = EquipmentSerializer(data=equipment_data)
            equipment_serializer.is_valid(raise_exception=True)
            equipment = equipment_serializer.save()
            instance.equipment = equipment

        instance.save()
        return instance


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'email', 'first_name', 'middle_name', 'last_name', 
            'gender', 'phone_number', 'profile_image', 'role'
        ]

    def create(self, validated_data):
        password = validated_data['first_name']
        profile_image = validated_data.pop('profile_image', None)
        user = User.objects.create(**validated_data)
        user.set_password(password)
        if profile_image:
            user.profile_image = profile_image
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = User.objects.filter(email=email).first()
        if not user:
            raise serializers.ValidationError(_("Invalid credentials"))

        if not user.check_password(password):
            raise serializers.ValidationError(_("Invalid credentials"))

        attrs['user'] = user
        return attrs

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError(_("Email not found"))
        return value

class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    def validate_password2(self, value):
        password = self.initial_data.get('password')
        if value != password:
            raise serializers.ValidationError("Passwords do not match.")
        return value

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

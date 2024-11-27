from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

from .models import Warrant,DisabilityRecord,Equipment
from .utils import validate_password
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'middle_name', 'last_name', 'gender', 'phone_number', 'profile_image', 'role', 'created_at', 'updated_at']

class WarrantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Warrant
        fields = ['id', 'first_name', 'middle_name', 'last_name', 'gender', 'phone_number', 'id_image']
        
        
class EquipmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Equipment
        fields = ['id', 'equipment_type', 'size','cause_of_need', 'created_at', 'updated_at']

class DisabilityRecordSerializer(serializers.ModelSerializer):
    recorder = UserSerializer(read_only=True)
    warrant = WarrantSerializer() 
    equipment = EquipmentSerializer()  

    class Meta:
        model = DisabilityRecord
        fields = [
            'id', 'first_name', 'middle_name', 'last_name', 'gender', 
            'phone_number', 'date_of_birth', 'region', 'zone', 'city', 
            'woreda', 'recorder', 'warrant', 'equipment', 
            'seat_width', 'backrest_height', 'seat_depth', 
            'profile_image', 'kebele_id_image', 'is_provided', 
            'deleted', 'created_at', 'updated_at'
        ]

    def create(self, validated_data):
        warrant_data = validated_data.pop('warrant', None)
        equipment_data = validated_data.pop('equipment', None)

        disability_record = DisabilityRecord.objects.create(
            **validated_data,
            recorder=self.context['request'].user
        )

        if warrant_data:
            warrant = Warrant.objects.create(**warrant_data)
            disability_record.warrant = warrant

        if equipment_data:
            equipment = Equipment.objects.create(**equipment_data)
            disability_record.equipment = equipment

        disability_record.save()
        return disability_record

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'first_name', 'middle_name', 'last_name', 'gender', 'phone_number', 'profile_image', 'role', 'password']

    def validate(self, attrs):
        password = attrs.get('password')

       

        # Validate password strength
        try:
            validate_password(password)
        except Exception as e:
            raise serializers.ValidationError({'password': e.messages})

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        profile_image = validated_data.pop('profile_image',None)
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
        # Check if user exists with the provided email
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value
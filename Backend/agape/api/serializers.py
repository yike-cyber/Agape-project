from rest_framework import serializers
from .models import User,DisabilityRecord,Warrant

class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name','middle_name', 'last_name', 'gender', 'phone_number', 'role', 'profile_image')

class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True, required=True)
    profile_image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name','middle_name', 'last_name', 'gender', 'phone_number', 'role', 'profile_image')

    def validate(self,attrs):
        return super.validate(attrs)
        
    def create(self, validated_data):
        profile_image = validated_data.pop('profile_image', None)

        user = User.objects.create_user(**validated_data)

        if profile_image:
            user.profile_image = profile_image
            user.save()

        return user
    
class WarrantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Warrant
        fields = '__all__'
        
        
class DisabilityRecordSerializer(serializers.ModelSerializer):
    warrant = WarrantSerializer()
    recorder = UserSerializer()
    
    class Meta:
        model=DisabilityRecord
        fields = '__all__'

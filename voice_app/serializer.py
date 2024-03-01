from rest_framework import serializers
from django.contrib.auth.models import User
from utils.base_models import DynamicFieldsModelSerializer
from django.contrib.auth.password_validation import validate_password



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password',
                  'first_name', 'last_name', 'email','is_staff']
    
    def validate_email(self, value):
        """
        Check if the email address is unique.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('This email address is already in use.')
        return value
    
    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        
        if 'is_staff' in validated_data:
            user.is_staff = validated_data['is_staff']
        
        user.save()
        return user
    

class GoogleAuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name']
        
    def validate_email(self, value):
        """
        Check if the email address is unique.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('This email address is already in use.')
        return value
    
    def create(self, validated_data):
        username = validated_data['email'].split('@')[0]
        user = User.objects.create(
            username=username,
            email=validated_data['email'],
            first_name=validated_data['first_name']
        )
        return user

class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    

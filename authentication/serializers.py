from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, PasswordResetToken

class UserSignUpSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password', 'password_confirm')
        
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Password and confirm password do not match.")
        return attrs
    
    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def create(self, validated_data):
        """Create a new user"""
        validated_data.pop('password_confirm')  # Remove password_confirm from data
        # Generate username from email
        validated_data['username'] = validated_data['email'].split('@')[0]
        
        # Check if username already exists, if so, append numbers
        username = validated_data['username']
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{validated_data['username']}{counter}"
            counter += 1
        validated_data['username'] = username
        
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate user credentials"""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            # Try to authenticate using email as username
            user = authenticate(username=email, password=password)
            
            if not user:
                # If authentication failed, try to find user by email and authenticate with username
                try:
                    user_obj = User.objects.get(email=email)
                    user = authenticate(username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
                
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
                
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include email and password.')
            
        return attrs

class ForgotPasswordSerializer(serializers.Serializer):
    """Serializer for forgot password"""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate if user exists with this email"""
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")
        return value

class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for password reset"""
    token = serializers.UUIDField()
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password confirmation and token"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Password and confirm password do not match.")
            
        # Validate token
        try:
            token_obj = PasswordResetToken.objects.get(
                token=attrs['token'], 
                is_used=False
            )
            if token_obj.is_expired():
                raise serializers.ValidationError("Password reset token has expired.")
            attrs['token_obj'] = token_obj
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")
            
        return attrs

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'is_verified', 'created_at')
        read_only_fields = ('id', 'email', 'is_verified', 'created_at')
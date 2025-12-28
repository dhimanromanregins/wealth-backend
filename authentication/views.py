from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.shortcuts import render
from django.http import HttpResponseNotAllowed
from .models import User, PasswordResetToken
from .serializers import (
    UserSignUpSerializer, 
    UserLoginSerializer, 
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UserProfileSerializer
)

def get_tokens_for_user(user):
    """Generate JWT tokens for user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['POST'])
@permission_classes([AllowAny])
def signup_view(request):
    """User registration endpoint"""
    serializer = UserSignUpSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        
        return Response({
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'tokens': tokens
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'message': 'Registration failed',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """User login endpoint"""
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        tokens = get_tokens_for_user(user)
        
        return Response({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'message': 'Login failed',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Forgot password endpoint"""
    serializer = ForgotPasswordSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        
        # Create password reset token
        reset_token = PasswordResetToken.objects.create(user=user)
        
        # Create reset link
        reset_link = f"{request.build_absolute_uri('/api/auth/reset-password/')}{reset_token.token}/"
        
        # Send email
        subject = 'Password Reset Request - Multifly'
        message = f"""
        Hello {user.first_name},
        
        You have requested to reset your password for your Multifly account.
        
        Please click the link below to reset your password:
        {reset_link}
        
        This link will expire in 1 hour.
        
        If you didn't request this password reset, please ignore this email.
        
        Best regards,
        Multifly Team
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            return Response({
                'success': True,
                'message': 'Password reset link has been sent to your email'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to send email. Please try again later.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response({
        'success': False,
        'message': 'Invalid email address',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    """Reset password endpoint"""
    serializer = ResetPasswordSerializer(data=request.data)
    if serializer.is_valid():
        token_obj = serializer.validated_data['token_obj']
        new_password = serializer.validated_data['password']
        
        # Update user password
        user = token_obj.user
        user.set_password(new_password)
        user.save()
        
        # Mark token as used
        token_obj.is_used = True
        token_obj.save()
        
        return Response({
            'success': True,
            'message': 'Password has been reset successfully'
        }, status=status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'message': 'Password reset failed',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    """Get user profile"""
    serializer = UserProfileSerializer(request.user)
    return Response({
        'success': True,
        'user': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout endpoint"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        return Response({
            'success': True,
            'message': 'Logged out successfully'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'success': False,
            'message': 'Logout failed',
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

def reset_password_form_view(request, token):
    """Display and handle the password reset form"""
    if request.method == 'GET':
        return render(request, 'authentication/reset_password.html', {'token': token})
    
    elif request.method == 'POST':
        # Process the form submission
        serializer = ResetPasswordSerializer(data=request.POST)
        if serializer.is_valid():
            token_obj = serializer.validated_data['token_obj']
            new_password = serializer.validated_data['password']
            
            # Update user password
            user = token_obj.user
            user.set_password(new_password)
            user.save()
            
            # Mark token as used
            token_obj.is_used = True
            token_obj.save()
            
            return render(request, 'authentication/reset_password.html', {
                'token': token,
                'success_message': 'Password has been reset successfully! You can now login with your new password.'
            })
        else:
            return render(request, 'authentication/reset_password.html', {
                'token': token,
                'error_message': 'Password reset failed. Please check your inputs and try again.',
                'errors': serializer.errors
            })
    
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])
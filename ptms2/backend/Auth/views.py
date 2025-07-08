import json
import re
import logging
import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.views import View
from django.http import HttpResponse, JsonResponse
import os
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

# Set up logging
logger = logging.getLogger(__name__)
class ValidationMixin:
    """Mixin class for common validation methods"""
    
    def validate_username(self, username):
        """Validate username with comprehensive checks"""
        if not username:
            return False, "Username is required."
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long."
        
        if len(username) > 30:
            return False, "Username must be less than 30 characters."
        
        # Check for valid characters (alphanumeric, underscores, hyphens)
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens."
        
        # Check if username starts with a letter
        if not username[0].isalpha():
            return False, "Username must start with a letter."
        
        return True, ""
    
    def validate_password(self, password):
        """Validate password with security requirements"""
        if not password:
            return False, "Password is required."
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        
        if len(password) > 128:
            return False, "Password must be less than 128 characters."
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter."
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter."
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number."
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
        
        return True, ""
    
    def sanitize_input(self, value):
        """Sanitize input to prevent basic injection attacks"""
        if not value:
            return ""
        return str(value).strip()


class RegisterView(APIView, ValidationMixin):
    """
    User registration endpoint with comprehensive validation
    """
    
    def post(self, request):
        try:
            # Get and sanitize input data
            username = self.sanitize_input(request.data.get("username"))
            password = self.sanitize_input(request.data.get("password"))
            confirm_password = self.sanitize_input(request.data.get("confirm_password"))
            email = self.sanitize_input(request.data.get("email", ""))
            
            # Validate username
            is_valid_username, username_error = self.validate_username(username)
            if not is_valid_username:
                logger.warning(f"Registration failed: Invalid username - {username_error}")
                return Response(
                    {"error": username_error}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate password
            is_valid_password, password_error = self.validate_password(password)
            if not is_valid_password:
                logger.warning(f"Registration failed: Invalid password for username {username}")
                return Response(
                    {"error": password_error}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check password confirmation
            if password != confirm_password:
                logger.warning(f"Registration failed: Password mismatch for username {username}")
                return Response(
                    {"error": "Passwords do not match."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate email if provided
            if email:
                try:
                    validate_email(email)
                except ValidationError:
                    return Response(
                        {"error": "Please enter a valid email address."}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Check if email already exists
                if User.objects.filter(email=email).exists():
                    return Response(
                        {"error": "Email address already registered."}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                logger.warning(f"Registration failed: Username {username} already exists")
                return Response(
                    {"error": "Username already exists."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create user
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email if email else ""
            )
            
            logger.info(f"User {username} registered successfully")
            return Response(
                {
                    "message": "User created successfully.",
                    "user": {
                        "username": user.username,
                        "email": user.email
                    }
                }, 
                status=status.HTTP_201_CREATED
            )
            
        except IntegrityError as e:
            logger.error(f"Database integrity error during registration: {str(e)}")
            return Response(
                {"error": "Username already exists."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Unexpected error during registration: {str(e)}")
            return Response(
                {"error": "An error occurred during registration. Please try again."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoginView(APIView, ValidationMixin):
    """
    User login endpoint with enhanced security and validation
    """
    
    def post(self, request):
        try:
            # Get and sanitize input data
            username = self.sanitize_input(request.data.get("username"))
            password = self.sanitize_input(request.data.get("password"))
            
            # Basic validation
            if not username or not password:
                logger.warning("Login attempt with missing credentials")
                return Response(
                    {"error": "Username and password are required."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Additional validation for username format
            is_valid_username, username_error = self.validate_username(username)
            if not is_valid_username:
                logger.warning(f"Login failed: Invalid username format - {username}")
                return Response(
                    {"error": "Invalid username format."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if user exists before attempting authentication
            if not User.objects.filter(username=username).exists():
                logger.warning(f"Login failed: User {username} does not exist")
                return Response(
                    {"error": "Invalid credentials"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Authenticate user
            user = authenticate(username=username, password=password)
            if user:
                # Check if user is active
                if not user.is_active:
                    logger.warning(f"Login failed: Inactive user {username}")
                    return Response(
                        {"error": "Account is deactivated. Please contact support."}, 
                        status=status.HTTP_401_UNAUTHORIZED
                    )
                
                # Generate tokens
                refresh = RefreshToken.for_user(user)
                
                # Create response with user data
                response_data = {
                    "message": "Login successful",
                    "user": {
                        "username": user.username,
                        "email": user.email,
                        "user_id": user.id,
                        "is_staff": user.is_staff,
                        "last_login": user.last_login.isoformat() if user.last_login else None
                    }
                }
                
                response = JsonResponse(response_data)
                
                # Set secure cookies
                # Access token cookie
                response.set_cookie(
                    'access_token',
                    str(refresh.access_token),
                    max_age=60*60*24,  # 24 hours
                    httponly=True,     # Can't be accessed by JavaScript
                    secure=settings.DEBUG is False,  # Use HTTPS in production
                    samesite='Lax'     # CSRF protection
                )
                
                # Refresh token cookie
                response.set_cookie(
                    'refresh_token',
                    str(refresh),
                    max_age=60*60*24*7,  # 7 days
                    httponly=True,
                    secure=settings.DEBUG is False,
                    samesite='Lax'
                )
                
                logger.info(f"User {username} logged in successfully")
                return response
            
            # Invalid credentials
            logger.warning(f"Login failed: Invalid credentials for {username}")
            return Response(
                {"error": "Invalid credentials"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}")
            return Response(
                {"error": "An error occurred during login. Please try again."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Serve frontend files
class LoginPageView(View):
    def get(self, request):
        # Path to your frontend login.html file
        frontend_path = os.path.join(settings.BASE_DIR.parent, 'frontend', 'login.html')
        
        try:
            with open(frontend_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            return HttpResponse(html_content, content_type='text/html')
        except FileNotFoundError:
            return HttpResponse("Login page not found", status=404)

class RegisterPageView(View):
    def get(self, request):
        # Path to your frontend register.html file
        frontend_path = os.path.join(settings.BASE_DIR.parent, 'frontend', 'register.html')
        
        try:
            with open(frontend_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            return HttpResponse(html_content, content_type='text/html')
        except FileNotFoundError:
            return HttpResponse("Register page not found", status=404)
          
class DashboardPageView(View):
    def get(self, request):
        # Path to your frontend dashboard.html file
        frontend_path = os.path.join(settings.BASE_DIR.parent, 'frontend', 'dashboard.html')
        
        try:
            with open(frontend_path, 'r', encoding='utf-8') as file:
                html_content = file.read()
            return HttpResponse(html_content, content_type='text/html')
        except FileNotFoundError:
            return HttpResponse("Dashboard page not found", status=404)

class HomepageView(View):
    def get(self, request):
        # Check if user is authenticated via cookie
        token = request.COOKIES.get('access_token')
        
        if not token:
            # Redirect to login if no token
            return redirect('/auth/login/')
        
        try:
            # Verify the token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            
            # Get user and check if active
            user = User.objects.get(id=user_id)
            if not user.is_active:
                # Redirect to login if user is inactive
                return redirect('/auth/login/')
            
            # User is authenticated, serve the homepage
            frontend_path = os.path.join(settings.BASE_DIR.parent, 'frontend', 'homepage.html')
            
            try:
                with open(frontend_path, 'r', encoding='utf-8') as file:
                    html_content = file.read()
                return HttpResponse(html_content, content_type='text/html')
            except FileNotFoundError:
                return HttpResponse("Homepage not found", status=404)
                
        except (InvalidToken, TokenError):
            # Invalid token, redirect to login
            return redirect('/auth/login/')
        except User.DoesNotExist:
            # User not found, redirect to login
            return redirect('/auth/login/')
        except Exception as e:
            logger.error(f"Unexpected error in homepage view: {str(e)}")
            return redirect('/auth/login/')
  
class CheckAuthView(APIView):
    def get(self, request):
        # Get token from cookie
        token = request.COOKIES.get('access_token')
        
        if not token:
            logger.warning("Authentication check failed: No token provided")
            return Response(
                {"error": "No authentication token provided", "authenticated": False}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Verify the token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            
            # Get user
            user = User.objects.get(id=user_id)
            
            # Check if user is still active
            if not user.is_active:
                logger.warning(f"Authentication check failed: User {user.username} is inactive")
                return Response(
                    {"error": "Account is deactivated", "authenticated": False}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return Response({
                "authenticated": True,
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "user_id": user.id,
                    "is_staff": user.is_staff,
                    "last_login": user.last_login.isoformat() if user.last_login else None
                }
            })
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Authentication check failed: Invalid token - {str(e)}")
            return Response(
                {"error": "Invalid or expired token", "authenticated": False}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            logger.warning(f"Authentication check failed: User not found for token")
            return Response(
                {"error": "User not found", "authenticated": False}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            logger.error(f"Unexpected error during authentication check: {str(e)}")
            return Response(
                {"error": "Authentication error", "authenticated": False}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

class LogoutView(APIView):
    """
    Enhanced logout endpoint with proper cleanup
    """
    
    def post(self, request):
        try:
            # Get token from cookie to identify user for logging
            token = request.COOKIES.get('access_token')
            username = "unknown"
            
            if token:
                try:
                    access_token = AccessToken(token)
                    user_id = access_token['user_id']
                    user = User.objects.get(id=user_id)
                    username = user.username
                except:
                    pass  # Don't fail logout if token is invalid
            
            # Create response
            response = Response({
                "message": "Logged out successfully",
                "authenticated": False
            })
            
            # Clear the cookies with proper settings
            response.delete_cookie(
                'access_token',
                samesite='Lax'
            )
            response.delete_cookie(
                'refresh_token',
                samesite='Lax'
            )
            
            logger.info(f"User {username} logged out successfully")
            return response
            
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            # Still return success for logout to prevent client-side issues
            response = Response({"message": "Logged out successfully"})
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response


class SyncSaveView(APIView):
    """
    Enhanced data sync save endpoint with validation
    """
    
    def post(self, request):
        # Get token from cookie for authentication
        token = request.COOKIES.get('access_token')
        
        if not token:
            logger.warning("Sync save failed: No authentication token")
            return Response(
                {"error": "Authentication required"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Verify token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Sync save failed: User {user.username} is inactive")
                return Response(
                    {"error": "Account is deactivated"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Get and validate data from request
            key = request.data.get('key')
            data = request.data.get('data')
            
            if not key:
                return Response(
                    {"error": "Key is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate key format
            if not re.match(r'^[a-zA-Z0-9_-]+$', key):
                return Response(
                    {"error": "Key can only contain letters, numbers, underscores, and hyphens"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if len(key) > 100:
                return Response(
                    {"error": "Key must be less than 100 characters"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate data size (limit to 10MB)
            data_size = len(json.dumps(data)) if data else 0
            if data_size > 10 * 1024 * 1024:  # 10MB limit
                return Response(
                    {"error": "Data size exceeds 10MB limit"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Save to file system
            sync_data_path = os.path.join(settings.BASE_DIR, 'sync_data', f'user_{user_id}')
            os.makedirs(sync_data_path, exist_ok=True)
            
            file_path = os.path.join(sync_data_path, f'{key}.json')
            
            # Create backup if file exists
            if os.path.exists(file_path):
                backup_path = f"{file_path}.backup"
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                os.rename(file_path, backup_path)
            
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                logger.info(f"Data synced successfully for user {user.username}, key: {key}")
                return Response({"message": "Data synced successfully"})
                
            except Exception as write_error:
                # Restore backup if write failed
                backup_path = f"{file_path}.backup"
                if os.path.exists(backup_path):
                    os.rename(backup_path, file_path)
                raise write_error
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Sync save failed: Invalid token - {str(e)}")
            return Response(
                {"error": "Invalid or expired token"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            logger.warning("Sync save failed: User not found")
            return Response(
                {"error": "User not found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            logger.error(f"Unexpected error during sync save: {str(e)}")
            return Response(
                {"error": "Sync failed"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SyncGetView(APIView):
    """
    Enhanced data sync get endpoint with validation
    """
    
    def get(self, request, key):
        # Get token from cookie for authentication
        token = request.COOKIES.get('access_token')
        
        if not token:
            logger.warning("Sync get failed: No authentication token")
            return Response(
                {"error": "Authentication required"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Verify token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Sync get failed: User {user.username} is inactive")
                return Response(
                    {"error": "Account is deactivated"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Validate key format
            if not key or not re.match(r'^[a-zA-Z0-9_-]+$', key):
                return Response(
                    {"error": "Invalid key format"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get data from file
            file_path = os.path.join(settings.BASE_DIR, 'sync_data', f'user_{user_id}', f'{key}.json')
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    logger.info(f"Data retrieved successfully for user {user.username}, key: {key}")
                    return Response(data)
                    
                except json.JSONDecodeError:
                    logger.error(f"Corrupted data file for user {user.username}, key: {key}")
                    return Response(
                        {"error": "Data file is corrupted"}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                except Exception as read_error:
                    logger.error(f"Error reading data file: {str(read_error)}")
                    return Response(
                        {"error": "Failed to read data"}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            else:
                logger.warning(f"Data not found for user {user.username}, key: {key}")
                return Response(
                    {"error": "Data not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Sync get failed: Invalid token - {str(e)}")
            return Response(
                {"error": "Invalid or expired token"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            logger.warning("Sync get failed: User not found")
            return Response(
                {"error": "User not found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            logger.error(f"Unexpected error during sync get: {str(e)}")
            return Response(
                {"error": "Fetch failed"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class SyncDeleteView(APIView):
    """
    Enhanced data sync delete endpoint with validation
    """
    
    def post(self, request):
        # Get token from cookie for authentication
        token = request.COOKIES.get('access_token')
        
        if not token:
            logger.warning("Sync delete failed: No authentication token")
            return Response(
                {"error": "Authentication required"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Verify token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Sync delete failed: User {user.username} is inactive")
                return Response(
                    {"error": "Account is deactivated"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Get key from request
            key = request.data.get('key')
            
            if not key:
                return Response(
                    {"error": "Key is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate key format
            if not re.match(r'^[a-zA-Z0-9_-]+$', key):
                return Response(
                    {"error": "Invalid key format"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Delete file
            file_path = os.path.join(settings.BASE_DIR, 'sync_data', f'user_{user_id}', f'{key}.json')
            
            if os.path.exists(file_path):
                try:
                    # Create backup before deletion
                    backup_path = f"{file_path}.deleted_{int(time.time())}"
                    os.rename(file_path, backup_path)
                    
                    logger.info(f"Data deleted successfully for user {user.username}, key: {key}")
                    return Response({"message": "Data deleted successfully"})
                    
                except Exception as delete_error:
                    logger.error(f"Error deleting data file: {str(delete_error)}")
                    return Response(
                        {"error": "Failed to delete data"}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            else:
                logger.warning(f"Data not found for deletion - user {user.username}, key: {key}")
                return Response(
                    {"error": "Data not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
        except (InvalidToken, TokenError) as e:
            logger.warning(f"Sync delete failed: Invalid token - {str(e)}")
            return Response(
                {"error": "Invalid or expired token"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            logger.warning("Sync delete failed: User not found")
            return Response(
                {"error": "User not found"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            logger.error(f"Unexpected error during sync delete: {str(e)}")
            return Response(
                {"error": "Delete failed"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ProfilePageView(View):
    """
    Protected profile page that requires authentication
    """
    def get(self, request):
        # Check if user is authenticated via cookie
        token = request.COOKIES.get('access_token')
        
        if not token:
            # Redirect to login if no token
            return redirect('/auth/login/')
        
        try:
            # Verify the token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            
            # Get user and check if active
            user = User.objects.get(id=user_id)
            if not user.is_active:
                # Redirect to login if user is inactive
                return redirect('/auth/login/')
            
            # User is authenticated, serve the profile page
            frontend_path = os.path.join(settings.BASE_DIR.parent, 'frontend', 'profile.html')
            
            try:
                with open(frontend_path, 'r', encoding='utf-8') as file:
                    html_content = file.read()
                return HttpResponse(html_content, content_type='text/html')
            except FileNotFoundError:
                return HttpResponse("Profile page not found", status=404)
                
        except (InvalidToken, TokenError):
            # Invalid token, redirect to login
            return redirect('/auth/login/')
        except User.DoesNotExist:
            # User not found, redirect to login
            return redirect('/auth/login/')
        except Exception as e:
            logger.error(f"Unexpected error in profile view: {str(e)}")
            return redirect('/auth/login/')
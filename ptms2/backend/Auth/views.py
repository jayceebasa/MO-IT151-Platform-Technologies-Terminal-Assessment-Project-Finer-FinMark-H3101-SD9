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
class RegisterView(APIView):
    def post(self, request):
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            
            # Basic validation
            if not username or not password:
                return Response(
                    {"error": "Username and password are required."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                return Response(
                    {"error": "Username already exists."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = User.objects.create_user(
                username=username,
                password=password
            )
            return Response(
                {"message": "User created successfully."}, 
                status=status.HTTP_201_CREATED
            )
            
        except IntegrityError:
            return Response(
                {"error": "Username already exists."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": "An error occurred during registration."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoginView(APIView):
    def post(self, request):
        try:
            username = request.data.get("username")
            password = request.data.get("password")
            
            if not username or not password:
                return Response(
                    {"error": "Username and password are required."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = authenticate(username=username, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                
                # Create response
                response = JsonResponse({
                    "message": "Login successful",
                    "user": {"username": user.username}
                })
                
                # Set cookies instead of returning tokens in response
                response.set_cookie(
                    'access_token',
                    str(refresh.access_token),
                    max_age=60*60*24,  # 24 hours
                    httponly=True,     # Can't be accessed by JavaScript
                    secure=False,      # Set to True in production with HTTPS
                    samesite='Lax'     # CSRF protection
                )
                
                response.set_cookie(
                    'refresh_token',
                    str(refresh),
                    max_age=60*60*24*7,  # 7 days
                    httponly=True,
                    secure=False,
                    samesite='Lax'
                )
                
                return response
            
            return Response(
                {"error": "Invalid credentials"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        except Exception as e:
            return Response(
                {"error": "An error occurred during login."}, 
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

  
class CheckAuthView(APIView):
    def get(self, request):
        # Get token from cookie
        token = request.COOKIES.get('access_token')
        
        if not token:
            return Response({"error": "No authentication token provided"}, status=401)
        
        try:
            # Verify the token
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            
            # Get user
            user = User.objects.get(id=user_id)
            
            return Response({
                "authenticated": True,
                "username": user.username,
                "user_id": user.id
            })
            
        except (InvalidToken, TokenError, User.DoesNotExist) as e:
            return Response({"error": "Invalid or expired token"}, status=401)
        except Exception as e:
            return Response({"error": "Authentication error"}, status=401)

class LogoutView(APIView):
    def post(self, request):
        response = Response({"message": "Logged out successfully"})
        
        # Clear the cookies
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        
        return response

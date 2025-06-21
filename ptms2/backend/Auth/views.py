from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.views import View
from django.http import HttpResponse
import os
from django.conf import settings

# Your existing API views
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
            
            # Basic validation
            if not username or not password:
                return Response(
                    {"error": "Username and password are required."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            user = authenticate(username=username, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "message": "Login successful"
                }, status=status.HTTP_200_OK)
            
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
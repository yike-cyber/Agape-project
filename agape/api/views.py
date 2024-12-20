from django.contrib.auth import login, logout, authenticate
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from django.db.models import Count


from django.db.models import Q
from django.http import HttpResponse
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework import generics, permissions
from rest_framework.exceptions import NotFound, AuthenticationFailed
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser

from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.token_blacklist.models import  BlacklistedToken,OutstandingToken

import csv
from io import BytesIO
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from uuid import UUID
import random
from django.utils import timezone
from datetime import datetime
import jwt
from django.core.cache import cache
from .models import User,Warrant,DisabilityRecord
from .serializers import UserSerializer,WarrantSerializer,DisabilityRecordSerializer, RegisterSerializer, LoginSerializer, ResetPasswordSerializer, SetNewPasswordSerializer
from .utils import send_email
from .constants import SUCCESS_RESPONSE, ERROR_RESPONSE
from .pagination import CustomPagination



class CurrentUserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        print('user',user_id)
        try:
            profile = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'Profile not found.'}, status=404)

        serializer = UserSerializer(profile)
        return Response(serializer.data)

class RegisterView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role != 'admin':
            response_data = ERROR_RESPONSE.copy()
            response_data["message"] = "You are not authorized to create users."
            response_data["error_code"] = 403
            return Response(response_data, status=status.HTTP_403_FORBIDDEN)

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode())
            current_domain = request.get_host()
            verification_link = f'http://{current_domain}/api/auth/email-verify/?uid={uid}&token={token}'

            subject = 'Email Verification for Agape'
            message = f'Click the link to verify your email: {verification_link}'
            recipient_list = [user.email]
            send_email(subject, message, recipient_list)

            response_data = SUCCESS_RESPONSE.copy()
            response_data["message"] = "User created successfully. Please verify the email."
            response_data["data"] = {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role,
            }
            return Response(response_data, status=status.HTTP_201_CREATED)

        response_data = ERROR_RESPONSE.copy()
        response_data["message"] = "Bad request. Please check the provided data."
        response_data["error_code"] = 400
        response_data["errors"] = serializer.errors
        return Response(response_data, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def get(self, request):
        uidb64 = request.GET.get('uid')
        token = request.GET.get('token')

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            html_content = render_to_string('email_verification_failed.html', {
                "message": "Invalid or expired token.",
            })
            return HttpResponse(html_content, status=400, content_type="text/html")

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()

            html_content = render_to_string('email_verification_success.html', {
                "message": "Email verified successfully!",
                "user": user,
            })
            return HttpResponse(html_content, status=200, content_type="text/html")

        html_content = render_to_string('email_verification_failed.html', {
            "message": "Invalid or expired token.",
        })
        return HttpResponse(html_content, status=400, content_type="text/html")

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)
            print('user',user)

            if user:
                refresh = RefreshToken.for_user(user)
                success_response["message"] = "Login successful."
                success_response["data"] = {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }
                return Response(success_response, status=status.HTTP_200_OK)
            else:
                error_response["message"] = "Invalid credentials."
                error_response["error_code"] = "invalid_credentials"
                return Response(error_response, status=status.HTTP_401_UNAUTHORIZED)

        error_response["message"] = "Invalid data provided."
        error_response["errors"] = serializer.errors
        return Response(error_response, status=status.HTTP_400_BAD_REQUEST)
    
class ResetPasswordView(APIView):
    def post(self, request):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        # Validate input data
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                error_response["message"] = "Email not found."
                error_response["error_code"] = "email_not_found"
                return Response(error_response, status=status.HTTP_404_NOT_FOUND)

            otp = str(random.randint(100000, 999999))  

            cache.set(f"reset_password_otp_{email}", otp, timeout=300)

            send_email(
                'Password Reset OTP',
                f'Your password reset OTP is: {otp} It will expire after 5 minutes.',
                [email]
            )
            print('OTP sent successfully!')

            # Prepare success response
            success_response["message"] = "OTP sent to your email."
            return Response(success_response, status=status.HTTP_200_OK)

        # Invalid data from serializer
        error_response["message"] = "Invalid data provided."
        error_response["errors"] = serializer.errors
        return Response(error_response, status=status.HTTP_400_BAD_REQUEST)  



class VerifyOTPView(APIView):
    def post(self, request):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            error_response["message"] = "Email and OTP are required."
            error_response["error_code"] = "missing_parameters"
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the OTP from the cache using the email as the key
        cached_otp = cache.get(f"reset_password_otp_{email}")

        if not cached_otp:
            error_response["message"] = "OTP expired or not generated."
            error_response["error_code"] = "otp_not_found"
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

        # Validate OTP
        if cached_otp == otp:
            success_response["message"] = "OTP verified successfully."
            return Response(success_response, status=status.HTTP_200_OK)
        else:
            error_response["message"] = "Invalid OTP."
            error_response["error_code"] = "invalid_otp"
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)    


class SetNewPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        serializer = SetNewPasswordSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            new_password = serializer.validated_data.get("password")

            try:
                user = User.objects.get(email=email)
                user.set_password(new_password)
                user.save()

                success_response["message"] = "Password updated successfully."
                return Response(success_response, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                error_response["message"] = "User with the provided email does not exist."
                error_response["error_code"] = "user_not_found"
                return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        error_response["message"] = "Invalid data provided."
        error_response["error_code"] = "invalid_data"
        error_response["errors"] = serializer.errors
        return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

class UserUpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_object(self):
        try:
            return User.objects.get(id=self.kwargs[self.lookup_field])
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        if request.user != user and request.user.role != 'admin' and request.user.is_superuser == False:
            raise AuthenticationFailed("You are not authorized to update this password.")

        old_password = request.data.get('old_password')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        
        if password != password2:
            return Response({
                "message": "Passwords do not match."
            }, status=status.HTTP_400_BAD_REQUEST)
         
        if not check_password(old_password,user.password):
            return Response({
                "message":"yor old password is not correct"
            },status = status.HTTP_400_BAD_REQUEST)
        user.set_password(password)
        user.save()
        
        return Response({
            "message": "Password updated successfully."
        }, status=status.HTTP_200_OK)
        
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        try:
            tokens = OutstandingToken.objects.filter(user_id=request.user.id)
            if not tokens.exists():
                error_response["message"] = "No active sessions found."
                error_response["error_code"] = "no_active_sessions"
                return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

            for token in tokens:
                BlacklistedToken.objects.get_or_create(token=token)
            success_response["message"] = "Logged out successfully."
            return Response(success_response, status=status.HTTP_205_RESET_CONTENT)

        except Exception as e:
            error_response["message"] = "An error occurred while logging out."
            error_response["error_code"] = "logout_error"
            error_response["errors"] = str(e)
            return Response(error_response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        
        if self.request.user.is_superuser:
             queryset = self.queryset.filter(is_active=True)
        else:
            queryset = self.queryset.filter(is_active=True,is_superuser=False)
            
        search_term = self.request.query_params.get('search', None)
        if search_term:
            filters = Q(
                Q(email__icontains=search_term) |
                Q(gender__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(middle_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(phone_number__icontains=search_term) |
                Q(role__icontains=search_term)
            )
            queryset = queryset.filter(filters)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset().exclude(id=request.user.id)
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        if not queryset.exists():
            response = ERROR_RESPONSE.copy()
            response.update({
                "message": "No users found matching found.",
                "error_code": "USER_NOT_FOUND"
            })
            return Response(response, status=status.HTTP_404_NOT_FOUND)
        
        elif paginated_queryset is not None:
            serializer = self.get_serializer(paginated_queryset, many=True)

            response = SUCCESS_RESPONSE.copy()
            response.update({
                "message": "Users fetched successfully.",
                "data": serializer.data,
                "pagination": {
                    "count": paginator.page.paginator.count,
                    "next": paginator.get_next_link(),
                    "previous": paginator.get_previous_link()
                }
            })
            return paginator.get_paginated_response(response)
    
        else:
            serializer = self.get_serializer(queryset,many=True)
            return Response({
                "message":"Users fetched successfully",
                "data":serializer.data
            },status = status.HTTP_200_OK)
            

    def create(self, request, *args, **kwargs):
        if request.user.role =='admin':
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                response = SUCCESS_RESPONSE.copy()
                response.update({
                    "message": "User created successfully.",
                    "data": serializer.data
                })
                return Response(response, status=status.HTTP_201_CREATED)

            response = ERROR_RESPONSE.copy()
            response.update({
                "message": "User creation failed.",
                "error_code": "VALIDATION_ERROR",
                "errors": serializer.errors
            })
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                "error_code":"FORBIDDEN",
                "message":"Only admin can register user."
            }, 
            status = status.HTTP_403_FORBIDDEN
             )

#update and access user detail
class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

    def get_object(self):
        user_id = self.kwargs.get(self.lookup_field)
        try:
            user = self.queryset.get(id=user_id)
            if not user.is_active:
                raise NotFound(detail="User is deactivated and can't be accessed.")
            return user
        except User.DoesNotExist:
            error_response = {
                "status": "error",
                "message": "User not found."
            }
            raise NotFound(detail=error_response)

    def update(self, request, *args, **kwargs):

        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            
            return Response( {
            "message": "User updated successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
        else:
            return Response({
            "status": "error",
            "message": "Validation error.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class BlockedUserListView(generics.ListAPIView):
    queryset = User.objects.filter(is_active=False, is_superuser=False) 
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({
                "message": "No blocked users found.",
                "data": []
            }, status=status.HTTP_200_OK)

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "message": "Blocked users retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    
class UserBlockView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_object(self):
        try:
            return User.objects.get(id=self.kwargs[self.lookup_field])
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")
    
    def patch(self, request, *args, **kwargs):
        if request.user.role == 'admin' or request.user.is_superuser:
            user = self.get_object()
            user.is_active = not user.is_active
            user.save()

            action = "unblocked" if user.is_active else "blocked"
            return Response({
                "message": f"User {action} successfully."
            }, status=status.HTTP_200_OK)

        return Response({
            "message": "You are not allowed to perform this action."
        }, status=status.HTTP_403_FORBIDDEN)

class DeleteUserPermanentlyView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = 'id'

    def get_object(self):
        try:
            user = None
            if self.request.user.is_superuser:
                user =self.get_queryset().get(id = self.kwargs[self.lookup_field])
            else:
                 user = self.get_queryset().get(id = self.kwargs[self.lookup_field], is_superuser = False)
            return user
        except User.DoesNotExist:
            raise NotFound(detail = 'user not found')
    
    def delete(self,request,*args,**kwargs):
        if request.user.role=='admin':
            user = self.get_object()
            user.delete()
            return Response({
                "message":"user deleted Permanently." },
                status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({
                "message": "You are not allowed to perform this action."
            }, status=status.HTTP_403_FORBIDDEN)

#filtering users
class UserFilterView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        query = self.request.query_params.get('search', '')
        role = self.request.query_params.get('role')
        queryset = User.objects.all()

        if role:
            queryset = queryset.filter(role__icontains=role)

        if query:
            queryset = queryset.filter(
                Q(email__icontains=query) |
                Q(gender__icontains=query) |
                Q(first_name__icontains=query) |
                Q(middle_name__icontains=query) |
                Q(last_name__icontains=query) |
                Q(phone_number__icontains=query)
            )

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            error_response = {
                "status": "error",
                "message": "No users found matching the search criteria.",
                "error_code": "USER_NOT_FOUND"
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        paginator = PageNumberPagination()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        serializer = self.get_serializer(paginated_queryset, many=True)

        success_response = {
            "status": "success",
            "message": "Users fetched successfully.",
            "data": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link()
            }
        }
        return paginator.get_paginated_response(success_response)

# create and list warrant
class WarrantListCreateView(generics.ListCreateAPIView):
    queryset = Warrant.objects.all()
    serializer_class = WarrantSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get_queryset(self):
        queryset = self.queryset.filter(deleted=False)
        search_term = self.request.query_params.get('search', None)

        if search_term:
            filters = Q(
                Q(gender__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(middle_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(phone_number__icontains=search_term)
            )
            queryset = queryset.filter(filters)

        return queryset.order_by('-first_name')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        if not queryset.exists():
            error_response = {
                "status": "error",
                "message": "No warrants found matching the search criteria.",
                "error_code": "WARRANT_NOT_FOUND"
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        if paginated_queryset is not None:
            serializer = self.get_serializer(paginated_queryset, many=True)
            return paginator.get_paginated_response({
                "status": "success",
                "message": "Warrants fetched successfully.",
                "data": serializer.data,
                "pagination": {
                    "count": paginator.page.paginator.count,
                    "next": paginator.get_next_link(),
                    "previous": paginator.get_previous_link(),
                },
            })

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "status": "success",
            "message": "Warrants fetched successfully.",
            "data": serializer.data,
            "pagination": None,
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            success_response = {
                "status": "success",
                "message": "Warrant created successfully.",
                "data": serializer.data
            }
            return Response(success_response, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({
                "status": "error",
                "message": str(e),
                "error_code": "VALIDATION_ERROR"
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "error",
                "message": "Internal Server Error: " + str(e),
                "error_code": "INTERNAL_SERVER_ERROR"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
# Retrieve, Update, and Delete Warrant
class WarrantDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Warrant.objects.all()
    serializer_class = WarrantSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)

            success_response = {
                "message": "Warrant retrieved successfully.",
                "data": serializer.data
            }
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = {
                "message": "Warrant not found.",
                "error_code": "WARRANT_NOT_FOUND"
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            success_response = {
                "message": "Warrant updated successfully.",
                "data": serializer.data
            }
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = {
                "status": "error",
                "message": "Warrant not found."
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.deleted = True  
            instance.save()

            success_response = {
                "message": "Warrant deleted successfully."
            }
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = {
                "message": "Warrant not found."
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

# List and Create Disability Records
class DisabilityRecordListCreateView(generics.ListCreateAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    pagination_class = CustomPagination

    def get_queryset(self):
        queryset = self.queryset.filter(deleted=False)
        search_term = self.request.query_params.get('search', None)

        if search_term:
            filters = Q(
                Q(gender__contains=search_term) |
                Q(phone_number__contains=search_term) |
                Q(region__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(middle_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(city__icontains=search_term) |
                Q(zone__icontains=search_term) |
                Q(woreda__icontains=search_term) 
                
            )
            queryset = queryset.filter(filters)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({
                "status": "success",
                "message": "No disability records found.",
                "data": [],
                "pagination": {
                    "count": 0,
                    "next": None,
                    "previous": None
                }
            }, status=status.HTTP_200_OK)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        if paginated_queryset is None:
            serializer = self.get_serializer(queryset, many=True)
            success_response = {
                "status": "success",
                "message": "Disability records fetched successfully.",
                "data": serializer.data,
                "pagination": {
                    "count": len(queryset),
                    "next": None,
                    "previous": None
                }
            }
            return Response(success_response, status=status.HTTP_200_OK)

        serializer = self.get_serializer(paginated_queryset, many=True)
        success_response = {
            "status": "success",
            "message": "Disability records fetched successfully.",
            "data": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link()
            }
        }
        return paginator.get_paginated_response(success_response)
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data,partial = True)
        if serializer.is_valid():
            disability_record = serializer.save(recorder=request.user)
            return Response({
                "status": "success",
                "message": "Disability record created successfully.",
                "data": self.get_serializer(disability_record).data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            "status": "error",
            "message": "Validation failed.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

# Retrieve, Update, and Delete Disability Record
class DisabilityRecordDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

    def get_object(self):
        disability_id = self.kwargs.get(self.lookup_field)
        try:
            disability = self.queryset.get(id=disability_id)
            if disability.deleted:
                raise NotFound(detail="Disability is deactivated and cannot be accessed.")
            return disability
        except DisabilityRecord.DoesNotExist:
            raise NotFound(detail="Disability not found.")

    def delete(self, request, *args, **kwargs):
        disability = self.get_object()
        disability.deleted = True
        disability.save()

        success_response = SUCCESS_RESPONSE.copy()
        success_response["message"] = "Disability record deactivated successfully."
        return Response(success_response, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        disability = self.get_object()
        serializer = self.get_serializer(disability, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        success_response = SUCCESS_RESPONSE.copy()
        success_response["message"] = "Disability record updated successfully."
        success_response["data"] = serializer.data
        return Response(success_response, status=status.HTTP_200_OK)
        
# Filter Disability Records

class DisabilityRecordListFilterView(generics.ListAPIView):
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = DisabilityRecord.objects.all()
        gender = self.request.query_params.get('gender')
        is_provided = self.request.query_params.get('is_provided')
        regions = self.request.query_params.get('regions',[])
        equipment_types = self.request.query_params.get('equipment_types',[])
        month = self.request.query_params.get('month')
        year = self.request.query_params.get('year')
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        

        # Filter by gender if provided
        if gender:
            queryset = queryset.filter(gender__iexact=gender)
            
        if is_provided:
            queryset = queryset.filter(is_provided=is_provided)

        if regions:
            regions = regions.split(',')
            queryset = queryset.filter(region__in=regions)
        
        if equipment_types:
            equipment_types = equipment_types.split(',')
            queryset = queryset.filter(equipment__equipment_type__in=equipment_types)

        if year:
            try:
                month = int(month)
                year = int(year)
                queryset = queryset.filter(created_at__year=year)
            except ValueError:
                pass
        if month:
            try:
                month = int(month)
                queryset = queryset.filter(created_at__month=month)
            except ValueError:
                pass


        if start_date:
            print('start date',start_date)
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
                queryset = queryset.filter(created_at__gte=start_date)
                print('query set',queryset)
            except ValueError:
                print('value error')
                pass  

        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                end_date = timezone.make_aware(datetime.combine(end_date, datetime.min.time()))
                queryset = queryset.filter(created_at__lte=end_date)
            except ValueError:
                print('value error here')
                pass  

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        filter_values = {key: value for key, value in request.query_params.items()}

        if not queryset.exists():
            error_response = {
                "status": "error",
                "message": "No disability records found matching the search criteria.",
                "filter_values":filter_values
            }
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(queryset, many=True)

        success_response = {
            "status": "success",
            "message": "Disability records retrieved successfully.",
            "filters": filter_values, 
            "number_of_records": len(queryset),
            "data": serializer.data
        }
        return Response(success_response, status=status.HTTP_200_OK)


class FileExportView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    # Define the field aliases
    field_aliases = {
        'first_name': 'First Name',
        'middle_name': 'Middle Name',
        'last_name': 'Last Name',
        'gender': 'Gender',
        'phone_number': 'Phone Number',
        'date_of_birth': 'Date of Birth',
        'region': 'Region',
        'zone': 'Zone',
        'city': 'City',
        'woreda': 'Woreda',
        'created_at': 'Created At',
        'equipment__equipment_type': 'Equipment Type',  # For nested fields
    }

    def post(self, request):
        filters = request.data.get("filters", {})
        file_format = request.data.get("format", "excel") 
        columns = request.data.get("columns", [])
        
        if isinstance(columns, str):
            columns = columns.split(',')

        if not columns:
            columns = ["first_name","middle_name","last_name","gender","phone_number","date_of_birth","region","zone","city","woreda","created_at","equipment__equipment_type"]

        queryset = self.filter_queryset(filters)
        if not queryset.exists():
            return Response({"error": "No records found for the provided filters"}, status=status.HTTP_404_NOT_FOUND)

        # Map columns to their aliases
        columns_with_aliases = [self.field_aliases.get(col, col) for col in columns]
        data = list(queryset.values(*columns))

        # Generate the appropriate file format
        if file_format == "csv":
            return self.generate_csv(data, columns_with_aliases)
        elif file_format == "excel":
            return self.generate_excel(data, columns_with_aliases)
        elif file_format == "pdf":
            return self.generate_pdf(data, columns_with_aliases)
        else:
            return Response({"error": "Unsupported file format"}, status=status.HTTP_400_BAD_REQUEST)

    def filter_queryset(self, filters):
        queryset = DisabilityRecord.objects.all()

        gender = filters.get('gender')
        regions = filters.get('regions')
        is_provided = filters.get('is_provided')
        equipment_types = filters.get('equipment_types')
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')

        if is_provided:
            queryset = queryset.filter(is_provided=is_provided)
            
        if gender:
            queryset = queryset.filter(gender__iexact=gender)

        if regions:
            regions = regions.split(',')
            queryset = queryset.filter(region__in=regions)

        if equipment_types:
            equipment_types = equipment_types.split(',')
            queryset = queryset.filter(equipment__equipment_type__in=equipment_types)

        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
                queryset = queryset.filter(created_at__gte=start_date)
            except ValueError:
                pass

        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                end_date = timezone.make_aware(datetime.combine(end_date, datetime.min.time()))
                queryset = queryset.filter(created_at__lte=end_date)
            except ValueError:
                pass

        return queryset

    def generate_csv(self, data, columns_with_aliases):
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="export.csv"'

        writer = csv.DictWriter(response, fieldnames=columns_with_aliases)
        writer.writeheader()

        # Write data to CSV with aliases
        for record in data:
            record_with_aliases = {}
            for key, value in record.items():
                alias = self.field_aliases.get(key, key)  # Get alias, default to original key if no alias
                record_with_aliases[alias] = value
            writer.writerow(record_with_aliases)
        
        return response

    def generate_excel(self, data, columns_with_aliases):
        df = pd.DataFrame(data, columns=columns_with_aliases)
        
        # Convert timezone-aware datetime fields to timezone-unaware for specific columns
        if 'created_at' in df.columns:
            df['created_at'] = df['created_at'].dt.tz_localize(None)
        if 'updated_at' in df.columns:
            df['updated_at'] = df['updated_at'].dt.tz_localize(None)

        # Prepare Excel file in memory
        output = BytesIO()
        df.to_excel(output, index=False)

        # Create response with the correct content type
        response = HttpResponse(
            output.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = 'attachment; filename="export.xlsx"'
    
        return response

    def generate_pdf(self, data, columns_with_aliases):
        # Create a PDF response
        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="export.pdf"'

        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)

        x = 50
        y = 750
        pdf.drawString(x, y, "Exported Data")
        y -= 20
        for record in data:
            line = ", ".join([f"{col}: {record.get(col, '')}" for col in columns_with_aliases])
            pdf.drawString(x, y, line)
            y -= 20
            if y < 50:  
                pdf.showPage()
                y = 750

        pdf.save()
        buffer.seek(0)

        response.write(buffer.getvalue())
        buffer.close()

        return response    

class DisabilityUserStatsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        dis_queryset = DisabilityRecord.objects.all()
        total_records = dis_queryset.count()
        num_of_males = dis_queryset.filter(gender="male").count()
        num_of_females = dis_queryset.filter(gender="female").count()
        approved_records = dis_queryset.filter(is_provided=True).count()
        unapproved_records = dis_queryset.filter(is_provided=False).count()
        num_of_pediatric_wheelchair = dis_queryset.filter(equipment__equipment_type="pediatric_wheelchair").count()
        num_of_american_wheelchair = dis_queryset.filter(equipment__equipment_type="american_wheelchair").count()
        num_of_FWP_wheelchair = dis_queryset.filter(equipment__equipment_type="FWP_wheelchair").count()
        num_of_walker = dis_queryset.filter(equipment__equipment_type="walker").count()
        num_of_crutch = dis_queryset.filter(equipment__equipment_type="crutch").count()
        num_of_cane = dis_queryset.filter(equipment__equipment_type="cane").count()
        region_stats = dis_queryset.values('region').annotate(count=Count('region'))
        region_data = [{"region": region["region"], "count": region["count"]} for region in region_stats]
        
        
        user_queryset = User.objects.all()
        total_users = user_queryset.count()
        admins = user_queryset.filter(role="admin").count()
        active_admins = user_queryset.filter(role="admin", is_active=True).count()
        blocked_admins = user_queryset.filter(role="admin", is_active=False).count()
        sub_admins = user_queryset.filter(role="field_worker").count()
        active_sub_admins = user_queryset.filter(role="field_worker", is_active=True).count()
        blocked_sub_admins = user_queryset.filter(role="field_worker", is_active=False).count()
        
        
        
        return Response(
                         {
                         "disability":{
                         "total_records": total_records, 
                         "num_of_males": num_of_males,
                         "num_of_females": num_of_females,
                         "approved_records": approved_records,
                         "unapproved_records": unapproved_records,
                         "equipments":{
                         "num_of_aediatric_wheelchair": num_of_pediatric_wheelchair,
                         "num_of-american_wheelchair": num_of_american_wheelchair,
                         "num_of_FWP_wheelchair": num_of_FWP_wheelchair,
                         "num_of_walker": num_of_walker,
                         "num_of_crutch": num_of_crutch,
                         "num_of_cane": num_of_cane
                         },
                         "region_data": region_data
                         },
                         
                         "users":{
                         "total_users": total_users, 
                         "admins": admins,
                         "active_admins": active_admins, 
                         "blocked_admins": blocked_admins,
                         "sub_admins": sub_admins,
                         "active_sub_admins": active_sub_admins,
                         "blocked_sub_admins": blocked_sub_admins}
                         
                         },status = status.HTTP_200_OK)
                         
                         



from django.contrib.auth import login, logout, authenticate
from django.template.loader import render_to_string
from django.db.models import Q
from django.http import HttpResponse
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework import generics, permissions
from rest_framework.exceptions import NotFound
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.token_blacklist.models import  BlacklistedToken,OutstandingToken

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


class RegisterView(APIView):
    permission_classes = [IsAuthenticated] 

    def post(self, request):
        if not request.user.is_superuser and request.user.role != 'Admin':
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

            # Success response
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

            otp = str(random.randint(100000, 999999))  # 6-digit OTP

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
        # Prepare success and error response templates
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        # Retrieve email and OTP from request
        email = request.data.get('email')
        otp = request.data.get('otp')

        # Check if both email and OTP are provided
        if not email or not otp:
            error_response["message"] = "Email and OTP are required."
            error_response["error_code"] = "missing_parameters"
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the OTP from the cache using the email as the key
        cached_otp = cache.get(f"reset_password_otp_{email}")

        # Check if the OTP exists in cache (expired or not generated)
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
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def post(self, request):
        # Prepare success and error response templates
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        # Validate input data
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid():
            # Get the access token from the request headers
            access_token = request.headers.get('Authorization', '').split(' ')[-1]

            if not access_token:
                error_response["message"] = "Access token is missing."
                error_response["error_code"] = "missing_token"
                return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Decode and validate the access token
                decoded_token = AccessToken(access_token)  # This will decode and validate the token

                # Get the user ID from the decoded token
                user_id = decoded_token['user_id']  # This is a UUID string

                # Convert user_id to UUID type and ensure it's valid
                user_id = UUID(user_id)  # Ensure we are using the UUID type to query

                # Get the user object using the extracted user ID
                user = User.objects.get(id=user_id)
                
            except (ValueError, TypeError, ObjectDoesNotExist) as e:
                error_response["message"] = "Invalid or expired token."
                error_response["error_code"] = "invalid_token"
                return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            new_password = serializer.validated_data['password']
            user.set_password(new_password)
            user.save()

            success_response["message"] = "Password updated successfully."
            return Response(success_response, status=status.HTTP_200_OK)

        # If serializer is invalid, return the error response
        error_response["message"] = "Invalid data provided."
        error_response["error_code"] = "invalid_data"
        error_response["errors"] = serializer.errors
        return Response(error_response, status=status.HTTP_400_BAD_REQUEST)
    


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Prepare success and error response templates
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        try:
            # Retrieve all outstanding tokens for the current user
            tokens = OutstandingToken.objects.filter(user_id=request.user.id)
            
            if not tokens.exists():
                error_response["message"] = "No active sessions found."
                error_response["error_code"] = "no_active_sessions"
                return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist each token (create if not already blacklisted)
            for token in tokens:
                BlacklistedToken.objects.get_or_create(token=token)

            success_response["message"] = "Logged out successfully."
            return Response(success_response, status=status.HTTP_205_RESET_CONTENT)

        except Exception as e:
            # If an unexpected error occurs, return a general error response
            error_response["message"] = "An error occurred while logging out."
            error_response["error_code"] = "logout_error"
            error_response["errors"] = str(e)
            return Response(error_response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = self.queryset

        search_term = self.request.query_params.get('search', None)
        print('search term',search_term)
        if search_term:
            filters = Q(
                Q(email__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(middle_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(phone_number__icontains=search_term) |
                Q(role__icontains=search_term)
            )
            queryset = queryset.filter(filters)

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = PageNumberPagination()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        # Checking if the paginated queryset is empty
        if not paginated_queryset:
            response = ERROR_RESPONSE.copy()
            response.update({
                "message": "No users found matching the search criteria.",
                "error_code": "USER_NOT_FOUND"
            })
            return Response(response, status=status.HTTP_404_NOT_FOUND)

        # Serialize the paginated data
        serializer = self.get_serializer(paginated_queryset, many=True)

        # Build the successful response
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

        # Return paginated response
        return paginator.get_paginated_response(response)

    def create(self, request, *args, **kwargs):
        # Handling user creation
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response = SUCCESS_RESPONSE.copy()
            response.update({
                "message": "User created successfully.",
                "data": serializer.data
            })
            return Response(response, status=status.HTTP_201_CREATED)

        # Return validation errors if the creation failed
        response = ERROR_RESPONSE.copy()
        response.update({
            "message": "User creation failed.",
            "error_code": "VALIDATION_ERROR",
            "errors": serializer.errors
        })
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

    def get_object(self):
        user_id = self.kwargs.get(self.lookup_field)
        try:
            user = self.queryset.get(id=user_id)
            if not user.is_active:
                raise NotFound(detail="User is deactivated and cannot be accessed.")
            return user
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

    def delete(self, request, *args, **kwargs):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        user = self.get_object()
        user.is_active = False  # Deactivate user
        user.save()

        success_response["message"] = "User deactivated successfully."
        return Response(success_response, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        success_response = SUCCESS_RESPONSE.copy()
        error_response = ERROR_RESPONSE.copy()

        partial = kwargs.pop('partial', False)
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=partial)

        if serializer.is_valid():
            self.perform_update(serializer)
            success_response["message"] = "User updated successfully."
            success_response["data"] = serializer.data
            return Response(success_response, status=status.HTTP_200_OK)
        else:
            error_response["message"] = "Validation error."
            error_response["errors"] = serializer.errors
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)


# for filtering users
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
            error_response = ERROR_RESPONSE.copy()
            error_response.update({
                "message": "No users found matching the search criteria.",
                "error_code": "USER_NOT_FOUND"
            })
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        paginator = PageNumberPagination()
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        serializer = self.get_serializer(paginated_queryset, many=True)

        success_response = SUCCESS_RESPONSE.copy()
        success_response.update({
            "message": "Users fetched successfully.",
            "data": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link()
            }
        })
        return paginator.get_paginated_response(success_response)
    
# List of warrents

class WarrantListCreateView(generics.ListCreateAPIView):
    queryset = Warrant.objects.all()
    serializer_class = WarrantSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = self.queryset
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

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        print('queryset,',queryset)
        paginator = PageNumberPagination()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        if not paginated_queryset:
            response = ERROR_RESPONSE.copy()
            response.update({
                "message": "No warrants found matching the search criteria.",
                "error_code": "WARRANT_NOT_FOUND"
            })
            return Response(response, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(paginated_queryset, many=True)

        success_response = SUCCESS_RESPONSE.copy()
        success_response.update({
            "message": "Warrants fetched successfully.",
            "data": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link()
            }
        })
        return paginator.get_paginated_response(success_response)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        success_response = SUCCESS_RESPONSE.copy()
        success_response.update({
            "message": "Warrant created successfully.",
            "data": serializer.data
        })
        return Response(success_response, status=status.HTTP_201_CREATED)
    
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

            success_response = SUCCESS_RESPONSE.copy()
            success_response.update({
                "message": "Warrant retrieved successfully.",
                "data": serializer.data
            })
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = ERROR_RESPONSE.copy()
            error_response.update({
                "message": "Warrant not found.",
                "error_code": "WARRANT_NOT_FOUND"
            })
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            success_response = SUCCESS_RESPONSE.copy()
            success_response.update({
                "message": "Warrant updated successfully.",
                "data": serializer.data
            })
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = ERROR_RESPONSE.copy()
            error_response.update({
                "message": "Warrant not found.",
                "error_code": "WARRANT_NOT_FOUND"
            })
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            instance.deleted = True  # Assuming a `deleted` flag for soft delete
            instance.save()

            success_response = SUCCESS_RESPONSE.copy()
            success_response.update({
                "message": "Warrant deleted successfully."
            })
            return Response(success_response, status=status.HTTP_200_OK)
        except Warrant.DoesNotExist:
            error_response = ERROR_RESPONSE.copy()
            error_response.update({
                "message": "Warrant not found.",
                "error_code": "WARRANT_NOT_FOUND"
            })
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

# List and Create Disability Records

class DisabilityRecordListCreateView(generics.ListCreateAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter the queryset based on the search parameter.
        """
        queryset = self.queryset.filter(deleted=False)  # Exclude deleted records
        search_term = self.request.query_params.get('search', None)

        if search_term:
            filters = Q(
                Q(record_id__icontains=search_term) |
                Q(disability_type__icontains=search_term) |
                Q(person_name__icontains=search_term) |
                Q(remarks__icontains=search_term) |
                Q(gender__icontains=search_term) |
                Q(region__icontains=search_term) |
                Q(wheelchair_type__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(middle_name__icontains=search_term) |
                Q(last_name__icontains=search_term) |
                Q(city__icontains=search_term) |
                Q(zone__icontains=search_term) |
                Q(woreda__icontains=search_term) |
                Q(seat_width__icontains=search_term) |
                Q(backrest_height__icontains=search_term) |
                Q(seat_depth__icontains=search_term)
            )
            queryset = queryset.filter(filters)

        return queryset

    def list(self, request, *args, **kwargs):
        """
        Handle listing disability records with pagination.
        """
        queryset = self.get_queryset()
        paginator = PageNumberPagination()
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        if not paginated_queryset:
            error_response = ERROR_RESPONSE.copy()
            error_response["message"] = "No disability records found matching the search criteria."
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(paginated_queryset, many=True)

        success_response = SUCCESS_RESPONSE.copy()
        success_response.update({
            "message": "Disability records fetched successfully.",
            "data": serializer.data,
            "pagination": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link()
            }
        })

        return paginator.get_paginated_response(success_response)

    def create(self, request, *args, **kwargs):
        """
        Handle creating a new disability record.
        """
        serializer = self.get_serializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        success_response = SUCCESS_RESPONSE.copy()
        success_response["message"] = "Disability record created successfully."
        success_response["data"] = serializer.data
        
        return Response(success_response, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        """
        Save the disability record to the database.
        """
        serializer.save()
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
        partial = kwargs.pop('partial', False)
        disability = self.get_object()
        serializer = self.get_serializer(disability, data=request.data, partial=partial)
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
        

        # Get query parameters from the request
        gender = self.request.query_params.get('gender')
        region = self.request.query_params.get('region')
        wheelchair_type = self.request.query_params.get('wheelchair_type')
        month = self.request.query_params.get('month')
        year = self.request.query_params.get('year')
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        # Filter by gender if provided
        if gender:
            queryset = queryset.filter(gender__iexact=gender)

        # Filter by region if provided
        if region:
            queryset = queryset.filter(region__icontains=region)

        # Filter by wheelchair type if provided
        if wheelchair_type:
            queryset = queryset.filter(wheelchair_type__icontains=wheelchair_type)

        # Filter by month and year if provided
        if month and year:
            try:
                month = int(month)
                year = int(year)
                queryset = queryset.filter(date_of_birth__month=month, date_of_birth__year=year)
            except ValueError:
                pass  # Ignore if invalid month/year format

        # Filter by start_date and end_date if provided
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
                queryset = queryset.filter(created_at__gte=start_date)
            except ValueError:
                pass  # Ignore if invalid start_date format

        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                end_date = timezone.make_aware(datetime.combine(end_date, datetime.min.time()))
                queryset = queryset.filter(created_at__lte=end_date)
            except ValueError:
                pass  # Ignore if invalid end_date format

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            # If no records match the filter, return an error response
            error_response = ERROR_RESPONSE.copy()
            error_response["message"] = "No disability records found matching the search criteria."
            return Response(error_response, status=status.HTTP_404_NOT_FOUND)

        # Serialize the data
        serializer = self.get_serializer(queryset, many=True)
        
        # Return success response with the serialized data
        success_response = SUCCESS_RESPONSE.copy()
        success_response["message"] = "Disability records retrieved successfully."
        success_response["data"] = serializer.data
        return Response(success_response, status=status.HTTP_200_OK)



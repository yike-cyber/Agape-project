from django.contrib.auth import login, logout, authenticate
from django.db.models import Q
from rest_framework.permissions import AllowAny,IsAuthenticated
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


class RegisterView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        if not request.user.is_superuser and request.user.role != 'Admin':
            return Response(
                {"error": "You are not authorized to create users."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate token and UID for email verification
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode())

            # Construct the email verification link
            verification_link = f'http://localhost:8000/api/auth/email-verify/?uid={uid}&token={token}'

            # Send email using the decoupled function
            subject = 'Email Verification for Agape'
            message = f'Click the link to verify your email: {verification_link}'
            recipient_list = [user.email]
            send_email(subject, message, recipient_list)

            return Response(
                {"message": "User created successfully. Please verify the email."},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    def get(self, request):
        uidb64 = request.GET.get('uid')
        token = request.GET.get('token')
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)

            if user:
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request):
        # Validate input data
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "Email not found."}, status=status.HTTP_404_NOT_FOUND)

            # Generate OTP
            otp = str(random.randint(100000, 999999))  # 6-digit OTP

            # Store OTP in the cache using email as the key (timeout is 5 minutes)
            cache.set(f"reset_password_otp_{email}", otp, timeout=300)

            # Send OTP via email
            send_email(
                'Password Reset OTP',
                f'Your password reset OTP is: {otp} It will expire after 5 min.' ,
                [email]
            )
            print('OTP sent successfully!')
            return Response({"message": "OTP sent to your email."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve the OTP from the cache using the email as the key
        cached_otp = cache.get(f"reset_password_otp_{email}")

        if not cached_otp:
            return Response({"error": "OTP expired or not generated."}, status=status.HTTP_400_BAD_REQUEST)

        if cached_otp == otp:
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
    


class SetNewPasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def post(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid():
            # Get the access token from the request headers
            access_token = request.headers.get('Authorization', '').split(' ')[-1]

            if not access_token:
                return Response({"error": "Access token is missing."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Decode and validate the access token
                decoded_token = AccessToken(access_token)  # This will decode and validate the token
                
                # Get the user ID from the decoded token
                user_id = decoded_token['user_id']  # This is a UUID string
                
                # Convert user_id to UUID type and ensure it's valid
                user_id = UUID(user_id)  # Ensure we are using the UUID type to query
                
                # Get the user object using the extracted user ID
                user = User.objects.get(id=user_id)
                
            except (Exception, ValueError, TypeError) as e:
                print('exception is',str(e))
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            # Now, set the new password
            new_password = serializer.validated_data['password']
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Retrieve all outstanding tokens for the current user
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            # Blacklist each token (create if not already blacklisted)
            BlacklistedToken.objects.get_or_create(token=token)

        return Response({"message": "Logged out successful."}, status=status.HTTP_205_RESET_CONTENT)

class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]



# Retrieve, Update, and Delete User
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
        user = self.get_object()
        user.is_active = False  
        user.save()
        return Response({"detail": "User deactivated successfully."}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)  
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


#filter users by search param and role
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

        if not queryset.exists():
            raise NotFound(detail="No users found matching the search criteria.")

        return queryset
    
# List of warrents
class WarrantListCreateView(generics.ListCreateAPIView):
    queryset = Warrant.objects.all()
    serializer_class = WarrantSerializer
    permission_classes = [permissions.IsAuthenticated]
    

# Retrieve, Update, and Delete Warrant
class WarrantDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Warrant.objects.all()
    serializer_class = WarrantSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    
    

# List and Create Disability Records
class DisabilityRecordListCreateView(generics.ListCreateAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        try:
           queryset =self.queryset.filter(deleted = False)
           return queryset
        except DisabilityRecord.DoesNotExist:
           raise NotFound(detail="disability not found.")
        
    def perform_create(self, serializer):
        serializer.save()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, partial=True)  
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    
    
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
            if  disability.deleted:
                raise NotFound(detail="disability is deactivated and cannot be accessed.")
            return disability
        except DisabilityRecord.DoesNotExist:
            raise NotFound(detail="disability not found.")

    def delete(self, request, *args, **kwargs):
        disability = self.get_object()
        disability.deleted = True  
        disability.save()
        return Response({"detail": "Disability deleted successfully."}, status=status.HTTP_200_OK)
        
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
                # Parse and make the start_date timezone aware
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
                queryset = queryset.filter(created_at__gte=start_date)
            except ValueError:
                pass  # Ignore if invalid start_date format

        if end_date:
            try:
                # Parse and make the end_date timezone aware
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                end_date = timezone.make_aware(datetime.combine(end_date, datetime.min.time()))
                queryset = queryset.filter(created_at__lte=end_date)
            except ValueError:
                pass  # Ignore if invalid end_date format

        return queryset

class DisabilityRecordSearchView(generics.ListAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = DisabilityRecord.objects.filter(deleted=False)

        # Get the search term from query parameters
        search_term = self.request.query_params.get('search', None)
        if search_term:
            filters = Q()

            # Apply search term to the relevant fields
            filters |= Q(gender__icontains=search_term)
            filters |= Q(region__icontains=search_term)
            filters |= Q(wheelchair_type__icontains=search_term)
            filters |= Q(first_name__icontains=search_term)
            filters |= Q(middle_name__icontains=search_term)
            filters |= Q(last_name__icontains=search_term)
            filters |= Q(city__icontains=search_term)
            filters |= Q(zone__icontains=search_term)
            filters |= Q(woreda__icontains=search_term)
            filters |= Q(seat_width__icontains=search_term)
            filters |= Q(backrest_height__icontains=search_term)
            filters |= Q(seat_depth__icontains=search_term)

            # Apply the filters to the queryset
            queryset = queryset.filter(filters)

        return queryset
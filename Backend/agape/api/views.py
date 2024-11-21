from django.contrib.auth import login, logout, authenticate
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework import generics, permissions
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
        # Step 1: Get the access token from the Authorization header
        access_token = request.headers.get('Authorization', '').split(' ')[-1]

        if not access_token:
            return Response({"error": "Access token is missing."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Step 2: Decode the access token to verify its validity
            decoded_token = AccessToken(access_token)
            user_id = decoded_token['user_id']
            print(f"Logging out user with ID: {user_id}")

            # Step 3: Check if the OutstandingToken exists
            outstanding_token = OutstandingToken.objects.filter(token=access_token).first()

            if not outstanding_token:
                return Response({"error": "Token not found or already expired."}, status=status.HTTP_400_BAD_REQUEST)

            # Step 4: Blacklist the token to invalidate it
            BlacklistedToken.objects.create(token=outstanding_token)

            # Optional: Delete the OutstandingToken after blacklisting
            outstanding_token.delete()

            return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            # Catch any errors, log them for debugging
            print(f"Error during logout: {str(e)}")
            return Response({"error": f"Error during logout: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

# Retrieve, Update, and Delete User
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'id'

# Filter Users by Role
class UserFilterView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        role = self.request.query_params.get('role')
        if role:
            return User.objects.filter(role=role)
        return User.objects.all()



# List and Create Warrants
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
    
    
# Retrieve, Update, and Delete Disability Record
class DisabilityRecordDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = DisabilityRecord.objects.all()
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'

# Filter Disability Records
class DisabilityRecordFilterView(generics.ListAPIView):
    serializer_class = DisabilityRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = DisabilityRecord.objects.all()
        is_provided = self.request.query_params.get('is_provided')
        region = self.request.query_params.get('region')
        recorder = self.request.query_params.get('recorder')

        if is_provided:
            queryset = queryset.filter(is_provided=is_provided.lower() == 'true')
        if region:
            queryset = queryset.filter(region__icontains=region)
        if recorder:
            queryset = queryset.filter(recorder__id=recorder)
        
        return queryset
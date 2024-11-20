from django.contrib.auth import login, logout, authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User,Warrant,DisabilityRecord
from .serializers import UserSerializer,WarrantSerializer,DisabilityRecordSerializer, RegisterSerializer, LoginSerializer, ResetPasswordSerializer, SetNewPasswordSerializer
from .utils import send_email  


class RegisterView(APIView):
    permission_classes = [IsAuthenticated] 

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
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"error": "Email not found."}, status=status.HTTP_404_NOT_FOUND)

            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode())
            reset_link = f'http://localhost:8000/auth/reset-password-confirm/?uid={uid}&token={token}'
            send_email(
                'Password Reset',
                f'Click the link to reset your password: {reset_link}',
                [email]
            )
            return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(APIView):
    def post(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = request.data.get('uid')
            token = request.data.get('token')
            new_password = serializer.validated_data['password']
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)

            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)



# List and Create Users
class UserListCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

# Retrieve, Update, and Delete User
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

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
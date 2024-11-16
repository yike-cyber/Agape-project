from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterUserSerializer
from .utils import send_code_to_user

class RegisterUserView(APIView):
    def post(self, request):
        print('data is',request.data)
        serializer = RegisterUserSerializer(data=request.data,partial = True)
        if serializer.is_valid():
            serializer.save()
            user = serializer.data
            send_code_to_user(user['email'])
            print(user)
            
            return Response({
                'data':user,
                "message": f"hi {user['first_name']} thanks for signing up a passcode has been sent to {user['email']}"
                }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

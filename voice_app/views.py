from django.shortcuts import render
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView,status
from rest_framework.permissions import (
    IsAuthenticated,
    IsAuthenticatedOrReadOnly,AllowAny
)
from django.db.models import Q
from voice_app.serializer import UserSerializer,GoogleAuthSerializer,ChangePasswordSerializer
from django.contrib.auth import authenticate,login as django_login, logout as django_logout
from rest_framework.authtoken.models import Token
from rest_framework import generics




# Create your views here.

#base url append
def baseurl(request):
    """
    Return a BASE_URL template context for the current request.
    """
    if request.is_secure():
        scheme = "https://"
    else:
        scheme = "http://"

    return scheme + request.get_host()



class CustomerView(APIView):
     permission_classes = (AllowAny,)
     def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get("username", None)
            password = request.data.get("password", None)

            if not email or not password:
                return Response({
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Please provide both email and password"
                })
            user = authenticate(username=email, password=password)
            if user is None:
                return Response({
                    "status": status.HTTP_401_UNAUTHORIZED,
                    "message": "Invalid credentials"
                })

            if not user.password:
                return Response({
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Please reset your password"
                })

            django_login(request, user)
            token, created = Token.objects.get_or_create(user=user)

            return Response({
                "status": status.HTTP_200_OK,
                "message": "Successfully logged in",
                "user_id": user.id,
                "token": token.key,
                "base_url": request.build_absolute_uri('/')
            })

        except Exception as e:
            return Response({
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": "An error occurred: {}".format(str(e))
            })



class GoogleLoginView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        email = request.data.get("email", None)
        name = request.data.get("first_name", None)
        
        if email and name:
            user = User.objects.filter(email=email).first() # Fetch user by email
            if user:
                django_login(request, user)
            else:
                serializer = GoogleAuthSerializer(data=request.data)
                if serializer.is_valid(raise_exception=True):
                    user = serializer.save()
                    django_login(request, user)

            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Successfully logged in",
                "user_id": user.id,
                "token": token.key,
                "base_url": baseurl(request),
            })
        else:
            return Response({
                "status": status.HTTP_400_BAD_REQUEST,
                "message": "Please provide both email and first name",
            })


#LogoutView API
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        user_id = request.user.id
        if user_id:
            logged_in_user_id = User.objects.filter(id=user_id).first()
            if logged_in_user_id:
                django_logout(request)
            content = {"status": 200, "message": "LogOut Successfully"}
        else:
            content = {"status": 400, "message": "Invalid token"}

        return Response(content, status=status.HTTP_200_OK)


#change password
class ChangePasswordView(generics.UpdateAPIView):
    
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj
    
    def update(self, request, *args, **kwargs):
            self.object = self.get_object()
            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid():
                # Check old password
                if not self.object.check_password(serializer.data.get("old_password")):
                    return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
                # set_password also hashes the password that the user will get
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                response = {
                    'status': 'success',
                    'code': status.HTTP_200_OK,
                    'message': 'Password updated successfully',
                    'data': []
                }

                return Response(response)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

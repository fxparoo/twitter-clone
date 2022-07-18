from django.contrib.auth import logout
from rest_framework import generics, permissions
from rest_framework.decorators import permission_classes, api_view
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
import authentication.models as am
import authentication.serializers as aps


class LoginTokenViewSet(TokenObtainPairView):
    serializer_class = aps.LoginTokenSerializer


class ChangePasswordView(generics.UpdateAPIView):
    queryset = am.CustomUser.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = aps.ChangePasswordSerializer


class UpdateProfileView(generics.UpdateAPIView):
    queryset = am.CustomUser.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = aps.UpdateUserSerializer


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def User_logout(request):
    request.user.auth_token.delete()

    logout(request)

    return Response('User Logged out successfully')

from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
import authentication.models as am
from rest_registration.api.serializers import DefaultRegisterUserSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class RegisterUserSerializer(DefaultRegisterUserSerializer):
    class Meta:
        model = am.CustomUser
        fields = ('first_name', 'last_name', 'email', 'username', 'password', 'password2')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data, *args):
        data = validated_data.copy()
        user = am.CustomUser.objects.create_user(**data)

        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password': 'password must mactch'})
        user.set_password(password)
        user.save()
        return user


class LoginTokenSerializer(TokenObtainPairSerializer):
    """Custom Serializer for jwt access and refresh token"""

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        token['email'] = user.email
        token['role'] = user.username

        return token


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    old_password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = am.CustomUser
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password2'):
            raise serializers.ValidationError({"message": "Password fields don't match"})
        return attrs

    def validate_old_password(self, value):
        user = self.context.get('request').user
        if not user.check_password(value):
            raise serializers.ValidationError({"message": "incorrect old password"})
        return value

    def update(self, instance, validated_data):
        instance.set_password(validated_data.get('password'))
        instance.save()
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return {
            "message": "password updated successfully"
        }


class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = am.CustomUser
        fields = ('first_name', 'last_name', 'email', 'DOB', 'joined', 'location', 'personal', 'tweets')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_email(self, value):
        user = self.context['request'].user
        if am.CustomUser.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError({"email": "This email is already in use."})
        return value

    def update(self, instance, validated_data):

        user = self.context['request'].user

        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})

        instance.first_name = validated_data['first_name']
        instance.last_name = validated_data['last_name']
        instance.email = validated_data['email']
        instance.username = validated_data['DOB']
        instance.joined = validated_data['joined']
        instance.location = validated_data['location']
        instance.personal = validated_data['personal']
        instance.tweets = validated_data['tweets']

        instance.save()

        return instance

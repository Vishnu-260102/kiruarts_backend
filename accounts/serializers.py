from rest_framework import serializers
from django.contrib.auth import authenticate
from models_logging.models import Change
from django.core.validators import EmailValidator

from accounts.models import Admin, User, LoginDetails, Userhoto


# serializer for Admin sign in validation
class AdminSignInSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        email_validation = EmailValidator()
        # check username is a Email Address
        try:
            email_validation(data['username'])
            # Find username using the Email address provided
            try:
                username = User.objects.get(email=data['username']).username
                data.update({"username": username})
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    {"error_detail": [
                        "Incorrect username/password"]}
                )
        except:
            pass

        user = authenticate(**data)
        if user:
            if user.is_active:
                if user.is_adminuser:
                    return user
                raise serializers.ValidationError(
                    {"error_detail": [
                        "Incorrect username/password for Admin"]})
            raise serializers.ValidationError(
                {"error_detail": [
                    "Inactive Account"]})
        raise serializers.ValidationError(
            {"error_detail": [
                "Incorrect username/password"]}
        )


class UserSignInSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        email_validation = EmailValidator()
        # check username is a Email Address
        try:
            email_validation(data['username'])
            # Find username using the Email address provided
            try:
                username = User.objects.get(email=data['username']).username
                data.update({"username": username})
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    {"error_detail": [
                        "Incorrect username/password"]}
                )
        except:
            pass

        user = authenticate(**data)
        if user:
            if user.is_active:
                return user
            raise serializers.ValidationError(
                {"error_detail": [
                    "Inactive Account"]})
        raise serializers.ValidationError(
            {"error_detail": [
                "Incorrect username/password"]}
        )


class LoginDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginDetails
        fields = '__all__'


class UserPhotoSerializer(serializers.ModelSerializer):

    class Meta:
        model = Userhoto
        fields = '__all__'

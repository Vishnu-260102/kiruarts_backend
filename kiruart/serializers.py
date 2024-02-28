from rest_framework import serializers
from django.contrib.auth import authenticate
from models_logging.models import Change
from django.core.validators import EmailValidator

from .models import (Contact)


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = '__all__'
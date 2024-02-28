from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import generics, status
from django.core.mail import send_mail
from django.template.loader import render_to_string

from .models import (Contact)
from .serializers import (ContactSerializer)


class ContactView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        obj = request.data
        contact = Contact.objects.create(**obj)
        contact_seri = ContactSerializer(contact)
        html_message = render_to_string('contact_message_preview.html', {
            "name": contact.name, "phoneNumber": contact.phone, "message": contact.message, "email":contact.email})
        send_mail(subject='New contact received', message='Welcome .. message is {}'.format(contact.message),
                  html_message=html_message,
                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=['kiruartsofficial@gmail.com'])
        return Response({"data": contact_seri.data}, status=status.HTTP_200_OK)
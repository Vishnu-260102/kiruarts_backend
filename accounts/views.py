from datetime import datetime, timedelta
from random import randint
from django.conf import settings
from django.forms import model_to_dict
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from knox.models import AuthToken
from rest_framework import generics, status
from django.db import IntegrityError
from django.utils import timezone
from django.db.models import Q, ProtectedError
from models_logging.models import Change
from django.utils.timezone import utc
from django.http import Http404
from django.core.mail import send_mail
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet, InvalidToken
from django.template.loader import render_to_string
import dotenv
import os
from django.contrib.auth.hashers import make_password


# local imports
from custom.permissions import isAdmin, isSuperuser
from accounts.models import Admin, AdminOTP, User, UserOTP, LoginDetails, Userhoto
from accounts.serializers import AdminSignInSerializer, UserSignInSerializer, LoginDetailSerializer, UserPhotoSerializer

#
dotenv.load_dotenv()
#
fernet = Fernet(os.getenv('crypt_key'))
#


class AdminSignInView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = AdminSignInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token_obj, token = AuthToken.objects.create(user=user)
        expiry = timezone.localtime(token_obj.expiry)
        User.objects.filter(id=user.id).update(
            last_login=datetime.now(tz=timezone.utc))
        if user.admin.admin_email_verified:
            email_verified = True
        else:
            email_verified = False
        return Response({"success": True, "message": "Login Successful", "email_verified": email_verified, "token": token, "login_expiry": expiry, "preferences": {}})


class UserSignupView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data['username']
        if (User.objects.filter(email=request.data['email']).exists()):
            return Response({"error_detail": ["Email ID already in use."]}, status=status.HTTP_400_BAD_REQUEST)
        if (User.objects.filter(username=username).exists()):
            return Response({"error_detail": ["Username already Taken."]}, status=status.HTTP_400_BAD_REQUEST)
        plain_passwd = request.data['con_pass']
        passwd = make_password(plain_passwd)
        name = request.data['first_name'] + request.data['last_name']
        while User.objects.filter(username=username).exists():
            username += str(randint(1, 99))
        user = User.objects.create(first_name=request.data['first_name'], last_name=request.data['last_name'],
                                   email=request.data['email'], email_verified=False, account_expiry=None,
                                   username=username, password=passwd)
        html_message = render_to_string('user_account_creation.html', {
            "name": user.first_name, "username": user.username, "email": user.email})
        send_mail(subject='Expense tracker account created', message='Welcome to expense tracker {}'.format(plain_passwd),
                  html_message=html_message,
                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email])
        return Response({"success": True, "message": "Account created successfully"}, status=status.HTTP_200_OK)


class UserSignInView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = UserSignInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token_obj, token = AuthToken.objects.create(user=user)
        expiry = timezone.localtime(token_obj.expiry)
        User.objects.filter(id=user.id).update(
            last_login=datetime.now(tz=timezone.utc))
        if user.email_verified:
            email_verified = True
        else:
            email_verified = False

        def get_ip_address(request):
            user_ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
            if user_ip_address:
                ip = user_ip_address.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            return ip
        user_ip = get_ip_address(request)
        LoginDetails.objects.create(
            user=user, is_mobile=request.user_agent.is_mobile, is_tablet=request.user_agent.is_tablet,
            is_touch_capable=request.user_agent.is_touch_capable, is_pc=request.user_agent.is_pc, is_bot=request.user_agent.is_bot,
            browser_fam=request.user_agent.browser.family, browser_ver=request.user_agent.browser.version_string,
            os_fam=request.user_agent.os.family, os_ver=request.user_agent.os.version_string,
            device_fam=request.user_agent.device.family, device_brand=request.user_agent.device.brand,
            signin_time=datetime.now(), ip_address=user_ip)
        return Response({"success": True, "message": "Login Successful", "email_verified": email_verified, "token": token, "login_expiry": expiry, "preferences": {}})


# Check Token Valid:
class CheckTokenAPI(generics.GenericAPIView):
    def get(self, request):
        if request.user.email_verified == False:
            return Response({"success": False, "message": "Verify Email Address"})
        return Response({"success": True, "message": "User already logged in"})


class UserInfo(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs,):
        data = {}
        data2 = {}
        try:
            user = User.objects.get(id=request.user.pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        # if admin.admin_email_verified == False:
        #     return Response({"error_detail": ['Admin User need to verify email first']}, status=status.HTTP_403_FORBIDDEN)
        expiry = timezone.localtime(AuthToken.objects.get(
            token_key=request.auth.token_key).expiry)
        if (request.user.pass_updated != None):
            data2.update({"username": request.user.username,
                          "email": request.user.email,
                          "name": request.user.first_name ,
                          "lname": request.user.last_name,
                          "login_expiry": expiry, "email_verified": user.email_verified,
                          "password_changed": datetime.strftime(request.user.pass_updated, '%Y-%m-%d %H:%M:%S')})
            # data = {"user": {"username": request.user.username,
            #                  "email": request.user.email,
            #                  "name": request.user.first_name,
            #                  "login_expiry": expiry, "email_verified": user.email_verified,
            #                  "password_changed": datetime.strftime(request.user.pass_updated, '%Y-%m-%d %H:%M:%S')}}
        else:
            data2.update({"username": request.user.username,
                          "email": request.user.email,
                          "name": request.user.first_name ,
                          "lname": request.user.last_name,
                          "login_expiry": expiry, "email_verified": user.email_verified})
            # data = {"user": {"username": request.user.username,
            #                  "email": request.user.email,
            #                  "name": request.user.first_name,
            #                  "login_expiry": expiry, "email_verified": user.email_verified}}
        if (Userhoto.objects.filter(user=user.pk).exists()):
            photo = Userhoto.objects.filter(user=user.pk)
            photo_serializer = UserPhotoSerializer(
                photo, many=True, context={"request": request})
            for datas in photo_serializer.data:
                data2.update({"photo": datas['profile_photo'],"photo_id":datas['id']})
        data.update({"user": data2})
        return Response({"data": data})


class UserChangePassword(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        if (request.data['old_password'] == request.data['new_password']):
            return Response({"error_detail": ['New Password and Old password cant be same']}, status=status.HTTP_400_BAD_REQUEST)
        if bool(user.check_password(request.data['old_password'])) == False:
            return Response({"error_detail": ['Incorrect password entered as Current Password']}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(request.data['new_password'])
        user.save()
        User.objects.filter(id=user.id).update(pass_updated=datetime.now())
        # Delete all  Tokens of this user to logout from other Devices other than This Device/Browser --
        AuthToken.objects.filter(user=user).exclude(
            token_key=request.auth.token_key).delete()
        return Response({"message": "Password changed successfully"})


class UserOTPCreate(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data['email']
        otp_for = request.data['otp_for']
        try:
            EmailValidator()(email)
        except ValidationError:
            return Response({"error_detail": ['Invalid email format']}, status=status.HTTP_400_BAD_REQUEST)
        if (User.objects.filter(Q(email=email)).exclude(id=request.user.id).exists()):
            return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
        otp = (randint(100000, 999999))
        # MODE - CREATE ADMIN OTP - now for Email verification for superadmin changed mail - / 1. profile change / 2.verification
        UserOTP.objects.create(otp_for=otp_for, user=request.user, otp_code=otp,
                               expiry=timezone.now() + timedelta(minutes=2), email_id=email)
        message = f'\n{request.user.first_name}, \n We received a request to update your email on the Expense Tracker. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
        html_message = render_to_string('verify_email_otp.html', {
                                        "name": request.user.first_name, "code": otp})
        subject = "One Time Password to Verify your Email Address"
        send_mail(html_message=html_message, subject=subject, message=message,
                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])
        return Response({'message': "OTP created and is sent to your email"})


class UserOTPVerify(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'email_otp' in request.data:
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            UserOTP.objects.filter(expiry__lt=timezone.now()).delete()
            try:
                # otp  for  -- "2", "Email Verify OTP" - change if any other scenario uses this API view
                latest_otp = UserOTP.objects.filter(
                    user=request.user.pk, otp_for=2, email_id=request.data['email'], expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    request.user.email_verified = True
                    request.user.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    UserOTP.objects.filter(
                        user=request.user.pk, email_id=request.data['email']).delete()  # / mutli request scenario
                    return Response({'message': "OTP verified"})
                else:
                    raise UserOTP.DoesNotExist
            except UserOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": ['Invalid Request']}, status=status.HTTP_400_BAD_REQUEST)


class UserResetPassword(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'reset_password' in request.data:
            try:
                try:
                    EmailValidator()(request.data['user'])
                    user = User.objects.get(
                        email=request.data['user'])
                except:
                    user = User.objects.get(
                        username=request.data['user'])
                #
                # check if already a reset link/otp request exists with expiry time still left
                if (UserOTP.objects.filter(user=user, otp_for=0, email_id=user.email, expiry__gt=timezone.now()).exists()):
                    return Response({"error_detail": ["A valid reset link already exists. Please use it / wait till its expiry"]}, status=status.HTTP_400_BAD_REQUEST)
                #
                subject = "Link to reset your Password"
                origin = request.data['origin']
                OTP_code = randint(100000, 999999)
                encOTP = fernet.encrypt(str(OTP_code).encode())
                # MODE - ADMIN PASSWORD RESET / FORGOT
                UserOTP.objects.create(user=user, otp_for=0, email_id=user.email,
                                       otp_code=OTP_code, expiry=timezone.now()+timedelta(minutes=5))
                message = f"Visit this link to confirm your willingness to reset your password and to enter new password : \n {origin}/expense-tracker/reset_password/confirm_reset/{encOTP.decode()} . \n This link is valid for next 5 minutes only"
                html_message = render_to_string(
                    'reset_email_template.html', {'origin': origin, "encOTP": encOTP, "name": user.first_name, "path": "expense-tracker/reset_password/confirm_reset"})
                send_mail(subject=subject, message=message,
                          from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email], html_message=html_message)
                # delete old OTPs created for passsword reset
                UserOTP.objects.filter(
                    user=user,  otp_for=0, expiry__lt=timezone.now()).delete()
                return Response({"success": True, "message": "Email with reset link has been sent"})
            except User.DoesNotExist:
                return Response({"error_detail": ["No User Found with provided details"]}, status=status.HTTP_400_BAD_REQUEST)
        if 'change_password' in request.data:
            # passing invalid OTP/encrypted code ... / if code is malfunctioned
            try:
                decOTP = fernet.decrypt(
                    request.data['reset_code'].encode('utf-8')).decode()
            except InvalidToken:
                return Response({"error_detail": ["Invalid password reset link. Please request reset link again "]}, status=status.HTTP_400_BAD_REQUEST)
            #
            if (UserOTP.objects.filter(otp_code=decOTP, otp_for=0,
                                       expiry__gte=timezone.now()).exists()):
                instance = UserOTP.objects.get(otp_code=decOTP)
                user = instance.user
                user.set_password(request.data['passwd'])
                user.save()
                # delete used OTP:
                instance.delete()
                # Delete users all tokens:
                AuthToken.objects.filter(user=user).delete()
                return Response({"success": True, 'message': "Password is reset successfully"})
            return Response({"error_detail": ["Invalid/Expired link used. Please request reset link again"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": []}, status=status.HTTP_400_BAD_REQUEST)


class UserChange(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        data = request.data.copy()
        request.data.pop('email')

        # Case - When OTP is entered with other data to  save email
        if ('email_otp' in request.data):
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            UserOTP.objects.filter(expiry__lt=timezone.now()).delete()
            ##
            try:
                latest_otp = UserOTP.objects.filter(
                    user=request.user, email_id=data['email'], otp_for=1, expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    try:
                        user.email = data['email']
                        user.save()
                    except IntegrityError:
                        return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
                    request.user.first_name = request.data['name']
                    request.user.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    UserOTP.objects.filter(
                        user=request.user, email_id=data['email']).delete()  # / mutli request scenario
                    return Response({"success": True, 'message': "Profile updated with email being successfully verified"})
                else:
                    raise UserOTP.DoesNotExist
            except UserOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)

        # Case - When Email is changed... OTP is sent to verify the email
        if (user.email != data['email']):
            if User.objects.filter(
                    email=data['email']).exclude(id=user.pk).exists():
                return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)

            otp = (randint(100000, 999999))
            message = f'\n{request.user.first_name}, \n We received a request to update your email on the Expense Tracker. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
            subject = "One Time Password to Verify your Email Address"
            # MODE - WHEN EMAIL IS CHANGED by SELF- OTP is sent
            UserOTP.objects.create(user=request.user, otp_code=otp,
                                   expiry=timezone.now() + timedelta(minutes=2), email_id=data['email'], otp_for=1)
            html_message = render_to_string('verify_email_otp.html', {
                "name": request.user.first_name, "code": otp})
            send_mail(subject=subject, message=message, html_message=html_message,
                      from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[data['email']])
            return Response({"success": True, "message": "Email verification Required"}, status=status.HTTP_200_OK)

        # Case - When Only Admin Name is Changed
        request.user.first_name = request.data['name']
        request.user.save()
        return Response({"success": True, "message": "Profile Updated"}, status=status.HTTP_200_OK)


class loginsessionView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        def get_ip_address(request):
            user_ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
            if user_ip_address:
                ip = user_ip_address.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            return ip
        user_ip = get_ip_address(request)
        print(user_ip)
        print(request.user)
    # Let's assume that the visitor uses an iPhone...
        print(request.user_agent.is_mobile)  # returns True
        print(request.user_agent.is_tablet)  # returns False
        print(request.user_agent.is_touch_capable)  # returns True
        print(request.user_agent.is_pc)  # returns False
        print(request.user_agent.is_bot)  # returns False

    # Accessing user agent's browser attributes
        # returns Browser(family=u'Mobile Safari', version=(5, 1), version_string='5.1')
        print(request.user_agent.browser)
        print(request.user_agent.browser.family)  # returns 'Mobile Safari'
        print(request.user_agent.browser.version)  # returns (5, 1)
        print(request.user_agent.browser.version_string)   # returns '5.1'

    # Operating System properties
        # returns OperatingSystem(family=u'iOS', version=(5, 1), version_string='5.1')
        print(request.user_agent.os)
        print(request.user_agent.os.family)  # returns 'iOS'
        print(request.user_agent.os.version)  # returns (5, 1)
        print(request.user_agent.os.version_string)  # returns '5.1'

    # Device properties
        print(request.user_agent.device)  # returns Device(family='iPhone')
        print(request.user_agent.device.family)  # returns 'iPhone'
        print(request.user_agent.device.brand)  # returns 'iPhone'

        return Response(status=status.HTTP_200_OK)

    def get(self, request):
        login_det = LoginDetails.objects.filter(
            user=request.user).order_by('-pk')
        serializer = LoginDetailSerializer(login_det, many=True)
        return Response(serializer.data)


# Get Admin user info:


class AdminInfo(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        try:
            admin = Admin.objects.get(user=request.user)
        except Admin.DoesNotExist:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        # if admin.admin_email_verified == False:
        #     return Response({"error_detail": ['Admin User need to verify email first']}, status=status.HTTP_403_FORBIDDEN)
        expiry = timezone.localtime(AuthToken.objects.get(
            token_key=request.auth.token_key).expiry)
        data = {"user": {"username": request.user.username, "admin_name": admin.name,
                         "admin_email": request.user.email,
                         "login_expiry": expiry, "admin_email_verified": admin.admin_email_verified}}
        return Response({"data": data})


# Admin Change Password API:
class AdminChangePassword(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        if (request.data['old_password'] == request.data['new_password']):
            return Response({"error_detail": ['New Password and Old password cant be same']}, status=status.HTTP_400_BAD_REQUEST)
        if bool(user.check_password(request.data['old_password'])) == False:
            return Response({"error_detail": ['Incorrect password entered as Current Password']}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(request.data['new_password'])
        user.save()
        # Delete all  Tokens of this user to logout from other Devices other than This Device/Browser --
        AuthToken.objects.filter(user=user).exclude(
            token_key=request.auth.token_key).delete()
        return Response({"message": "Password changed successfully"})


# Update Admin by self
class AdminChange(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        user = (request.user)
        data = request.data.copy()
        request.data.pop('email')

        # Case - When OTP is entered with other data to  save email
        if ('email_otp' in request.data):
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            AdminOTP.objects.filter(expiry__lt=timezone.now()).delete()
            ##
            try:
                latest_otp = AdminOTP.objects.filter(
                    admin=request.user.admin, email_id=data['email'], otp_for=1, expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    try:
                        user.email = data['email']
                        user.save()
                    except IntegrityError:
                        return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
                    request.user.admin.name = request.data['name']
                    request.user.admin.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    AdminOTP.objects.filter(
                        admin=request.user.admin, email_id=data['email']).delete()  # / mutli request scenario
                    return Response({"success": True, 'message': "Profile updated with email being successfully verified"})
                else:
                    raise AdminOTP.DoesNotExist
            except AdminOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)

        # Case - When Email is changed... OTP is sent to verify the email
        if (user.email != data['email']):
            if User.objects.filter(
                    email=data['email']).exclude(id=user.pk).exists():
                return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)

            otp = (randint(100000, 999999))
            message = f'\n{request.user.admin.name}, \n We received a request to update your email on the Jewellery Association Admin. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
            subject = "One Time Password to Verify your Email Address"
            # MODE - WHEN EMAIL IS CHANGED by SELF- OTP is sent
            AdminOTP.objects.create(admin=request.user.admin, otp_code=otp,
                                    expiry=timezone.now() + timedelta(minutes=2), email_id=data['email'], otp_for=1)
            html_message = render_to_string('verify_email_otp.html', {
                "name": request.user.admin.name, "code": otp})
            send_mail(subject=subject, message=message, html_message=html_message,
                      from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[data['email']])
            return Response({"success": True, "message": "Email verification Required"}, status=status.HTTP_200_OK)

        # Case - When Only Admin Name is Changed
        request.user.admin.name = request.data['name']
        request.user.admin.save()
        return Response({"success": True, "message": "Profile Updated"}, status=status.HTTP_200_OK)


# Create Admin OTP:
class AdminOTPCreate(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        email = request.data['email']
        otp_for = request.data['otp_for']
        try:
            EmailValidator()(email)
        except ValidationError:
            return Response({"error_detail": ['Invalid email format']}, status=status.HTTP_400_BAD_REQUEST)
        if (User.objects.filter(Q(email=email)).exclude(id=request.user.id).exists()):
            return Response({"error_detail": ['Email already associated with another account']}, status=status.HTTP_400_BAD_REQUEST)
        otp = (randint(100000, 999999))
        # MODE - CREATE ADMIN OTP - now for Email verification for superadmin changed mail - / 1. profile change / 2.verification
        AdminOTP.objects.create(otp_for=otp_for, admin=request.user.admin, otp_code=otp,
                                expiry=timezone.now() + timedelta(minutes=2), email_id=email)
        message = f'\n{request.user.admin.name}, \n We received a request to update your email on the Jewellery Association Admin. Please use the OTP {otp} to verify this email and complete the process.OTP is valid for 2 minutes only.'
        html_message = render_to_string('verify_email_otp.html', {
                                        "name": request.user.admin.name, "code": otp})
        subject = "One Time Password to Verify your Email Address"
        send_mail(html_message=html_message, subject=subject, message=message,
                  from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email])
        return Response({'message': "OTP created and is sent to your email"})


# Verify Admin OTP:
class AdminOTPVerify(generics.GenericAPIView):
    permission_classes = [isAdmin]

    def post(self, request, *args, **kwargs):
        if 'email_otp' in request.data:
            # Delete Expired OTPs of all users.  || Later:  Need to check case of Valid OTPs of this User other than email in request
            AdminOTP.objects.filter(expiry__lt=timezone.now()).delete()
            try:
                # otp  for  -- "2", "Email Verify OTP" - change if any other scenario uses this API view
                latest_otp = AdminOTP.objects.filter(
                    admin=request.user.admin, otp_for=2, email_id=request.data['email'], expiry__gte=timezone.now()).latest('creation_time')
                if (latest_otp.otp_code == request.data['email_otp']):
                    request.user.admin.admin_email_verified = True
                    request.user.admin.save()
                    # Delete this OTP because its usage is over.
                    latest_otp.delete()
                    # Delete OTP related with user & email
                    AdminOTP.objects.filter(
                        admin=request.user.admin, email_id=request.data['email']).delete()  # / mutli request scenario
                    return Response({'message': "OTP verified"})
                else:
                    raise AdminOTP.DoesNotExist
            except AdminOTP.DoesNotExist:
                return Response({"error_detail": ['OTP entered is incorrect']}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": ['Invalid Request']}, status=status.HTTP_400_BAD_REQUEST)


# Reset Admin Password:
class AdminResetPassword(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'reset_password' in request.data:
            try:
                try:
                    EmailValidator()(request.data['user'])
                    user = User.objects.filter(is_adminuser=True).get(
                        email=request.data['user'])
                except:
                    user = User.objects.filter(is_adminuser=True).get(
                        username=request.data['user'])
                #
                # check if already a reset link/otp request exists with expiry time still left
                if (AdminOTP.objects.filter(admin=user.admin, otp_for=0, email_id=user.email, expiry__gt=timezone.now()).exists()):
                    return Response({"error_detail": ["A valid reset link already exists. Please use it / wait till its expiry"]}, status=status.HTTP_400_BAD_REQUEST)
                #
                subject = "Link to reset your Password"
                origin = request.data['origin']
                OTP_code = randint(100000, 999999)
                encOTP = fernet.encrypt(str(OTP_code).encode())
                # MODE - ADMIN PASSWORD RESET / FORGOT
                AdminOTP.objects.create(admin=user.admin, otp_for=0, email_id=user.email,
                                        otp_code=OTP_code, expiry=timezone.now()+timedelta(minutes=5))
                message = f"Visit this link to confirm your willingness to reset your password and to enter new password : \n {origin}/auth-reset/confirm_reset/{encOTP.decode()} . \n This link is valid for next 5 minutes only"
                html_message = render_to_string(
                    'reset_email_template.html', {'origin': origin, "encOTP": encOTP, "name": user.admin.name, "account_type": "Admin", "path": "auth-reset/confirm_reset"})
                send_mail(subject=subject, message=message,
                          from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[user.email], html_message=html_message)
                # delete old OTPs created for passsword reset
                AdminOTP.objects.filter(
                    admin=user.admin,  otp_for=0, expiry__lt=timezone.now()).delete()
                return Response({"success": True, "message": "Email with reset link has been sent"})
            except User.DoesNotExist:
                return Response({"error_detail": ["No User Found with provided details"]}, status=status.HTTP_400_BAD_REQUEST)
        if 'change_password' in request.data:
            # passing invalid OTP/encrypted code ... / if code is malfunctioned
            try:
                decOTP = fernet.decrypt(
                    request.data['reset_code'].encode('utf-8')).decode()
            except InvalidToken:
                return Response({"error_detail": ["Invalid password reset link. Please request reset link again "]}, status=status.HTTP_400_BAD_REQUEST)
            #
            if (AdminOTP.objects.filter(otp_code=decOTP, otp_for=0,
                                        expiry__gte=timezone.now()).exists()):
                instance = AdminOTP.objects.get(otp_code=decOTP)
                user = instance.admin.user
                user.set_password(request.data['passwd'])
                user.save()
                # delete used OTP:
                instance.delete()
                # Delete users all tokens:
                AuthToken.objects.filter(user=user).delete()
                return Response({"success": True, 'message': "Password is reset successfully"})
            return Response({"error_detail": ["Invalid/Expired link used. Please request reset link again"]}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error_detail": []}, status=status.HTTP_400_BAD_REQUEST)


class UserPhotoAdd(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserPhotoSerializer
    queryset = Userhoto.objects.all()

    def post(self, request, *args, **kwargs):
        request.data.update({"user": request.user.pk})
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UserPhotoDetails(generics.RetrieveUpdateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserPhotoSerializer
    queryset = Userhoto.objects.all()

    def get(self, request, *args, **kwargs):
        photo = self.get_object()
        serializer = self.get_serializer(photo)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        photo = self.get_object()
        request.data.update({"user": request.user.pk})
        serializer = self.get_serializer(photo, data=request.data)
        serializer.is_valid(raise_exception=True)
        photo.profile_photo.delete()
        serializer.save()
        return Response(serializer.data)

from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser
from . import file_save
from dateutil.relativedelta import relativedelta
import os
from django.core.files.images import get_image_dimensions
from django.core.exceptions import ValidationError
from PIL import Image


def upload_pic(instance, filename):
    _, file_extension = os.path.splitext(filename)
    return 'images/user/{title}{ext}'.format(title=instance.user.username, ext=file_extension)
# Accounts , access related models
# User model is used to store Users ; to be used as basic auth model for authentication of both admin and customers


def user_img_restriction(image):
    image_width, image_height = get_image_dimensions(image)
    if image_width != 600 or image_height != 600:
        raise ValidationError(
            'Image width needs to be 600px and height needs to be 600px ')


class User(AbstractUser):
    account_expiry = models.DateField(blank=True, null=True)
    first_name = models.CharField(max_length=45, null=True, blank=True)
    last_name = models.CharField(max_length=45, null=True, blank=True)
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    pass_updated = models.DateTimeField(null=True, default=None)

    def __str__(self) -> str:
        return 'User - ' + str(self.pk)

    LOGGING_IGNORE_FIELDS = ('password', 'first_name',
                             'last_name', 'last_login')

    class Meta:
        db_table = 'users'
        constraints = [

            models.CheckConstraint(
                check=models.Q(
                    username__regex=r'^\w(?:\w|[.-](?=\w))*$'
                ),
                name="Invalid username",
                violation_error_message="Username must only contain alphanumeric characters, '@', '#', '-', '_', and '.'",
            )
        ]


class UserOTP(models.Model):

    OTP_FOR = (
        ("0", "Password Reset OTP"),
        ("1", "Profile Email Change OTP"),
        ("2", "Email Verify OTP"),
    )

    id_otp = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        'User', on_delete=models.CASCADE, related_name='otp_set')
    email_id = models.EmailField()
    otp_code = models.CharField(
        max_length=6)
    creation_time = models.DateTimeField(default=timezone.now)
    expiry = models.DateTimeField()
    otp_for = models.CharField(choices=OTP_FOR, max_length=1)

    def __str__(self) -> str:
        return 'User OTP - ' + str(self.pk)

    class Meta:
        db_table = 'user_otp'

# Admin model is used to store Admin users


class Userhoto(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.OneToOneField('User', on_delete=models.CASCADE, error_messages={
        "unique": "Profile Photo already exists. So, Try to Update it."})
    profile_photo = models.ImageField(validators=[user_img_restriction],
        upload_to=upload_pic, default='images/user/user.png')

    def __str__(self) -> str:
        return 'User Profile Photo - ' + str(self.pk)

    class Meta:
        db_table = 'user_photo'


class LoginDetails(models.Model):
    detail_id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey('User',
                             on_delete=models.CASCADE)
    is_mobile = models.BooleanField(default=False)
    is_tablet = models.BooleanField(default=False)
    is_touch_capable = models.BooleanField(default=False)
    is_pc = models.BooleanField(default=False)
    is_bot = models.BooleanField(default=False)
    browser_fam = models.CharField(max_length=50)
    browser_ver = models.CharField(max_length=50)
    os_fam = models.CharField(max_length=50)
    os_ver = models.CharField(max_length=50)
    device_fam = models.CharField(max_length=50)
    device_brand = models.CharField(max_length=50, null=True)
    ip_address = models.CharField(max_length=50)
    signin_time = models.DateTimeField()

    def __str__(self) -> str:
        return 'Login Device Details - ' + str(self.pk)

    class Meta:
        db_table = "login_details"


class Admin(models.Model):
    adminid = models.AutoField(primary_key=True)
    name = models.CharField(
        max_length=100)
    user = models.OneToOneField(
        'User', on_delete=models.PROTECT, limit_choices_to={'is_adminuser': True}, related_name='admin')
    admin_email_verified = models.BooleanField(default=False)

    def __str__(self) -> str:
        return 'Admin User - ' + str(self.pk)

    class Meta:
        db_table = 'admin'


# Admin OTP model is used to store Email OTPs of user
class AdminOTP(models.Model):

    OTP_FOR = (
        ("0", "Password Reset OTP"),
        ("1", "Profile Email Change OTP"),
        ("2", "Email Verify OTP"),
    )

    id_otp = models.BigAutoField(primary_key=True)
    admin = models.ForeignKey(
        'Admin', on_delete=models.CASCADE, related_name='otp_set')
    email_id = models.EmailField()
    otp_code = models.CharField(
        max_length=6)
    creation_time = models.DateTimeField(default=timezone.now)
    expiry = models.DateTimeField()
    otp_for = models.CharField(choices=OTP_FOR, max_length=1)

    def __str__(self) -> str:
        return 'Admin User OTP - ' + str(self.pk)

    class Meta:
        db_table = 'admin_otp'
    # LOG IGNORE THIS MODEL

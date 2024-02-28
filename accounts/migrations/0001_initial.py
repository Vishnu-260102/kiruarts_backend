# Generated by Django 4.1.7 on 2024-02-28 11:12

import accounts.models
from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('account_expiry', models.DateField(blank=True, null=True)),
                ('first_name', models.CharField(blank=True, max_length=45, null=True)),
                ('last_name', models.CharField(blank=True, max_length=45, null=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('email_verified', models.BooleanField(default=False)),
                ('pass_updated', models.DateTimeField(default=None, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'db_table': 'users',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Admin',
            fields=[
                ('adminid', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('admin_email_verified', models.BooleanField(default=False)),
                ('user', models.OneToOneField(limit_choices_to={'is_adminuser': True}, on_delete=django.db.models.deletion.PROTECT, related_name='admin', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'admin',
            },
        ),
        migrations.CreateModel(
            name='UserOTP',
            fields=[
                ('id_otp', models.BigAutoField(primary_key=True, serialize=False)),
                ('email_id', models.EmailField(max_length=254)),
                ('otp_code', models.CharField(max_length=6)),
                ('creation_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('expiry', models.DateTimeField()),
                ('otp_for', models.CharField(choices=[('0', 'Password Reset OTP'), ('1', 'Profile Email Change OTP'), ('2', 'Email Verify OTP')], max_length=1)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otp_set', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'user_otp',
            },
        ),
        migrations.CreateModel(
            name='Userhoto',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('profile_photo', models.ImageField(default='images/user/user.png', upload_to=accounts.models.upload_pic, validators=[accounts.models.user_img_restriction])),
                ('user', models.OneToOneField(error_messages={'unique': 'Profile Photo already exists. So, Try to Update it.'}, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'user_photo',
            },
        ),
        migrations.CreateModel(
            name='LoginDetails',
            fields=[
                ('detail_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('is_mobile', models.BooleanField(default=False)),
                ('is_tablet', models.BooleanField(default=False)),
                ('is_touch_capable', models.BooleanField(default=False)),
                ('is_pc', models.BooleanField(default=False)),
                ('is_bot', models.BooleanField(default=False)),
                ('browser_fam', models.CharField(max_length=50)),
                ('browser_ver', models.CharField(max_length=50)),
                ('os_fam', models.CharField(max_length=50)),
                ('os_ver', models.CharField(max_length=50)),
                ('device_fam', models.CharField(max_length=50)),
                ('device_brand', models.CharField(max_length=50, null=True)),
                ('ip_address', models.CharField(max_length=50)),
                ('signin_time', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'login_details',
            },
        ),
        migrations.CreateModel(
            name='AdminOTP',
            fields=[
                ('id_otp', models.BigAutoField(primary_key=True, serialize=False)),
                ('email_id', models.EmailField(max_length=254)),
                ('otp_code', models.CharField(max_length=6)),
                ('creation_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('expiry', models.DateTimeField()),
                ('otp_for', models.CharField(choices=[('0', 'Password Reset OTP'), ('1', 'Profile Email Change OTP'), ('2', 'Email Verify OTP')], max_length=1)),
                ('admin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otp_set', to='accounts.admin')),
            ],
            options={
                'db_table': 'admin_otp',
            },
        ),
        migrations.AddConstraint(
            model_name='user',
            constraint=models.CheckConstraint(check=models.Q(('username__regex', '^\\w(?:\\w|[.-](?=\\w))*$')), name='Invalid username', violation_error_message="Username must only contain alphanumeric characters, '@', '#', '-', '_', and '.'"),
        ),
    ]
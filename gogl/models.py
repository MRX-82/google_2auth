from django.db import models

import os
# Create your models here.
#from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
import pyotp


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Класс модели для создания пользователя с поддержкой двухфакторной аутентификации
    """
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)

    #поле для хранения секретного ключа 2FA
    otp_secret_key = models.CharField(max_length=50, null=True, blank=True)
    totp_devices = models.ManyToManyField(TOTPDevice, blank=True, related_name='users')

    #Поля для аутентификации
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    #Переопределяем методы базовой модели пользователя
    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    def __str__(self):
        return self.email

    def check_password(self, raw_password):
        """
        Проверяет пароль пользователя с учетом двухфакторной аутентификации
        """
        is_valid = super().check_password(raw_password)
        if is_valid:
            totp_device = self.totpdevice_set.filter(confirmed=True).first()
            if totp_device:
                is_valid = totp_device.verify_token(raw_password)
        return is_valid


    @staticmethod
    def generate_otp_secret_key(user):
        """
        Генерация на 32 бита
        """
        secret_key = pyotp.random_base32()
        user.otp_secret_key = secret_key
        user.save()
        return secret_key


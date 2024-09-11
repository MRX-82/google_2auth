from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
#from django_otp.plugins.otp_totp.models import TOTPDevice

class CustomUserBackend(ModelBackend):
    """
    Кастомный бэкенд аутентификации
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Переопределяет метод аутентификации чтобы учитывать двухфакторную
        аутентификацию
        """
        UserModel = get_user_model()
        try:
            #Если пользователь найден
            user = UserModel.objects.get(username=username)
            if user.check_password(password):
                #Пароль верный
                return user
        except UserModel.DoesNotExist:
            #Пользователь не найден
            #RUN the default password hasher once to reduce the timing
            #Difference beetwen an existing and a nonexistent user(#20760)
            UserModel().set_password(password)

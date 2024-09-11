from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse_lazy, reverse

#import qrcode
import pyotp
#from io import BytesIO
#from django.core.files.uploadedfile import InMemoryUploadedFile
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.contrib.auth import login, logout, authenticate
#from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.signals import user_logged_in
#from django.utils.decorators import method_decorator
#from django.contrib import messages
#from django.contrib.auth import get_user_model
from django.dispatch import receiver
from .models import CustomUser
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.contrib.auth.hashers import check_password


def index(request):
    """
    Функция представление для главной страницы
    """
    return render(request, 'layout/base.html')


class UserLoginView(LoginView):
    """
    Класс для авторизации пользователя по логину и паролю
    """
    template_name = "registration/login.html"
    form_class = CustomAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        try:
            user = CustomUser.objects.get(username=username)
            if check_password(password, user.password):
                login(self.request, user)
                return super().form_valid(form)
        except CustomUser.DoesNotExist:
            pass
        return self.form_invalid(form)

    def get_success_url(self):
        """
        Функция в случае успешной валидации формы
        """
        try:
            user = CustomUser.objects.get(id=self.request.user.id)
            if user.otp_secret_key:
                #Если отп подвязан отправляем на гугл аутентификацию
                return reverse('gogl:otp_verify')
            else:
                #Если отп не настроен отправляем на страницу настройки отп
                return reverse('gogl:otp_setup')
        except CustomUser.DoesNotExist:
            #Если пользователь не найден на главную
            return reverse('gogl:index')


def logout_view(request):
    """
    Функция для выхода
    """
    logout(request)
    return redirect('gogl:index')



def registr(request):
    """
    Функция для регистрации нового пользователя
    """
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            #Если все корректно сохраняем
            form.save()
            return redirect('gogl:login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/registr.html', {'form': form})


def otp_setup(request):
    """
    Функция настройки отп устройства
    """
    user = request.user #получаем пользователя
    otp_secret_key = user.generate_otp_secret_key(user)  #генерирует отп код
    #Создание ТОТР устройства для пользователя
    totp_device = TOTPDevice(user=user,name='Default')
    totp_device.save() #сохраняем
    user.totp_devices.add(totp_device) #Добавляем устройство
    user.otp_secret_key = otp_secret_key #это допка
    user.save() #сохраняем изменения
    return render(request, 'registration/otp_setup.html', {'otp_secret_key': otp_secret_key})


@login_required
def bomber(request):
    """
    Страница после прохождения успешной двухфакторной аутентификации
    """
    return render(request, 'registration/bomber.html')


@receiver(user_logged_in)
def redirect_after_login(sender, user, request, **kwargs):
    return redirect(reverse('gogl:redirect_al'))


@login_required
def otp_verify(request):
    """
    OTP верификация пользователя
    """
    if request.method == "POST":
        otp_code = request.POST.get('otp_code')
        user = request.user
        #Получаем секретный ключ пользователя из модели
        otp_secret_key = user.otp_secret_key
        #Создаем объект TOTP и проверяем введенный код
        totp = pyotp.TOTP(otp_secret_key)
        if totp.verify(otp_code):
            #Аутентификация прошла успешно, можно перенаправлять пользователя на
            #нужную страницу
            return redirect(reverse('gogl:bomber'))
        else:
            #Неверный одноразовый пароль
            error_message = "Неверный одноразовый пароль, попробуйте еще раз"
            return render(request, 'registration/otp_verify.html', {'error_message': error_message})
    return render(request, 'registration/otp_verify.html')


#@login_required
#def two_factor_auth(request):
    #Логика
    #return render(request, 'registration/two_factor_auth.html')





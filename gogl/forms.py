from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
#from django.contrib.auth.models import User
from .models import CustomUser
#from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password


class CustomAuthenticationForm(AuthenticationForm):
    """
    RK для аутентификации пользователя
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control col-md-2 col-sm-3',
            'placeholder': 'Имя пользователя',
        })
        self.fields['password'].widget.attrs.update({
            'class': 'form-control col-md-2 col-sm-3',
            'placeholder': 'Пароль',
        })
    #Дополнительный clean(self)
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        user = CustomUser.objects.filter(username=username).first()
        password = make_password(password)
        #user.password = password
        if user is None or not user.password:
            raise forms.ValidationError("Неправильное имя или пароль")
        return self.cleaned_data


class CustomUserCreationForm(UserCreationForm):
    """
    Форма для регистрации нового пользователя с поддержкой двухфакторной
    аутентификации
    """
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'})
    )
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'})
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'})
    )

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class OTPSetupForm(forms.Form):
    otp_secret = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'OTP Secret'})
    )
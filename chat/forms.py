from django import forms

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True)

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True)

class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput, required=True, min_length=6)
    confirm_password = forms.CharField(widget=forms.PasswordInput, required=True, min_length=6)

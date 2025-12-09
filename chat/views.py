from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import ChatMessage


# -------------------------
# Register
# -------------------------
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm

def register_view(request):
    form = UserCreationForm()  # create an empty form

    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")

    return render(request, "register.html", {"form": form})



# -------------------------
# Login
# -------------------------
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            if user.is_staff:
                return redirect('admin_dashboard')
            return redirect('user_dashboard')

        return render(request, 'login.html', {'error': 'Invalid username/password'})

    return render(request, 'login.html')


# -------------------------
# Logout
# -------------------------
def logout_view(request):
    logout(request)
    return redirect('login')


# -------------------------
# Admin Dashboard
# -------------------------
  # assuming you have a Chat model
@login_required
def admin_dashboard(request):
    chats = ChatMessage.objects.all().order_by('-timestamp')
    users = User.objects.filter(is_staff=False)
    return render(request, 'admin_dashboard.html', {'chats': chats, 'users': users})

# -------------------------
# User Dashboard
# -------------------------

@login_required
def user_dashboard(request):
    # Messages where user is sender or recipient
    chats = ChatMessage.objects.filter(user=request.user) | ChatMessage.objects.filter(recipient=request.user)
    chats = chats.order_by('timestamp')
    return render(request, 'user_dashboard.html', {'chats': chats})


# -------------------------
# Chat (dummy)
# -------------------------
from django.views.decorators.csrf import csrf_exempt  # optional, if using cookie CSRF
from .models import ChatMessage

# @login_required
# def send_message(request):
#     if request.method == 'POST':
#         msg = request.POST.get('message')
#         recipient_id = request.POST.get('recipient_id')  # optional
#         recipient = None

#         # If admin sends to a specific user
#         if recipient_id:
#             try:
#                 recipient = User.objects.get(id=recipient_id)
#             except User.DoesNotExist:
#                 return JsonResponse({'status': 'error', 'response': 'Invalid recipient'})

#         # Save the message
#         chat = ChatMessage.objects.create(
#             user=request.user,
#             message=msg,
#             recipient=recipient
#         )

#         # AI response only if sender is a normal user
#         ai_response = ""
#         if not request.user.is_staff:
#             ai_response = f"AI Response to: {msg}"
#             chat.response = ai_response
#             chat.save()

#         return JsonResponse({'status': 'ok', 'response': ai_response or "Message sent"})

#     return JsonResponse({'status': 'error', 'response': 'Invalid request'})
@login_required
def send_message(request):
    if request.method == 'POST':
        msg = request.POST.get('message')
        recipient_id = request.POST.get('recipient_id')  # optional
        recipient = None

        if recipient_id:
            try:
                recipient = User.objects.get(id=recipient_id)
            except User.DoesNotExist:
                return JsonResponse({'status': 'error', 'response': 'Invalid recipient'})

        # Save the message
        ChatMessage.objects.create(
            user=request.user,
            message=msg,
            recipient=recipient
        )

        return JsonResponse({'status': 'ok', 'response': 'Message sent'})

    return JsonResponse({'status': 'error', 'response': 'Invalid request'})
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
from .models import PasswordResetOTP
from .forms import ForgotPasswordForm, OTPForm, ResetPasswordForm

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                otp_entry = PasswordResetOTP.objects.create(user=user)
                
                # send email
                send_mail(
                    'Your OTP for Password Reset',
                    f'Your OTP is {otp_entry.otp}',
                    'from@example.com',
                    [email],
                    fail_silently=False,
                )
                
                request.session['user_id'] = user.id
                return redirect('verify_otp')
            except User.DoesNotExist:
                form.add_error('email', 'Email not found.')
    else:
        form = ForgotPasswordForm()
    return render(request, 'forgot_password.html', {'form': form})

def verify_otp(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('forgot_password')
    user = User.objects.get(id=user_id)

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_input = form.cleaned_data['otp']
            otp_entry = PasswordResetOTP.objects.filter(user=user).order_by('-created_at').first()
            if otp_entry and otp_entry.otp == otp_input and timezone.now() - otp_entry.created_at < timedelta(minutes=10):
                request.session['otp_verified'] = True
                return redirect('reset_password')
            else:
                form.add_error('otp', 'Invalid or expired OTP.')
    else:
        form = OTPForm()
    return render(request, 'verify_otp.html', {'form': form})

def reset_password(request):
    user_id = request.session.get('user_id')
    otp_verified = request.session.get('otp_verified', False)
    if not user_id or not otp_verified:
        return redirect('forgot_password')
    user = User.objects.get(id=user_id)

    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            password1 = form.cleaned_data['new_password']
            password2 = form.cleaned_data['confirm_password']
            if password1 != password2:
                form.add_error('confirm_password', "Passwords don't match.")
            else:
                user.set_password(password1)
                user.save()
                # cleanup session
                del request.session['user_id']
                del request.session['otp_verified']
                return redirect('login')
    else:
        form = ResetPasswordForm()
    return render(request, 'reset_password.html', {'form': form})



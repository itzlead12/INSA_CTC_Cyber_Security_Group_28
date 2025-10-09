from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.http import JsonResponse
from logs.models import RequestLog
from django.views.decorators.csrf import csrf_exempt
from clients.models import Client
from rules.models import WAFRule
from django.db.models import Count, Q
from datetime import datetime, timedelta
import pytz

def staff_required(view):
    return user_passes_test(lambda u: u.is_staff)(view)



def register(request):
    """User registration (sign up) page - NO login required"""
    if request.user.is_authenticated:
        return redirect('clients:client_register')
        
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            
            if user is not None:
                login(request, user)
                messages.success(request, 'Account created successfully! Please register your website.')
                return redirect('clients:client_register') 
    else:
        form = UserCreationForm()
    
    return render(request, 'dashboard/register.html', {'form': form})



def landing_page(request):
    return render(request, 'dashboard/landing.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:admin_dashboard')
        
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next', 'dashboard:admin_dashboard')
                return redirect(next_url)
    else:
        form = AuthenticationForm()
    return render(request, 'dashboard/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('dashboard:login')

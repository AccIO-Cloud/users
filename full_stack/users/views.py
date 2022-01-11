from django.contrib import messages
from django.contrib.auth.models import User, auth
from django.http import HttpResponse  
from django.shortcuts import render, redirect  
from django.contrib.auth import login, authenticate  
from .forms import SignupForm  
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes, force_str  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string  
from .token import account_activation_token  
from django.core.mail import EmailMessage  
from django.contrib.auth import get_user_model
from django.core.mail import send_mail, BadHeaderError
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.db.models.query_utils import Q
from django.contrib.auth.tokens import default_token_generator

# Create your views here.


def login(request):
    if request.method== 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request, user)
            return redirect("/")
        else:
            messages.info(request,'invalid credentials, Please register or check the details')
            return redirect('login')

    else:
        return render(request,'login.html')    

def logout(request):
    auth.logout(request)
    return redirect('/')

def signup(request):  
    if request.method == 'POST':  
        form = SignupForm(request.POST)
        if form.is_valid():
            if User.objects.filter(email=form.cleaned_data.get('email') ).exists():
                messages.info(request,'Email Exists, Please login to continue')
            
            else:
            # save form in the memory not in database  
                user = form.save(commit=False)  
                user.is_active = False  
                user.save()  
                # to get the domain of the current site  
                current_site = get_current_site(request)  
                mail_subject = 'Activation link has been sent to your email id' 
                message = render_to_string('acc_active_email.html', {  
                    'user': user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)), 
                                    'token':account_activation_token.make_token(user),  
                })  
                to_email = form.cleaned_data.get('email')  
                email = EmailMessage(  
                            mail_subject, message, to=[to_email]  
                )  
                email.send()  
                return render(request, 'backpage.html')
    else:  
        form = SignupForm()  
    return render(request, 'signup.html', {'form': form})  

def activate(request, uidb64, token):  
    User = get_user_model()  
    try:  
        uid = force_str(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save()  
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')  
    else:  
        return HttpResponse('Activation link is invalid!') 
    
def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password/password_reset_email.txt"
                    c = {
                    "email":user.email,
                    'domain':'127.0.0.1:8000',
                    'site_name': 'Website',
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "user": user,
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'admin@example.com' , [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return redirect ("/password_reset/done/")
            else:
                messages.info(request,'Email not valid')
                
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="password/password_reset.html", context={"password_reset_form":password_reset_form})

def password_reset_done(request):
    return render(request, 'password/password_reset_done.html')
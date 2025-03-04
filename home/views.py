from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def home(request):
    context = {'username' : request.user.username}
    return render(request, 'home/home.html', context)


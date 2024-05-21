from django.db import models
from django.contrib.auth.models import User
from django.http import HttpRequest
from django.contrib.auth import get_user_model

User=get_user_model()

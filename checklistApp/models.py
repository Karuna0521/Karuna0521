from django.db import models
from django.contrib.auth.models import AbstractUser

STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    )

# AbstractUser
class User(AbstractUser):
    # first_name = models.CharField(blank=False, max_length=50)
    # last_name = models.CharField(blank=False, max_length=50)
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(blank=False, max_length=20)
    password = models.CharField(max_length=25, blank=False)
    confirm_password = models.CharField(max_length=25, blank=False)
    team = models.CharField(max_length=25, blank=False)
    specialization = models.CharField(max_length=25, blank=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    updated_date = models.DateField(blank=False)
    first_name = None
    last_name = None
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email' #to use the email as the only unique identifier.
    def __str__(self):
        return self.username

class ChecklistAppHome(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(blank=False, max_length=20)
    password = models.CharField(max_length=25, blank=False)
    confirm_password = models.CharField(max_length=25, blank=False)
    team = models.CharField(max_length=25, blank=False)
    specialization = models.CharField(max_length=25, blank=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    updated_date = models.DateField(blank=False)

    class Meta:
        managed = False
        db_table = 'checklistApp_user'

class Captcha(models.Model):
    key = models.CharField(max_length=255)
    captcha_string = models.CharField(max_length=255)
    count = models.IntegerField(blank=True)


class AudRevMapping(models.Model):
    rev_id = models.IntegerField()
    aud_id = models.IntegerField()
    class Meta:
        unique_together = ('rev_id', 'aud_id')

class ChecklistType(models.Model):
    checklist_title = models.CharField(max_length=255,unique=True)
    # subcategories = models.ManyToManyField(unique=True, blank=False)
    subcategories = models.JSONField(max_length=500, unique=True, default=list, encoder=None)
    questions = models.JSONField(max_length=500, unique=True, default=list, encoder=None)


class Options(models.Model):
    option_text = models.CharField(max_length=25, blank=False)


# class Options(models.Model):
#     # Optionid = models.AutoField(primary_key=True, db_column='Optionid')
#     option_text = models.CharField(max_length=100, unique=True, blank=False)

# Check the primary key type
# print(OptionsData._meta.pk);

class AppInfo(models.Model):
    STATUS_CHOICES = [
        ('assigned', 'Assigned'),
        ('inprogress', 'In Progress'),
        ('completed', 'Completed')
    ]
    app_name = models.CharField(max_length=100, unique=True)
    app_category = models.CharField(max_length=100)
    reviewer_id = models.IntegerField()
    auditor_id = models.IntegerField()
    status = models.CharField(max_length=25, choices=STATUS_CHOICES, default='assigned')
    remark = models.CharField(max_length=255,null=True)
    created_date = models.DateField(auto_now_add=True)
    reviewer_assigned_date = models.DateField()
    auditor_assigned_date = models.DateField()
    updated_date = models.DateField(auto_now=True)




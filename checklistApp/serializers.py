from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from checklistApp.models import *
import re

class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )
    password = serializers.CharField(max_length=25)
    confirm_password = serializers.CharField(style={'input_type':'password'}, write_only=True, required=True)

    class Meta:
        model = User    
        fields = [ 'id', 'full_name', 'email', 'password','confirm_password', 'role', 'team','status','specialization']
        extra_kwargs = {
            'full_name': {'required': True},
            # 'last_name': {'required': True},
            'password': {'write_only': True}, 
            }
    # Validating Password and Confirm Password while Registration
    def validate_password(self, password):
        if not re.match(r'^(?=.*\d)(?=.*[A-Z])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password):
            raise serializers.ValidationError("Password must be more than 8 characters with at least one symbol, one uppercase letter, and digits.")
        confirm_password = self.initial_data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return password  

    def validate_full_name(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("First name must contain only alphabets and no spaces.")
        return value
    # def validate_last_name(self, value):
    #     if not re.match(r'^[A-Za-z]+$', value):
    #         raise serializers.ValidationError("Last name must contain only alphabets and no spaces.")
    #     return value
    def validate_role(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Role must contain only alphabets and no spaces.")
        return value
    def validate_team(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Team must contain only alphabets and no spaces.")
        return value
    def validate_specialization(self, value):
        if not re.match(r'^[A-Za-z]+$', value):
            raise serializers.ValidationError("Specialization must contain only alphabets and no spaces.")
        return value 
    
    def create(self, validated_data):
        user = User(
            full_name=validated_data['full_name'],
            # last_name=validated_data['last_name'],
            username=validated_data['email'],
            email=validated_data['email'],
            role=validated_data['role'],
            team=validated_data['team'],
            specialization=validated_data['specialization'],
            # updated_date=validated_data['updated_date'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['role','status']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, max_length=255)
    password = serializers.CharField(required=True, max_length=100)
    class Meta:
        model = User
        fields = [ "email", "password" ]   
    
class CaptchaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Captcha
        fields = '__all__'

class Captcha_count_ser(serializers.ModelSerializer):

    class Meta:
        model = Captcha
        fields = ["count"]

class AudRevMapSerializer(serializers.ModelSerializer):
    rev_id = serializers.IntegerField()
    aud_id = serializers.IntegerField()
    class Meta:
        model = AudRevMapping
        fields = '__all__'

class ChecklistTypeSerializer(serializers.ModelSerializer):
    checklist_title = serializers.CharField()
    subcategories = serializers.ListField(child=serializers.CharField())
    questions = serializers.JSONField(required=False)
    class Meta:
        model=ChecklistType
        # fields = ['checklist_title','subcategories']
        # exclude=['questions']
        # fields=['id','checklist_title','subcategories']
        fields = '__all__'
      
class OptionsSerializer(serializers.ModelSerializer):
    option_text = serializers.CharField()
    class Meta:
        model = Options
        fields = '__all__'


# class checklistTypeSerializer(serializers.Serializer):
#     class Meta:
#         model = ChecklistType
#         fields = '__all__'



# class CaptchaCountSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Captcha
#         fields = ['count']

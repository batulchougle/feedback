from rest_framework import serializers
from .models import Institute, Student, Faculty
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.response import Response
from rest_framework import status


class InstituteRegisterSerializer(serializers.ModelSerializer):
    password= serializers.CharField(max_length=68, min_length=6, write_only= True)
    password2=serializers.CharField(max_length=68, min_length=6, write_only= True)

    class Meta:
        model=Institute
        fields=['email','name','password','password2']

    def validate(self, attrs):
        password=attrs.get('password','')
        password2=attrs.get('password2','')
        if password != password2:
            raise serializers.ValidationError("Passwords did not match")
        return attrs   
    
    def create(self, validated_data):
        institute=Institute.objects.create_institute(
        email=validated_data['email'],
        name=validated_data.get('name'),
        password=validated_data.get('password')
        )
        return institute
    
class StudentRegisterSerializer(serializers.ModelSerializer):
    password= serializers.CharField(max_length=68, min_length=6, write_only= True)
    password2=serializers.CharField(max_length=68, min_length=6, write_only= True)

    class Meta:
        model=Student
        fields=['email','name','password','password2','institute']

    def validate(self, attrs):
        password=attrs.get('password','')
        password2=attrs.get('password2','')
        if password != password2:
            raise serializers.ValidationError("Passwords did not match")
        return attrs   
    
    def create(self, validated_data):

        user=Student.objects.create_user(
        email=validated_data['email'],
        name=validated_data.get('name'),
        password=validated_data.get('password'),
        institute=validated_data.get('institute')
        
        )
        return user    
    
class FacultyRegisterSerializer(serializers.ModelSerializer):
    password= serializers.CharField(max_length=68, min_length=6, write_only= True)
    password2=serializers.CharField(max_length=68, min_length=6, write_only= True)

    class Meta:
        model=Faculty
        fields=['email','name','password','password2','institute']

    def validate(self, attrs):
        password=attrs.get('password','')
        password2=attrs.get('password2','')
        if password != password2:
            raise serializers.ValidationError("Passwords did not match")
        return attrs   
    
    def create(self, validated_data):

        user=Faculty.objects.create_user(
        email=validated_data['email'],
        name=validated_data.get('name'),
        password=validated_data.get('password'),
        institute=validated_data.get('institute')
        
        )
        return user    

class StudentLoginSerializer(serializers.ModelSerializer):
    
    email=serializers.EmailField(max_length=255)
    password=serializers.CharField(max_length=68,write_only=True)
    name = serializers.CharField(max_length=255)
    access_token=serializers.CharField(max_length=255,read_only=True)
    refresh_token=serializers.CharField(max_length=255,read_only=True)

    class Meta:
        model=Student
        fields=['email','password','name','institute','access_token','refresh_token']


    def validate(self,attrs):
         email=attrs.get('email') 
         password=attrs.get('password')
         request=self.context.get('request')
         student=authenticate(request,email=email,password=password)
         if not student:
                raise AuthenticationFailed("invalid credentials try again")
         user_tokens=student.tokens()

         return {
             'email':student.email,
             'name': student.get_name,
             'institue': student.get_institute,
              'access_token':str(user_tokens.get('access')),
              'refresh_token':str(user_tokens.get('refresh'))
         }
        
from collections import OrderedDict
import random
import string
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.db import DatabaseError
from django.shortcuts import get_object_or_404, render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate,login
from checklistApp.models import User
from .scripts.authentication import MyJWTAuthentication
from checklistApp.scripts.permissions import IsAdmin, IsReviewer
from checklistApp.serializers import *
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics


from django.contrib.sessions.models import Session
# from django.contrib.auth.models import Group  # Import the Group class

# Create your views here.
class UserRegistrationView(APIView):      
    def post(self, request):
        request_data = request.data
        # By default role is set to Auditor
        request_data['role']= "Auditor"
        
        data = OrderedDict()
        data.update(request_data)
        try:
            if not request.data.get('key'):
                raise serializers.ValidationError("Key is required !")
            if not request.data.get('captcha_string'):
                raise serializers.ValidationError("captcha_string is required !")
            key = request.data["key"]
            ip = ''.join([char for char in key if not char.isalpha()])
            try:
                captcha = Captcha.objects.filter(key=key)
                if len(captcha) == 0:
                    raise serializers.ValidationError("key is invalid")
            except Captcha.DoesNotExist:
                raise serializers.ValidationError("key is invalid")
            if ip != request.META["REMOTE_ADDR"] and captcha[0].key != key:
                # self.captcha_update(captcha[0])
                captcha.update(count=captcha.count+1)
                raise serializers.ValidationError("IP mismatch")
            if captcha[0].captcha_string != str(data["captcha_string"]):
                if captcha[0].count == 3 :
                    print(captcha[0].captcha_string)
                    Captchas = Captcha.objects.filter(captcha_string=captcha[0].captcha_string)
                    Captchas.delete()
                    raise serializers.ValidationError("captcha was expired")
                captcha.update(count=captcha[0].count+1)
                raise serializers.ValidationError("captcha_string mismatch")
        except Captcha.DoesNotExist:
            raise serializers.ValidationError("captcha is invalid")
        try :
            user = User.objects.get(email=request.data["email"])
            return Response({'status':403, 'message':'Email address already exists..!! Please choose a different email.'})
        except User.DoesNotExist :
            ser = UserSerializer(data = request.data)
            if ser.is_valid():
                user = ser.save()
                # captcha.delete()
                # token, created = Token.objects.get_or_create(user=user)
                # return Response({'token': token.key,"status-code": "201","message":"User Registered successfully"}, status=status.HTTP_200_OK)       
                return Response({"status-code": "201","errors": [],"message":"User Registered successfully"}, status=status.HTTP_200_OK)       
        return Response({'status-code':403, 'message':'Something went wrong','errors':ser.errors}, status=status.HTTP_400_BAD_REQUEST)


class CaptchaStringAPIView(APIView):
    def generateCaptchaString(self):
        length=6
        charset=string.ascii_letters
        return ''.join(random.choice(charset) for _ in range(length))

    def post(self, request):
        captcha_str = self.generateCaptchaString()
        key = self.generateCaptchaString() + str(request.META["REMOTE_ADDR"]) + self.generateCaptchaString()
        captcha = CaptchaSerializer(data={"captcha_string": captcha_str, "key":key, "count":0})
        captcha.is_valid(raise_exception=True)
        c = captcha.save()
        print(str(c.id))
        return Response({'status-code': 200,
                         "errors": [],
                         'message':'Captcha Generated',
                         "data":{"c_id": str(c.id), "captcha_string": captcha_str, "key":key}}, status=status.HTTP_200_OK)

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        print(token)
        try : 
            Usergroup = User.objects.get(id=user.pk)
            print(Usergroup.pk)
        except User.DoesNotExist:  
            pass
        token["role"] = Usergroup.role
        token["user_id"] = user.pk
        return token

class UserLogin(APIView):
    # authentication_classes=[MyJWTAuthentication]
    # permission_classes=[IsAuthenticated, IsAdmin]
    def post(self, request):
        data = OrderedDict()
        data.update(request.data)
        try:
            if not request.data.get('key'):
                raise serializers.ValidationError("Key is required !")
            if not request.data.get('captcha_string'):
                raise serializers.ValidationError("captcha_string is required !")
            key = request.data["key"]
            ip = ''.join([char for char in key if not char.isalpha()])
            try:
                captcha = Captcha.objects.filter(key=key)
                if len(captcha) == 0:
                    raise serializers.ValidationError("key is invalid")
            except Captcha.DoesNotExist:
                raise serializers.ValidationError("key is invalid")
            if ip != request.META["REMOTE_ADDR"] and captcha[0].key != key:
                # self.captcha_update(captcha[0])
                captcha.update(count=captcha.count+1)
                raise serializers.ValidationError("IP mismatch")
            if captcha[0].captcha_string != str(data["captcha_string"]):
                if captcha[0].count == 3 :
                    print(captcha[0].captcha_string)
                    Captchas = Captcha.objects.filter(captcha_string=captcha[0].captcha_string)
                    Captchas.delete()
                    raise serializers.ValidationError("captcha was expired")
                captcha.update(count=captcha[0].count+1)
                raise serializers.ValidationError("captcha_string mismatch")
        except Captcha.DoesNotExist:
            raise serializers.ValidationError("captcha is invalid")

        email = request.data.get('email')
        password = request.data.get('password')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None
        
        if user is not None:
            auth_user = authenticate(username=user.username, password=password)
            if auth_user is not None:
                # if email == "cdacadmin@gmail.com":
                #     # Get the 'auth_permission_group' with ID 1
                #     auth_permission_group = Group.objects.get(id=1)
                #     # Add the user to the group
                #     user.groups.add(auth_permission_group)
                #     user.save()
                # if auth_user.is_active is False:
                #     return Response({
                #     'status': 400,
                #     'message': 'Your account is not active',
                # })


                login(request, auth_user)
                u = User.objects.get(id=auth_user.pk)
                refresh = MyTokenObtainPairSerializer.get_token(u)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                 # Get the session_key after login
                session_key = request.session.session_key
                
                return Response({
                    'msg': "User loggedIn Succesfully",
                    'refresh': refresh_token,
                    'access': access_token,
                    'session_key': session_key,
                })
                # token, created = Token.objects.get_or_create(user=user)
                # return Response({'token': token.key,"status-code": "200","message":"User LoggedIn successfully"}, status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# class userLogout(APIView):
#     # authentication_classes = (TokenAuthentication,)
#     # authentication_classes = (SessionAuthentication, BasicAuthentication, TokenAuthentication)
#     # permission_classes = (IsAuthenticated,)
    
#     def post(self, request):
#         try:
#             refresh_token = request.data["refresh"]
#             token = RefreshToken(refresh_token)
#             print(request.auth,'---->',token)
#             # request.auth.delete()
#             token.blacklist()
#             return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({"detail": "Invalid token or token not provided."}, status=status.HTTP_400_BAD_REQUEST)

class UserLogout(APIView):
    def post(self, request):
        try:
            # Check if the request contains a 'session_id' in the JSON body
            session_id = request.data.get('session_id', None)

            if not session_id:
                return Response({"detail": "Missing 'session_id' in the request body."}, status=status.HTTP_400_BAD_REQUEST)

            # Get the current user's session key
            current_session_key = request.session.session_key
            print('current-->',current_session_key)
            # Check if the provided session key matches the current user's session key
            if session_id != current_session_key:
                return Response({"detail": "Provided session key does not match the current user's session."}, status=status.HTTP_400_BAD_REQUEST)

            # Delete the session ID from the django_session table
            session = Session.objects.filter(session_key=session_id)
            if len(session) > 0:
                session.delete()
                return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "session not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)





    # def post(self, request):
    #     try:
    #         # Delete the user's token to logout
    #         print('----->',request.user)
    #         request.auth.delete()
    #         # request.auth.delete()
    #         return Response({"status-code":"200","message":"User Logged out Successfully"}, status=status.HTTP_200_OK)
    #     except Exception as e:
    #         return Response({'error':str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#----------- Karuna -----------------#
class UserApi(APIView):
    # authentication_classes=[MyJWTAuthentication]
    # permission_classes = [IsAuthenticated, IsAdmin]
    def get(self, request,id=None):
       if id:
            user = User.objects.get(id=id)
            ser = UserSerializer(user)
            return Response({"payload": ser.data}, status=status.HTTP_200_OK)
       userData = User.objects.all()
       ser = UserSerializer(userData, many=True)
       return Response({'payload':ser.data})
    
    def patch(self, request):
        try:
            data = OrderedDict()
            data.update(request.data)
            user = User.objects.get(id=request.data['id'])
            print("this is id",request.data['id'])
            ser = UserSerializer(user, data = request.data, partial=True)
            print("---------==========>>>>>",ser)
            if ser.is_valid():
                ser.save()
                return Response({'status-code': 200,"errors": [], 'message': 'User Data is updated'})
            return Response({'status-code':403, 'message':'Something went wrong','errors':ser.errors})
        except Exception as e:
            print('--->',e)
            return Response({'status-code':403, 'message':'Invalid id in the url'})
        
    def delete(self, request, id=None):
        try:
            # id = request.GET.get('id')
            user_id = User.objects.get(id =request.data['id'])
            user_id.delete()
            return Response({'status-code': 200,"errors": [],'message':'User is deleted'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status-code':403,'message':'Inavlid id'},status=status.HTTP_403_FORBIDDEN)  
        
# -------------------------
# sarath
# -------------------------

# from rest_framework.views import APIView

# class UserApi(APIView):
#     authentication_classes = [MyJWTAuthentication]
#     permission_classes = [IsAuthenticated, IsAdmin]

#     def get(self, request, id=None):
#         if id:
#             user = User.objects.get(id=id)
#             ser = UserSerializer(user)
#             return Response({"payload": ser.data}, status=status.HTTP_200_OK)
#         userData = User.objects.all()
#         ser = UserSerializer(userData, many=True)
#         return Response({'payload': ser.data})

#     def patch(self, request, id):
#         try:
#             data = OrderedDict()
#             data.update(request.data)
#             user = User.objects.get(id=id)
#             ser = UserSerializer(user, data=request.data, partial=True)
#             if ser.is_valid():
#                 ser.save()
#                 return Response({'status-code': 200, "errors": [], 'message': 'User Data is updated'})
#             return Response({'status-code': 403, 'message': 'Something went wrong', 'errors': ser.errors})
#         except Exception as e:
#             return Response({'status-code': 403, 'message': 'Invalid id in the URL'})

#     def delete(self, request, id):
#         try:
#             user_id = User.objects.get(id=id)
#             user_id.delete()
#             return Response({'status-code': 200, "errors": [], 'message': 'User is deleted'}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'status-code': 403, 'message': 'Invalid id'}, status=status.HTTP_403_FORBIDDEN)

# ------------------------- Sarath ---------------------------#

class AuditorData(APIView):
    # authentication_classes=[MyJWTAuthentication]
    # permission_classes = [IsAuthenticated, IsReviewer]
    def get(self, request):
        # auditor_data = get_object_or_404(User, id=auditor_id, role='auditor')
        auditor_data = User.objects.filter(role='Auditor')
        serializer = UserSerializer(auditor_data, many=True)
        print(auditor_data)
        return Response({'status-code': 200,"errors": [], 'payload':serializer.data},status=status.HTTP_200_OK)
    

class AudRevMapView(APIView):
    def get(self, request):
        mappings = AudRevMapping.objects.all()
        serializer = AudRevMapSerializer(mappings, many=True)
        data = list()
        for map in serializer.data:
            aud_dict = dict()
            rev_dict = dict()
            mapping = dict()
            aud = User.objects.get(id=map.get('aud_id'))
            rev = User.objects.get(id=map.get('rev_id'))
            aud_dict.update({"id": map.get('aud_id'), "name": aud.full_name})
            rev_dict.update({"id": map.get('rev_id'), "name": rev.full_name})
            mapping.update({"id": map.get('id'), "aud": aud_dict, "rev": rev_dict})
            data.append(mapping)
        return Response({'status-code': 200,"errors": [],'payload':data}, status=status.HTTP_200_OK)

    def post(self, request):
        audrev_to_map = request.data
        print("------------->>>>>>>",audrev_to_map)
        auditor_ids = audrev_to_map.get('aud_ids')
        reviewer_id = audrev_to_map.get('rev_id')

        reviewer = User.objects.filter(id=reviewer_id)
        print('review---',reviewer)
        if len(reviewer) > 0:
            if reviewer[0].role not in ['Reviewer', 'reviewer']:
                raise serializers.ValidationError(str(reviewer_id) + " is not a Reviewer!")
            print("This is reviewers===========>>>", reviewer)
        else:
            raise serializers.ValidationError("Reviewer Does Not exists with id:" + str(reviewer_id))
            
        if not isinstance(auditor_ids, list):
            auditor_ids = [auditor_ids]  # Ensure auditors is treated as a list

        # existing_mapping = []
        for aud_id in auditor_ids:
            print("this is audid", aud_id)
            auditor = User.objects.filter(id=aud_id)
            print('aud---',auditor)
            if len(auditor) > 0:
                if auditor[0].role in ['Auditor', 'auditor']:
                    mapping = AudRevMapping.objects.filter(aud_id=aud_id)
                    if len(mapping) > 0: #aud is mapped to reviewer
                        raise serializers.ValidationError("Auditor " + str(aud_id)+" is assigned already to " + str(mapping[0].rev_id))  
                    else:
                        print(mapping,'--->aud_id',aud_id, ' rev ----<',reviewer_id)
                        created = AudRevMapping.objects.create(rev_id=reviewer_id, aud_id=aud_id)
                    
                    #existing_mapping = [*existing_mapping,*mapping]
                else:                
                    raise serializers.ValidationError(str(aud_id) + " is not a Auditor!")
                # print("This is from table -------->", existing_mapping)
            else:
                raise serializers.ValidationError("Auditor Does Not Exist with id:" + str(aud_id))
        # existing_mapping_as_dict = [{key: value for key, value in obj.__dict__.items() if not key.startswith('_') and key != 'id'} for obj in existing_mapping]

        # print('dictiomanry---->',existing_mapping_as_dict)
        # for aud_id in auditor_ids:
        #     rev_aud_map = {'rev_id': reviewer_id, 'aud_id': aud_id}
        #     if rev_aud_map in existing_mapping_as_dict: # if {id:5} in [{id:4},5,6,7]
        #         raise serializers.ValidationError("Auditor is assigned already..!!!")
        #     else:
        #         AudRevMapping.objects.create(rev_id=reviewer_id, aud_id=aud_id)
        return Response({'status-code':200, 'erros':[],'message':"Auditors are assigned successfully"}, status=status.HTTP_200_OK)

    def patch(self, request):
        audrev_to_map = request.data
        auditor_ids = audrev_to_map.get('aud_ids')
        reviewer_id = audrev_to_map.get('rev_id')
        reviewer = User.objects.filter(id=reviewer_id)
        if len(reviewer) > 0:
            if reviewer[0].role not in ['Reviewer', 'reviewer']:
                raise serializers.ValidationError(str(reviewer_id) + " is not a Reviewer!")
        else:
            raise serializers.ValidationError("Reviewer Does Not exists with id:" + str(reviewer_id))
        
        rev_mappings = AudRevMapping.objects.filter(rev_id=reviewer_id) 
        rev_mapping_as_dict = [{key: value for key, value in obj.__dict__.items() if not key.startswith('_') and key != 'id'} for obj in rev_mappings]
        print('rev_mapping AS DiCT--------->',rev_mapping_as_dict)
        
        if not isinstance(auditor_ids, list):
            auditor_ids = [auditor_ids]
        
        req_rev_aud_mappings = []
        for aud_id in auditor_ids:
            auditor = User.objects.filter(id=aud_id)
            if len(auditor) > 0: 
                if auditor[0].role in ['Auditor', 'auditor']:
                    aud_mappings = AudRevMapping.objects.filter(aud_id=aud_id).exclude(rev_id=reviewer_id)
                    if len(aud_mappings) > 0:
                        raise serializers.ValidationError("Auditor "+str(aud_id)+" is already assigned to " + str(aud_mappings[0].rev_id))
                    else: # appending to create new mappings
                        req_rev_aud_mappings.append({'rev_id': reviewer_id, 'aud_id': aud_id})                                           
                else:                
                    raise serializers.ValidationError(str(aud_id) + " is not a Auditor!")
            else:
                raise serializers.ValidationError("Auditor Does Not Exist with id:" + str(aud_id))
           
        
        for mapping in req_rev_aud_mappings:
            if mapping not in rev_mapping_as_dict:
                AudRevMapping.objects.create(rev_id=mapping['rev_id'], aud_id=mapping['aud_id'])

        for rev_map in rev_mappings:
            temp_mapping = {'rev_id': rev_map.rev_id, 'aud_id': rev_map.aud_id}
            if temp_mapping not in req_rev_aud_mappings: # delete if mapping not in request data 
                rev_map.delete()
        return Response({'status-code':200, 'erros':[],'message':"Mappings are updated successfully"}, status=status.HTTP_200_OK)

    def delete(self, request):
        try:
            audrev_id = AudRevMapping.objects.get(id=request.data['id'])
            audrev_id.delete()
            return Response({'status-code':200, 'errors':[], 'message':'mapping deleted successfully.!'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status-code':403,'message':'Inavlid id'},status=status.HTTP_403_FORBIDDEN)

# class ChecklistTypeView(APIView):
#     def post(self, request):
#         checklist_data = request.data
#         serializer = ChecklistTypeSerializer(data=checklist_data)

#         if serializer.is_valid():
#             checklist_title = serializer.validated_data.get('checklist_title')
#             subcategories = serializer.validated_data.get('subcategories')
#             # Do something with checklist_title and subcategories
#             print("this is title ----------->",checklist_title)
#             print("this is subcategories ----------->",subcategories)
#             if ChecklistType.objects.filter(checklist_title=checklist_title).exists():###This exists was not working
#                 return Response({'status-code': 400, 'message':"Checklist Title or Checklist Subcategories already exists."})
#             checklist = ChecklistType(**serializer.validated_data)
#             checklist.save()
#             return Response({"status-code":200,"errors":[],"message": "New Checklist is created ."})
#         else:
#             return Response(serializer.errors, status=400)

class ChecklistTypeView(APIView):
    def post(self, request):
        checklist_data = request.data
        data = dict()
        data['checklist_title'] = str(checklist_data['checklist_title']).capitalize()
        data['subcategories'] = checklist_data['subcategories']

        existing = ChecklistType.objects.filter(checklist_title=data['checklist_title'])
        if len(existing) > 0:
            return Response({'status-code': 400,"message": "Checklist Title or Checklist Subcategories already exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = ChecklistTypeSerializer(data=data)
        if serializer.is_valid():
            
            checklist_title = serializer.validated_data.get('checklist_title')
            subcategories = serializer.validated_data.get('subcategories')

            checklist = ChecklistType.objects.create(
                checklist_title=checklist_title,
                subcategories=subcategories 
            )
            if checklist:
                return Response({"status-code":200,"errors":[],"message": "Checklist created successfully."},status=status.HTTP_201_CREATED)
        else:
            return Response({'status-code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        checklist_data = ChecklistType.objects.all()
        serializer = ChecklistTypeSerializer(checklist_data, many=True)
        return Response({'status-code':200,'errors':[],'payload':serializer.data}, status=status.HTTP_200_OK)

    def delete(self, request):
        print("This is request data", request.data)
        checklist_id = request.data.get('id')
        print("this is checklist id", checklist_id)
        try:
            data = ChecklistType.objects.all()
            print(data)
            checklist_data = ChecklistType.objects.get(id=checklist_id)
            checklist_data.delete()
            return Response({'status-code':200,'errors':[], 'message':'Checklist data deleted successfully'})
        except:
            raise serializers.ValidationError(str(checklist_id)+" is an Invalid id")
    
    def patch(self,request):
        checklist_data = request.data
        data = dict()
        data['id'] = checklist_data['id']
        data['checklist_title'] = str(checklist_data['checklist_title']).capitalize()
        data['subcategories'] = checklist_data['subcategories']
        if 'questions' not in checklist_data:
            data['questions'] = []
        else:
            data['questions'] = checklist_data['questions']
        
        # Validations for  questions
        for q in data['questions']:
            if q['category'] not in data['subcategories']:
                return Response({'status-code':400, 'message': str(q['category'])+' category not present in checklist subcategories'},status=status.HTTP_400_BAD_REQUEST)

        # unique question (non repeat) validation
        unique_category_question = set()

        for item in data['questions']:
            pair = (item["category"], item["question"])
            unique_category_question.add(pair)

        unique_category_question_list = [{"category": category, "question": question} for category, question in unique_category_question]

        print(unique_category_question_list)
        data['questions'] = unique_category_question_list

        checklist = ChecklistType.objects.get(id=data['id'])
        serializer = ChecklistTypeSerializer(checklist, data=data, partial=True)
        if serializer.is_valid():
            # checklist_id = serializer.validated_data.get('id')
            # checklist_title = serializer.validated_data.get('checklist_title')
            # subcategories = serializer.validated_data.get('subcategories')
            # questions = serializer.validated_data.get('questions')

            serializer.save()
            return Response({'status-code':200, 'errors':[], 'message':'Checklist data updated successfully'},status=status.HTTP_200_OK)
        return Response({'status-code':400, 'message':'Invalid checklist', 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class OptionsView(APIView):
    def get(self, request):
        options = Options.objects.all()
        serializer = OptionsSerializer(options, many=True)
        return Response({'status-code':200, 'errors':[], 'payload':serializer.data},status=status.HTTP_200_OK)

    def post(self, request):
        option_text = str(request.data.get('option_text')).capitalize()
        existing = Options.objects.filter(option_text=option_text)
        if len(existing) > 0:
            return Response({'status-code':400, 'message': 'Option ' + option_text + ' already exists ..!'},status=status.HTTP_400_BAD_REQUEST)
            
        optionSer = OptionsSerializer(data={"option_text": option_text})
        optionSer.is_valid(raise_exception=True)
        o = optionSer.save()
        return Response({'status-code': 200,
                         "errors": [],
                         'message':'option created successfully ..!',
                         "data":{"id": str(o.id), "option_text": option_text}}, status=status.HTTP_200_OK)
    
    def delete(self, request):
        option_id = request.data.get('id')
        try:
            data = Options.objects.all()
            print(data)
            option_data = Options.objects.get(id=option_id)
            option_data.delete()
            return Response({'status-code':200,'errors':[], 'message':'Option '+str(option_data.option_text)+' deleted successfully'})
        except:
            raise serializers.ValidationError(str(option_id)+" is an Invalid id")


    def patch(self,request):
        option_data = request.data
        data = dict()
        data['id'] = option_data['id']
        data['option_text'] = str(option_data['option_text']).capitalize()

        option = Options.objects.filter(id=data['id'])
        if len(option) > 0:
            serializer = OptionsSerializer(option[0], data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'status-code':200, 'errors':[], 'message':'Option '+ str(option[0].option_text) +' updated successfully'},status=status.HTTP_200_OK)
            return Response({'status-code':400, 'message':'Invalid Option', 'errors': serializer.errors},status=status.HTTP_400_BAD_REQUEST)
        raise serializers.ValidationError(str(option_data['id'])+" is an Invalid id")




### Old Options API ###
# class OptionsView(APIView):
#     def get(self, request):
#         options_data = OptionsData.objects.all()
#         serializer = OptionSerializer(options_data, many=True)

#         # Extracting integer IDs from options_data
#         option_data_with_ids = [{'id': str(ObjectId(option.pk)), **serializer.data[i]} for i, option in enumerate(options_data)]

#         return Response({
#             'status-code': 200,
#             'errors': [],
#             'payload': {
#                 'option_ids': option_data_with_ids,
#             }
#         }, status=status.HTTP_200_OK)

#     def post(self, request):
#         option_data = request.data
#         data = dict()
#         data['option_text'] = str(option_data['option_text']).capitalize()

#         existing_options = OptionsData.objects.filter(option_text=data['option_text'])
#         if len(existing_options) > 0:
#             return Response({'status-code': 400, 'message': 'Option already Exists..!'}, status=status.HTTP_400_BAD_REQUEST)

#         serializer = OptionSerializer(data=data)
#         if serializer.is_valid():
#             option = serializer.save()
#             # Convert Optionid to string before including it in the response
#             response_data = {
#                 'status-code': 200,
#                 'errors': [],
#                 'message': 'Option Created Successfully',
#                 # 'Optionid': str(option.Optionid),  # Convert to string
#             }
#             return Response(response_data, status=status.HTTP_201_CREATED)
#         else:
#             return Response({'status-code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)

#     def patch(self, request):
#         data = dict()
#         option_data = request.data
#         option_id = option_data['id']
#         option_text = str(option_data['option_text']).capitalize()
#         data['id'] = option_id
#         data['option_text'] = option_text
#         existing_option = OptionsData.objects.get(id=option_id)
#         serializer = OptionsData(existing_option, data=data,  partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             # Convert Optionid to string before including it in the response
#             response_data = {
#                 'status-code': 200,
#                 'errors': [],
#                 'message': 'Option Updated Successfully',
#                 'Optionid': str(option_id),  # Convert to string
#             }
#             return Response(response_data, status=status.HTTP_200_OK)
#         else:
#             return Response({'status-code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)

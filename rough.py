class OptionsView(APIView):
    def get(self, request):
        options_data = OptionsData.objects.all()
        serializer = OptionSerializer(options_data, many=True)

       # Extracting ids from options_data
        option_data_with_ids = [{'id': option.id, **serializer.data[i]} for i, option in enumerate(options_data)]

        # return Response({'status-code':200, 'errors':[], 'payload':serializer.data}, status=status.HTTP_200_OK)    
        return Response({
            'status-code': 200,
            'errors': [],
            'payload': {
                # 'options': serializer.data,
                'option_ids': option_data_with_ids,
            }
        }, status=status.HTTP_200_OK)
      
    def post(self, request):
        option_data = request.data
        data = dict()
        data['option_text'] = str(option_data['option_text']).capitalize()

        # Print the data before saving
        print("Data before saving:", data)

        existing_options = OptionsData.objects.filter(option_text=data['option_text'])
        if len(existing_options) > 0:
            return Response({'status-code': 400, 'message': 'Option already Exists..!'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = OptionSerializer(data=data)
        if serializer.is_valid():
            # Print the validated data before saving
            print("Validated Data before saving:", serializer.validated_data)

            option = serializer.save()
            # Print the saved option, including the id
            print("Saved Option - ID:", option.id, "Option Text:", option.option_text)

            return Response({'status-code': 200, 'errors': [], 'message': 'Option Created Successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'status-code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)


    def patch(self, request):
        data = dict()
        option_data = request.data
        option_id = option_data['id']
        option_text = str(option_data['option_text']).capitalize()
        data['id'] = option_id
        data['option_text'] = option_text
        existing_option = OptionsData.objects.get(id=option_id)
        serializer = OptionsData(existing_option, data=data,  partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status-code':200, 'errors':[] ,'message':'Option Updated Successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'status-code': 400, 'errors': serializer.errors, 'message': 'Validation errors occurred.'}, status=status.HTTP_400_BAD_REQUEST)

class OptionSerializer(serializers.ModelSerializer):
    option_text = serializers.CharField()

    class Meta:
        model = OptionsData
        fields = '__all__'


from django.db import models

class OptionsData(models.Model):
    Optionid = models.AutoField(primary_key=True)
    option_text = models.CharField(max_length=100, unique=True, blank=False)

# Check the primary key type
print(OptionsData._meta.pk)



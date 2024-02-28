from django.db import models
from datetime import datetime

# Create your models here.
class Contact(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length = 200)
    phone = models.CharField(max_length = 15)
    email = models.EmailField()
    date = models.DateTimeField(auto_now_add=datetime.now())
    message = models.TextField()
    
    class Meta:
        db_table = 'contact'

    def __str__(self):
        return 'Contact - ' + str(self.pk)
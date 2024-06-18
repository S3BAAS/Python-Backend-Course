from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

password_mongodb = os.getenv('PASSWORD_MONGODB')
username_mongodb = os.getenv('USERNAME_MONGODB')

# Base de datos local
# client = MongoClient().local

# Base de datos de la nube
client = MongoClient(
    f'mongodb+srv://{username_mongodb}:{password_mongodb}@cluster0.x5etwlt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0').test
from fastapi import APIRouter, HTTPException
from typing import List
from db.models.users import User
from db.client import client
from db.schemas.users import users_schema

router = APIRouter(prefix='/users', 
                   responses={404: {"message": "Not found"}}, 
                   tags=['users_list'])


# Devuelve todos los usuarios
@router.get('/', response_model=List[User])
async def users():
    """
    Obtener una lista de todos los usuarios.
    
    :return: Una lista de objetos User.
    """
    if client.users.count_documents({}) == 0:
        raise HTTPException(status_code=404, detail="No hay usuarios registrados")
    
    return users_schema(client.users.find())
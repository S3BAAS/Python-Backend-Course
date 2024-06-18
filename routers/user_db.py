from fastapi import APIRouter, HTTPException
from db.models.users import User
from db.client import client
from db.schemas.users import user_schema
from bson import ObjectId


# Crear un enrutador para gestionar las rutas relacionadas con usuarios
router = APIRouter(
    prefix='/userdb',
    responses={404: {"message": "Not found"}},
    tags=['user']
)

def search_user(field: str, value: str | ObjectId) -> User | None:
    """
    Buscar un usuario en la base de datos por un campo específico y su valor.
    
    :param field: El campo por el cual se realizará la búsqueda (ej. "_id").
    :param value: El valor del campo a buscar (puede ser una cadena o un ObjectId).
    :return: Un objeto User si se encuentra, de lo contrario None.
    """
    try:
        user = client.users.find_one({field: value})
        return User(**user_schema(user))
    except:
        return None

# Path parameters / Parámetros de ruta
@router.get('/{id}', response_model=User)
async def users_path(id: str):
    """
    Obtener un usuario específico por su ID.

    :param id: El ID del usuario.
    :return: Un objeto User si se encuentra, de lo contrario lanza una excepción HTTP 404.
    """
    user = search_user("_id", ObjectId(id))
    if user:
        return user
    else:
        raise HTTPException(status_code=404, detail='User not found')

# Query parameters (/?id=id) / Parámetros de consulta
@router.get('/q/')
async def users_query(id: str):
    """
    Obtener un usuario específico por su ID utilizando parámetros de consulta.
    
    :param id: El ID del usuario.
    :return: Un objeto User si se encuentra, de lo contrario lanza una excepción HTTP 404.
    """
    user = search_user("_id", ObjectId(id))
    
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    else:
        return user

# Actualizando un usuario
@router.put('/', status_code=200, response_model=User)
async def update_user(user: User):
    """
    Actualizar un usuario existente.
    
    :param user: Un objeto User con los nuevos datos.
    :return: El usuario actualizado si se encuentra, de lo contrario lanza una excepción HTTP 404.
    """
    user_dict = dict(user)
    if "id" in user_dict:
        del user_dict['id']
    
    try:
        client.users.find_one_and_replace(
            {"_id": ObjectId(user.id)},
            user_dict
        )
        return search_user("_id", ObjectId(user.id))
    except:
        raise HTTPException(status_code=404, detail='User not found')

# Borrando un usuario
@router.delete('/{id}', status_code=204)
async def delete_user(id: str):
    """
    Borrar un usuario por su ID.
    
    :param id: El ID del usuario a borrar.
    :return: Nada si la eliminación es exitosa, de lo contrario lanza una excepción HTTP 404.
    """
    found = client.users.find_one_and_delete({"_id": ObjectId(id)})
    
    if not found:
        raise HTTPException(status_code=404, detail='User not found')

# Creando un usuario
@router.post('/', status_code=201)
async def new_user(user: User):
    """
    Crear un nuevo usuario.
    
    :param user: Un objeto User con los datos del nuevo usuario.
    :return: El usuario creado.
    """
    if search_user("email", user.email) or search_user("username", user.username):
        raise HTTPException(status_code=409, detail='User already exists')
    
    user_dict = dict(user)
    if "id" in user_dict:
        del user_dict['id']
    
    result = client.users.insert_one(user_dict)
    
    new_user = user_schema(
        client.users.find_one(
            {"_id": result.inserted_id}
        )
    )
    
    return User(**new_user)
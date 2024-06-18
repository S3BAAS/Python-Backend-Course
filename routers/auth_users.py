from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from db.client import client
from db.schemas.user_auth import dict_not_password, dict_password
from db.models.user_auth import User, UserDB

# TODO: Inicialización del enrutador
router = APIRouter()

# * Dependencia para obtener el token de OAuth2
oauth2 = OAuth2PasswordBearer(tokenUrl="login")

def search_user_db(field: str, value: str) -> UserDB | None:
    """
    Busca un usuario en la base de datos y lo devuelve como UserDB.

    :param field: El campo por el cual buscar (por ejemplo, 'email', 'username').
    :param value: El valor del campo a buscar.
    :return: Un objeto UserDB si se encuentra el usuario, de lo contrario None.
    """
    try:
        user = client.usersdb.find_one({field: value})
        return UserDB(**dict_password(user))
    except:
        return None

def search_user(field: str, value: str) -> User | None:
    """
    Busca un usuario en la base de datos y lo devuelve como User.

    :param field: El campo por el cual buscar (por ejemplo, 'email', 'username').
    :param value: El valor del campo a buscar.
    :return: Un objeto User si se encuentra el usuario, de lo contrario None.
    """
    try:
        user = client.usersdb.find_one({field: value})
        return User(**dict_not_password(user))
    except:
        return None

async def current_user(token: str = Depends(oauth2)):
    """
    Obtiene el usuario actual a partir del token de autenticación.

    :param token: El token de autenticación OAuth2.
    :return: Un objeto User si el usuario está autenticado y no está deshabilitado.
    :raises HTTPException: Si las credenciales son incorrectas o el usuario está deshabilitado.
    """
    user = search_user('username', token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credentials Incorrect",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User disabled"
        )
        
    return user

# TODO: Endpoint para la autenticación y generación del token
@router.post('/login')
async def login(form: OAuth2PasswordRequestForm = Depends()):
    """
    Autentica un usuario y genera un token de acceso.

    :param form: El formulario de solicitud de OAuth2 con el nombre de usuario y la contraseña.
    :return: Un diccionario con el token de acceso y el tipo de token.
    :raises HTTPException: Si el nombre de usuario o la contraseña son incorrectos.
    """
    user = search_user_db('username', form.username)
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if form.password != user.password or form.username != user.username:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect username or password"
        )
    
    return {
        'access_token': user.username,
        'token_type': 'bearer'
    }

# * Endpoint para validar el token y obtener el usuario actual
@router.get('/users/{username}')
async def me(user: User = Depends(current_user)):
    """
    Devuelve el usuario actual autenticado.

    :param user: El objeto User autenticado (dependencia de current_user).
    :return: Un objeto User con los datos del usuario actual.
    """
    return user

# TODO: Endpoint para crear un nuevo usuario
@router.post('/createdb', status_code=201)
async def new_user(user: UserDB) -> User:
    """
    Crear un nuevo usuario.

    :param user: Un objeto UserDB con los datos del nuevo usuario.
    :return: El usuario creado sin la contraseña.
    :raises HTTPException: Si el usuario ya existe.
    """
    if search_user('email', user.email):
        raise HTTPException(status_code=409, detail='User already exists')
            
    user_dict = dict(user)
    
    # ! Se elimina el campo "disabled" si está presente
    if "disabled" in user_dict:
        del user_dict['disabled']
    
    # Inserta el usuario en la base de datos
    client.usersdb.insert_one(user_dict)
    
    # Actualiza el usuario para agregar el campo "disabled"
    client.usersdb.update_one(
        {'email': user.email},
        {'$set': {'disabled': False}}
    )
    
    #Obtiene el nuevo usuario de la base de datos
    user_new = client.usersdb.find_one({'email': user.email})
    
    return User(**user_new)
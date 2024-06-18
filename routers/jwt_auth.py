from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import encode, decode, ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from db.models.user_jwt import User, UserDB
from db.client import client
from db.schemas.user_jwt import dict_not_password, dict_password

# Inicialización de constantes para configuración del token JWT
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 1
SECRET_KEY = '967f331124239e3aebfe83e2512d3f30194faab3855596b7f383e1a0872c534d'

# Inicialización del enrutador
router = APIRouter(
    prefix='/auth',
    responses={404: {"message": "Not found"}},
    tags=['auth']
)

# Dependencia para obtener el token de OAuth2
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Contexto de cifrado para las contraseñas
crypt = CryptContext(schemes=['bcrypt'])

def search_user_db(field: str, value: str) -> UserDB | None:
    """
    Busca un usuario en la base de datos y devuelve un objeto UserDB si lo encuentra.

    :param field: Campo por el cual buscar (ej. 'username', 'email').
    :param value: Valor del campo a buscar.
    :return: Objeto UserDB si se encuentra, None si no se encuentra.
    """
    try:
        user = client.usersdb.find_one({field: value})
        return UserDB(**dict_password(user))
    except:
        return None

def search_user(field: str, value: str) -> User | None:
    """
    Busca un usuario en la base de datos y devuelve un objeto User si lo encuentra.

    :param field: Campo por el cual buscar (ej. 'username', 'email').
    :param value: Valor del campo a buscar.
    :return: Objeto User si se encuentra, None si no se encuentra.
    """
    try:
        user = client.usersdb.find_one({field: value})
        return User(**dict_not_password(user))
    except:
        return None

async def auth_user(token: str = Depends(oauth2)) -> User:
    """
    Autentica al usuario mediante un token JWT.

    :param token: Token JWT.
    :return: Usuario autenticado.
    """
    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales incorrectas",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        # Decodificación del token JWT
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get('sub')

        if username is None:
            raise exception

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tiempo de expiración excedido",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except InvalidTokenError:
        raise exception

    user = search_user('username', username)

    if not user:
        raise exception

    return user

def current_user(user: User = Depends(auth_user)) -> User:
    """
    Obtiene el usuario actual.

    :param user: Usuario autenticado.
    :return: Usuario actual si no está deshabilitado.
    """
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario deshabilitado"
        )
    return user

# Endpoint para la autenticación y generación del token
@router.post('/token')
async def login(form: OAuth2PasswordRequestForm = Depends()):
    """
    Autentica al usuario y genera un token JWT.

    :param form: Formulario con nombre de usuario y contraseña.
    :return: Token de acceso.
    """
    user = search_user_db('username', form.username)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )

    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nombre de usuario o contraseña incorrectos"
        )

    access_token_expiration = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expiration = datetime.now(timezone.utc) + access_token_expiration

    # Generación del token JWT
    access_token = encode(
        {
            'sub': user.username,
            'iat': datetime.now(timezone.utc),
            'exp': expiration,
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        'access_token': access_token,
        'token_type': 'bearer',
    }

# Endpoint para validar el token y obtener el usuario actual
@router.get('/validate')
async def me(user: User = Depends(current_user)) -> User:
    """
    Valida el token y obtiene el usuario actual.

    :param user: Usuario actual en el token.
    :return: Usuario actual sin la contraseña.
    """
    return user

# Endpoint para crear un nuevo usuario
@router.post('/create', status_code=201)
async def new_user(user: UserDB) -> User:
    """
    Crea un nuevo usuario.

    :param user: Objeto UserDB con los datos del nuevo usuario.
    :return: Usuario creado sin la contraseña.
    """
    if search_user('email', user.email):
        raise HTTPException(status_code=409, detail='Usuario ya existe')

    password_hash = crypt.hash(user.password)
    user.password = password_hash

    user_dict = dict(user)

    # Elimina el campo "disabled" si está presente
    if "disabled" in user_dict:
        del user_dict['disabled']

    # Inserta el usuario en la base de datos
    client.usersdb.insert_one(user_dict)

    # Actualiza el usuario para agregar el campo "disabled"
    client.usersdb.update_one(
        {'email': user.email},
        {'$set': {'disabled': False}}
    )

    # Obtiene el nuevo usuario de la base de datos
    user_new = client.usersdb.find_one({'email': user.email})

    return User(**user_new)
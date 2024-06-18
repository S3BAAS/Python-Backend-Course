from fastapi import FastAPI
from routers import user_db, users, auth_users, jwt_auth
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# Routers
app.include_router(user_db.router)
app.include_router(users.router)
app.include_router(auth_users.router)
app.include_router(jwt_auth.router)

# Static files
# '/static' es la ruta de acceso en la página.
# 'directory' es la ruta en la que se encuentran los archivos estáticos.
# 'name' es el nombre interno asignado para esta configuración.
app.mount('/static/images', StaticFiles(directory='static/images'), name='static')



@app.get("/")
async def root():
    return {"message": "Hello World"}
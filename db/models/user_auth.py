from pydantic import BaseModel

class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool | None = None


class UserDB(User):
    password: str
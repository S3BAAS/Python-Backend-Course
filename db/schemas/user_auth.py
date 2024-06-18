def dict_not_password(user) -> dict:
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "disabled": bool(user["disabled"])
    }

def dict_password(user) -> dict:
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "disabled": bool(user["disabled"]),
        "password": user["password"]
    }
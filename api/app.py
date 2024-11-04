from fastapi import FastAPI
from pydantic import BaseModel
from fastapi import HTTPException
app = FastAPI(description="TP5 API")

@app.get("/")
async def root():
    return {}

@app.get("/miscellaneous/addition")
async def addition(a: float, b: float):
    return {"result": a + b}

class User(BaseModel):
    username: str
    password: str

users_db = []

@app.post("/users", status_code=201)
async def create_user(user: User):
    if any(u['username'] == user.username for u in users_db):
        raise HTTPException(status_code=400, detail="User already exists.")
    users_db.append(user.dict())
    return {"username": user.username, "todo_count": 0}

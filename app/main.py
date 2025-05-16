# main.py

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.database import Base, engine
from app.router import router
import os

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

app.include_router(router)

@app.get("/")
async def root():
    return {"message": "Welcome to the API"}

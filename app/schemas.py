# schemas.py

from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
    class Config:
        orm_mode = True

class ShowUser(BaseModel):
    id: int
    email: EmailStr
    is_active: bool
    role: str

    class Config:
        orm_mode = True  




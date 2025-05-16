# schemas.py

from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: Optional[str] = "user"

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
    class Config:
        from_attributes = True

class ShowUser(BaseModel):
    id: int
    email: EmailStr
    is_active: bool
    role: str

    class Config:
        from_attributes = True  
class UserUpdate(BaseModel):
    email: str
    role: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
class PasswordResetTokenBase(BaseModel):
    short_code: str
    token: str
    expires_at: datetime

class PasswordResetTokenCreate(PasswordResetTokenBase):
    user_id: int

class PasswordResetTokenOut(PasswordResetTokenBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True




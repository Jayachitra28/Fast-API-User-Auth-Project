# models.py

from sqlalchemy import Column, Integer, String, Boolean,DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)  
    email = Column(String, unique=True, index=True, nullable=False)  
    hashed_password = Column(String, nullable=False)  
    is_active = Column(Boolean, default=True) 
    role = Column(String, default="user") 
    delete_requested = Column(Boolean, default=False)  
    reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")
class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    short_code = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reset_tokens")


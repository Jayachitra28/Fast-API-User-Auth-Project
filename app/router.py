# main.py

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app import models, schemas, utils, auth, email_utils
from app.database import engine, SessionLocal, Base
from fastapi.responses import HTMLResponse
from fastapi import Form
from fastapi import Request
from fastapi.responses import JSONResponse
from authlib.integrations.starlette_client import OAuth,OAuthError
import os
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter



# Base.metadata.create_all(bind=engine)

router = APIRouter()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY"))

oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    client_kwargs={
        'scope': 'email openid profile',
        
    }
)
@router.get('/google-login')
async def google_login(request: Request):
    redirect_uri = request.url_for('google_auth')  
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/google-auth/callback')
async def google_auth(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
            return JSONResponse(
                status_code=400,
                content={"error": e.error}
            )
    user = token.get('userinfo')
    if user:
        request.session['user'] = dict(user)
    return RedirectResponse(url='/welcome')

@router.get('/welcome')
async def welcome(request: Request):
    user = request.session.get('user')
    if user:
        name = user.get('name', 'User')
        html_content = f"""
            <h2>Welcome, {name}!</h2>
            <a href="/google-logout">Logout</a>
        """
        return HTMLResponse(content=html_content, status_code=200)
    return HTMLResponse(content="<h2>User not logged in.</h2>", status_code=401)

@router.get('/google-logout')
async def logout(request: Request):
    request.session.pop('user', None)
    request.session.clear()
    return RedirectResponse(url='/')

@router.post("/register", response_model=schemas.ShowUser)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pwd = utils.hash_password(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_pwd,role=user.role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    email_utils.send_welcome_email(user.email)
    return new_user

@router.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not utils.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = auth.create_access_token(data={"sub": db_user.email})

    return {
        "access_token": token,
        "token_type": "bearer"
    }

@router.get("/protected")
def get_protected_user_data(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)):
    current_user = auth.verify_token(token, db)
    return {"message": "Hello, secure world!", "user_email": current_user.email}

@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users

@router.put("/user_update/{user_id}")
def update_user(user_id: int, updated_data: schemas.UserUpdate, db: Session = Depends(get_db),token: str = Depends(auth.oauth2_scheme)):
    current_user = auth.verify_token(token, db)
    auth.check_admin_permission(current_user)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.email = updated_data.email
    user.role = updated_data.role
    db.commit()
    db.refresh(user)
    
    return {"message": "User updated successfully", "user": user}

@router.delete("/user_delete/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db),token: str = Depends(auth.oauth2_scheme)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    current_user = auth.verify_token(token, db)
    auth.check_superadmin_permission(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@router.post("/forgot-password")
def forgot_password(user: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Email not found")

    short_code = secrets.token_urlsafe(6)  # e.g., 'abc123'
    expiry = datetime.utcnow() + timedelta(minutes=15)

    reset_entry = models.PasswordResetToken(
        short_code=short_code,
        user_id=db_user.id,
        expires_at=expiry
    )
    db.add(reset_entry)
    db.commit()

    reset_link = f"http://localhost:8000/reset-password/{short_code}"
    email_utils.send_reset_email(user.email, reset_link)

    return {"message": "Password reset link has been sent to your email"}

@router.get("/reset-password/{short_code}")
def reset_password_get(short_code: str, db: Session = Depends(get_db)):
    reset_entry = db.query(models.PasswordResetToken).filter_by(short_code=short_code).first()
    if not reset_entry or reset_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    return HTMLResponse(content=f"""
        <h1>Reset your password</h1>
        <form action='/reset-password/{short_code}' method='POST'>
            New Password: <input type="password" name="new_password">
            <button type="submit">Submit</button>
        </form>
    """, status_code=200)

@router.post("/reset-password/{short_code}")
def reset_password_post(
    short_code: str,
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    reset_entry = db.query(models.PasswordResetToken).filter_by(short_code=short_code).first()
    if not reset_entry or reset_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    user = db.query(models.User).filter_by(id=reset_entry.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = utils.hash_password(new_password)
    db.delete(reset_entry) 
    db.commit()

    return HTMLResponse(content="<h3>Password has been reset successfully!</h3>", status_code=200)

token_blacklist = set()
@router.post("/logout")
def logout(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)):
    token = token.replace("Bearer ", "")
    try:
        current_user = auth.verify_token(token, db, token_blacklist)
        token_blacklist.add(token)
    except Exception as e:
        print("Error:", str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    return {"message": "Logged out successfully"}

# Create API for Standard User to Request Deletion
@router.post("/request-delete")
def request_delete(db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    current_user = auth.verify_token(token, db)
    if current_user.role == "superadmin":
        raise HTTPException(status_code=400, detail="Superadmin cannot request account deletion")
    current_user.delete_requested = True
    db.commit()
    return {"message": "Account deletion requested. Superadmin will review it."}

# API for Superadmin to View Deletion Requests
@router.get("/deletion-requests")
def get_deletion_requests(db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    current_user = auth.verify_token(token, db)
    auth.check_superadmin_permission(current_user)
    requests = db.query(models.User).filter(models.User.delete_requested == True).all()
    return requests

# API for Superadmin to Approve/Delete User
@router.delete("/approve-delete/{user_id}")
def approve_user_deletion(user_id: int, db: Session = Depends(get_db), token: str = Depends(auth.oauth2_scheme)):
    current_user = auth.verify_token(token, db)
    auth.check_superadmin_permission(current_user)

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.delete_requested:
        raise HTTPException(status_code=400, detail="No deletion request found for this user")
    
    db.delete(user)
    db.commit()
    return {"message": f"User ID {user_id} deleted successfully"}






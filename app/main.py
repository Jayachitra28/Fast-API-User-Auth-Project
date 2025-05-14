# main.py

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app import models, schemas, utils, auth, email_utils
from app.database import engine, SessionLocal, Base
from fastapi.responses import HTMLResponse
from fastapi import Form

Base.metadata.create_all(bind=engine)

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=schemas.ShowUser)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pwd = utils.hash_password(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_pwd)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    email_utils.send_welcome_email(user.email)
    return new_user

@app.post("/login")
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

@app.get("/protected")
def get_protected_user_data(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)):
    current_user = auth.verify_token(token, db)
    return {"message": "Hello, secure world!", "user_email": current_user.email}

@app.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users

@app.put("/user_update/{user_id}")
def update_user(user_id: int, updated_data: schemas.UserUpdate, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.email = updated_data.email
    user.role = updated_data.role
    db.commit()
    db.refresh(user)
    
    return {"message": "User updated successfully", "user": user}

@app.delete("/user_delete/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@app.post("/forgot-password")
def forgot_password(user:schemas.ForgotPasswordRequest , db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    print("db_user",db_user)
    if not db_user:
        raise HTTPException(status_code=404, detail="Email not found")

    token = auth.create_access_token(data={"sub": db_user.email})
    print("token",token)
    reset_link = f"http://localhost:8000/reset-password?token={token}"
    print("reset_link",reset_link)
    print("user.mail",user.email,)
    email_utils.send_reset_email(user.email, reset_link)

    return {"message": "Password reset link has been sent to your email"}


@app.get("/reset-password")
def reset_password_get(token: str, db: Session = Depends(get_db)):
    try:
        current_user = auth.verify_token(token, db)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    return HTMLResponse(content=f"""
        <h1>Reset your password</h1>
        <form action='/reset-password' method='POST'>
            <input type="hidden" name="token" value="{token}">
            New Password: <input type="password" name="new_password">
            <button type="submit">Submit</button>
        </form>
    """, status_code=200)

@app.post("/reset-password")
def reset_password_post(
    new_password: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)
):
    try:
        current_user = auth.verify_token(token, db)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.email == current_user.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = utils.hash_password(new_password)
    db.commit()

    return HTMLResponse(content="<h3>Password has been reset successfully!</h3>", status_code=200)

token_blacklist = set()
@app.post("/logout")
def logout(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)):
    token = token.replace("Bearer ", "")
    try:
        current_user = auth.verify_token(token, db, token_blacklist)
        token_blacklist.add(token)
    except Exception as e:
        print("Error:", str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    return {"message": "Logged out successfully"}
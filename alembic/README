# FastAPI User Authentication and Authorization

This FastAPI project provides user authentication and authorization features with support for both **Email/Password-based login** and **Google OAuth login**. It also implements user management, including the creation, updating, and deletion of users with different roles: **Superadmin**, **Admin**, and **Standard User**.

## Features

- **Email/password-based authentication**: Allows users to log in using their email and password.
- **Google OAuth authentication**: Allows users to log in using their Google account.
- **User Management**: Superadmin, Admin, and Standard Users can be created, updated, or deleted.
  - **Roles**: Superadmin, Admin, and Standard User roles with different levels of access.
  - **Superadmin**: Can manage all users and assign roles.
  - **Admin**: Can manage Standard Users.
  - **Standard User**: Limited permissions, cannot delete their account without approval.
- **Send Welcome Email**: Sends a welcome email after successful registration.
- **Forgot Password API**: Allows users to reset their password via email.
- **Account Deletion Request**: Standard Users can request their account deletion, and Superadmin must approve it.

## Technologies Used

- **FastAPI**: Web framework for building APIs.
- **Uvicorn**: ASGI server for running the FastAPI application.
- **Pydantic**: Data validation and parsing using Python type annotations.
- **SQLAlchemy**: ORM for database interactions.
- **Google OAuth**: OAuth2 integration for Google login.
- **JWT**: JSON Web Tokens for user authentication.
- **SMTP**: For sending emails (e.g., welcome email, password reset).

## Installation

### 1. Clone the repository:
```bash
git clone <repository-url>
cd <project-directory>

Create a virtual environment and activate it:
python -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate  # For Windows

Install dependencies:
pip install -r requirements.txt

Run the application:
uvicorn app.main:app --reload




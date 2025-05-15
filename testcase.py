import unittest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app import main, models, schemas, utils, auth, email_utils
from fastapi.responses import HTMLResponse


class TestRegisterUser(unittest.TestCase):
    def test_register_user_success(self):
        mock_db = MagicMock(spec=Session)
        user_input = schemas.UserCreate(email="test@example.com", password="password123", role="user")
        mock_db.query().filter().first.return_value = None
        with patch("app.utils.hash_password", return_value="hashed_pwd"), \
             patch("app.email_utils.send_welcome_email") as mock_send_email:
            result = main.register_user(user=user_input, db=mock_db)

            self.assertEqual(result.email, user_input.email)
            self.assertEqual(result.hashed_password, "hashed_pwd")
            self.assertEqual(result.role, user_input.role)
            mock_send_email.assert_called_once_with(user_input.email)

    def test_register_user_existing_email(self):
        mock_db = MagicMock(spec=Session)
        user_input = schemas.UserCreate(email="test@example.com", password="secret", role="user")
        mock_db.query().filter().first.return_value = models.User(
            email="test@example.com", hashed_password="some_pwd", role="user"
        )
        with self.assertRaises(HTTPException) as context:
            main.register_user(user=user_input, db=mock_db)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Email already registered")


class TestLoginUser(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=Session)
        self.user_input = schemas.UserLogin(
            email="test@example.com", password="password123"
        )
        self.db_user = models.User(
            email="test@example.com", hashed_password="hashed_pwd", role="user"
        )

    @patch("app.utils.verify_password", return_value=True)
    @patch("app.auth.create_access_token", return_value="mocked_token")
    def test_login_success(self, mock_create_token, mock_verify_pwd):
        self.mock_db.query().filter().first.return_value = self.db_user

        response = main.login(user=self.user_input, db=self.mock_db)

        self.assertEqual(response["access_token"], "mocked_token")
        self.assertEqual(response["token_type"], "bearer")
        mock_verify_pwd.assert_called_once_with("password123", "hashed_pwd")
        mock_create_token.assert_called_once_with(data={"sub": "test@example.com"})

    def test_login_invalid_email(self):
        self.mock_db.query().filter().first.return_value = None
        with self.assertRaises(HTTPException) as context:
            main.login(user=self.user_input, db=self.mock_db)

        self.assertEqual(context.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(context.exception.detail, "Invalid email or password")

    @patch("app.utils.verify_password", return_value=False)
    def test_login_invalid_password(self, mock_verify_pwd):
        self.mock_db.query().filter().first.return_value = self.db_user
        with self.assertRaises(HTTPException) as context:
            main.login(user=self.user_input, db=self.mock_db)
        self.assertEqual(context.exception.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(context.exception.detail, "Invalid email or password")
        mock_verify_pwd.assert_called_once_with("password123", "hashed_pwd")

class TestUpdateUser(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=Session)
        self.user_id = 1
        self.updated_data = schemas.UserUpdate(email="new@example.com", role="admin")
        self.existing_user = models.User(id=1, email="old@example.com", role="user")

    @patch("app.auth.verify_token")
    @patch("app.auth.check_admin_permission")
    def test_update_user_success(self, mock_check_admin, mock_verify_token):
        mock_verify_token.return_value = self.existing_user  
        mock_check_admin.return_value = None
        self.mock_db.query().filter().first.return_value = self.existing_user
        response = main.update_user(
            user_id=self.user_id,
            updated_data=self.updated_data,
            db=self.mock_db,
            token="valid_token"
        )
        self.assertEqual(response["message"], "User updated successfully")
        self.assertEqual(response["user"].email, "new@example.com")
        self.assertEqual(response["user"].role, "admin")
        self.mock_db.commit.assert_called_once()
        self.mock_db.refresh.assert_called_once_with(self.existing_user)

    @patch("app.auth.verify_token")
    @patch("app.auth.check_admin_permission")
    def test_update_user_not_found(self, mock_check_admin, mock_verify_token):
        mock_verify_token.return_value = self.existing_user
        mock_check_admin.return_value = None
        self.mock_db.query().filter().first.return_value = None
        with self.assertRaises(HTTPException) as context:
            main.update_user(
                user_id=self.user_id,
                updated_data=self.updated_data,
                db=self.mock_db,
                token="valid_token"
            )
        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "User not found")

class TestDeleteUser(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=Session)
        self.user_id = 1
        self.existing_user = models.User(id=1, email="old@example.com", role="user")
    @patch("app.auth.verify_token")
    @patch("app.auth.check_superadmin_permission")
    def test_delete_user_success(self, mock_check_superadmin, mock_verify_token):
        mock_verify_token.return_value = self.existing_user
        mock_check_superadmin.return_value = None
        self.mock_db.query().filter().first.return_value = self.existing_user
        response = main.delete_user(
            user_id=self.user_id,
            db=self.mock_db,
            token="valid_token"
        )
        self.assertEqual(response["message"], "User deleted successfully")
        self.mock_db.delete.assert_called_once_with(self.existing_user)
        self.mock_db.commit.assert_called_once()

    @patch("app.auth.verify_token")
    @patch("app.auth.check_superadmin_permission")
    def test_delete_user_not_found(self, mock_check_superadmin, mock_verify_token):
        mock_verify_token.return_value = self.existing_user
        mock_check_superadmin.return_value = None
        self.mock_db.query().filter().first.return_value = None
        with self.assertRaises(HTTPException) as context:
            main.delete_user(
                user_id=self.user_id,
                db=self.mock_db,
                token="valid_token"
            )
        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "User not found")

class TestPasswordReset(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=Session)
        self.test_email = "test@example.com"
        self.test_user = models.User(id=1, email=self.test_email, hashed_password="oldhashed")
        self.valid_token = "validtoken123"
        self.new_password = "newpassword"

    @patch("app.email_utils.send_reset_email")
    @patch("app.auth.create_access_token")
    def test_forgot_password_success(self, mock_create_token, mock_send_email):
        mock_create_token.return_value = self.valid_token
        self.mock_db.query().filter().first.return_value = self.test_user
        request_data = schemas.ForgotPasswordRequest(email=self.test_email)

        response = main.forgot_password(user=request_data, db=self.mock_db)

        self.assertEqual(response["message"], "Password reset link has been sent to your email")
        mock_create_token.assert_called_once_with(data={"sub": self.test_email})
        reset_link = f"http://localhost:8000/reset-password?token={self.valid_token}"
        mock_send_email.assert_called_once_with(self.test_email, reset_link)

    def test_forgot_password_email_not_found(self):
        self.mock_db.query().filter().first.return_value = None
        request_data = schemas.ForgotPasswordRequest(email=self.test_email)

        with self.assertRaises(HTTPException) as context:
            main.forgot_password(user=request_data, db=self.mock_db)

        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "Email not found")

    @patch("app.auth.verify_token")
    def test_reset_password_get_success(self, mock_verify_token):
        mock_verify_token.return_value = self.test_user
        token = self.valid_token

        response = main.reset_password_get(token=token, db=self.mock_db)

        self.assertIsInstance(response, HTMLResponse)
        self.assertIn("Reset your password", response.body.decode())
        self.assertIn(token, response.body.decode())

    @patch("app.auth.verify_token")
    def test_reset_password_get_invalid_token(self, mock_verify_token):
        mock_verify_token.side_effect = Exception("Invalid token")
        token = "invalidtoken"

        with self.assertRaises(HTTPException) as context:
            main.reset_password_get(token=token, db=self.mock_db)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Invalid or expired token")

    @patch("app.auth.verify_token")
    @patch("app.utils.hash_password")
    def test_reset_password_post_success(self, mock_hash_password, mock_verify_token):
        mock_verify_token.return_value = self.test_user
        self.mock_db.query().filter().first.return_value = self.test_user
        mock_hash_password.return_value = "newhashedpassword"

        response = main.reset_password_post(new_password=self.new_password, token=self.valid_token, db=self.mock_db)

        self.assertIsInstance(response, HTMLResponse)
        self.assertIn("Password has been reset successfully", response.body.decode())
        self.assertEqual(self.test_user.hashed_password, "newhashedpassword")
        self.mock_db.commit.assert_called_once()
        mock_hash_password.assert_called_once_with(self.new_password)

    @patch("app.auth.verify_token")
    def test_reset_password_post_invalid_token(self, mock_verify_token):
        mock_verify_token.side_effect = Exception("Invalid token")

        with self.assertRaises(HTTPException) as context:
            main.reset_password_post(new_password=self.new_password, token="invalidtoken", db=self.mock_db)

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "Invalid or expired token")

    @patch("app.auth.verify_token")
    def test_reset_password_post_user_not_found(self, mock_verify_token):
        mock_verify_token.return_value = self.test_user
        self.mock_db.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as context:
            main.reset_password_post(new_password=self.new_password, token=self.valid_token, db=self.mock_db)

        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.detail, "User not found")

class TestLogout(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=Session)
        self.valid_token = "validtoken123"
        self.invalid_token = "invalidtoken"
        self.token_blacklist = set()

    @patch("app.auth.verify_token")
    def test_logout_success(self, mock_verify_token):
        mock_verify_token.return_value = "testuser"

        response = main.logout(token=self.valid_token, db=self.mock_db)

        self.assertEqual(response["message"], "Logged out successfully")
        self.assertIn(self.valid_token.replace("Bearer ", ""), main.token_blacklist)

    @patch("app.auth.verify_token")
    def test_logout_invalid_token(self, mock_verify_token):
        mock_verify_token.side_effect = Exception("Invalid token")

        with self.assertRaises(HTTPException) as context:
            main.logout(token=self.invalid_token, db=self.mock_db)

        self.assertEqual(context.exception.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(context.exception.detail, "Invalid or expired token")

class TestUserDeletionRequests(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.token = "validtoken"
        self.superadmin_user = models.User(id=1, role="superadmin", delete_requested=False)
        self.standard_user = models.User(id=2, role="user", delete_requested=False)
        self.user_with_request = models.User(id=3, role="user", delete_requested=True)

    @patch("app.auth.verify_token")
    def test_request_delete_standard_user_success(self, mock_verify_token):
        mock_verify_token.return_value = self.standard_user
        response = main.request_delete(db=self.mock_db, token=self.token)
        self.assertEqual(response["message"], "Account deletion requested. Superadmin will review it.")
        self.assertTrue(self.standard_user.delete_requested)
        self.mock_db.commit.assert_called_once()

    @patch("app.auth.verify_token")
    def test_request_delete_superadmin_forbidden(self, mock_verify_token):
        mock_verify_token.return_value = self.superadmin_user
        with self.assertRaises(HTTPException) as ctx:
            main.request_delete(db=self.mock_db, token=self.token)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "Superadmin cannot request account deletion")

    @patch("app.auth.verify_token")
    def test_get_deletion_requests_success(self, mock_verify_token):
        mock_verify_token.return_value = self.superadmin_user
        self.mock_db.query().filter().all.return_value = [self.user_with_request]

        requests = main.get_deletion_requests(db=self.mock_db, token=self.token)
        self.assertEqual(requests, [self.user_with_request])
        self.mock_db.query().filter().all.assert_called_once()

    @patch("app.auth.verify_token")
    @patch("app.auth.check_superadmin_permission")
    def test_approve_user_deletion_success(self, mock_check_permission, mock_verify_token):
        mock_verify_token.return_value = self.superadmin_user
        mock_check_permission.return_value = None
        self.mock_db.query().filter().first.return_value = self.user_with_request

        response = main.approve_user_deletion(user_id=self.user_with_request.id, db=self.mock_db, token=self.token)
        self.assertEqual(response["message"], f"User ID {self.user_with_request.id} deleted successfully")
        self.mock_db.delete.assert_called_once_with(self.user_with_request)
        self.mock_db.commit.assert_called_once()

    @patch("app.auth.verify_token")
    @patch("app.auth.check_superadmin_permission")
    def test_approve_user_deletion_user_not_found(self, mock_check_permission, mock_verify_token):
        mock_verify_token.return_value = self.superadmin_user
        mock_check_permission.return_value = None
        self.mock_db.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as ctx:
            main.approve_user_deletion(user_id=999, db=self.mock_db, token=self.token)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail, "User not found")

    @patch("app.auth.verify_token")
    @patch("app.auth.check_superadmin_permission")
    def test_approve_user_deletion_no_request_found(self, mock_check_permission, mock_verify_token):
        mock_verify_token.return_value = self.superadmin_user
        mock_check_permission.return_value = None
        self.mock_db.query().filter().first.return_value = self.standard_user

        with self.assertRaises(HTTPException) as ctx:
            main.approve_user_deletion(user_id=self.standard_user.id, db=self.mock_db, token=self.token)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "No deletion request found for this user")


if __name__ == '__main__':
    unittest.main()

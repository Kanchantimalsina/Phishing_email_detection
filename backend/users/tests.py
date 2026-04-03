from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


User = get_user_model()


class UserRegistrationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = '/api/users/register/'

    def test_user_registration_success(self):
        """Test successful user registration with valid data."""
        data = {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'full_name': 'New User',
            'password': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'newuser@example.com')

    def test_user_registration_password_mismatch(self):
        """Test registration fails when passwords don't match."""
        data = {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'full_name': 'New User',
            'password': 'StrongPass123!',
            'password2': 'DifferentPass123!',
        }
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_user_registration_weak_password(self):
        """Test registration fails with weak password."""
        data = {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'full_name': 'New User',
            'password': '123',
            'password2': '123',
        }
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_user_registration_duplicate_email(self):
        """Test registration fails with duplicate email."""
        User.objects.create_user(
            email='existing@example.com',
            username='existing',
            password='StrongPass123!'
        )
        data = {
            'email': 'existing@example.com',
            'username': 'newuser',
            'full_name': 'New User',
            'password': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.register_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class UserLoginTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = '/api/users/login/'
        self.user = User.objects.create_user(
            email='testuser@example.com',
            username='testuser',
            full_name='Test User',
            password='StrongPass123!'
        )

    def test_login_success(self):
        """Test successful login with correct credentials."""
        data = {
            'email': 'testuser@example.com',
            'password': 'StrongPass123!',
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'testuser@example.com')

    def test_login_invalid_email(self):
        """Test login fails with invalid email."""
        data = {
            'email': 'nonexistent@example.com',
            'password': 'StrongPass123!',
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_login_wrong_password(self):
        """Test login fails with wrong password."""
        data = {
            'email': 'testuser@example.com',
            'password': 'WrongPassword123!',
        }
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)


class UserLogoutTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.logout_url = '/api/users/logout/'
        self.user = User.objects.create_user(
            email='testuser@example.com',
            username='testuser',
            full_name='Test User',
            password='StrongPass123!'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)
        self.refresh_token = str(self.refresh)

    def test_logout_success(self):
        """Test successful logout with valid refresh token."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')
        data = {'refresh': self.refresh_token}
        response = self.client.post(self.logout_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)

    def test_logout_invalid_token(self):
        """Test logout fails with invalid refresh token."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')
        data = {'refresh': 'invalid-token'}
        response = self.client.post(self.logout_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_requires_authentication(self):
        """Test logout endpoint requires authentication."""
        data = {'refresh': self.refresh_token}
        response = self.client.post(self.logout_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserProfileTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.profile_url = '/api/users/profile/'
        self.user = User.objects.create_user(
            email='testuser@example.com',
            username='testuser',
            full_name='Test User',
            password='StrongPass123!'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)

    def test_get_user_profile(self):
        """Test retrieving user profile returns correct data."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')
        response = self.client.get(self.profile_url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'testuser@example.com')
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['full_name'], 'Test User')

    def test_update_user_profile(self):
        """Test updating user profile works correctly."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access}')
        data = {'full_name': 'Updated User Name'}
        response = self.client.put(self.profile_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['full_name'], 'Updated User Name')

        # Verify update persisted
        self.user.refresh_from_db()
        self.assertEqual(self.user.full_name, 'Updated User Name')

    def test_profile_requires_authentication(self):
        """Test profile endpoint requires authentication."""
        response = self.client.get(self.profile_url, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.token_refresh_url = '/api/users/token/refresh/'
        self.user = User.objects.create_user(
            email='testuser@example.com',
            username='testuser',
            full_name='Test User',
            password='StrongPass123!'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(self.refresh)

    def test_token_refresh_success(self):
        """Test refreshing access token with valid refresh token."""
        data = {'refresh': self.refresh_token}
        response = self.client.post(self.token_refresh_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_token_refresh_invalid_token(self):
        """Test token refresh fails with invalid token."""
        data = {'refresh': 'invalid-token'}
        response = self.client.post(self.token_refresh_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

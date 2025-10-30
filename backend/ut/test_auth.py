import pytest
from fastapi.testclient import TestClient

def test_register_user_success(client: TestClient):
    """Prueba el registro exitoso de un nuevo usuario."""
    response = client.post(
        "/auth/register",
        json={"username": "testagent", "email": "test@agent.com", "password": "strongpassword123"},
    )
    assert response.status_code == 201 # Un registro exitoso debe devolver 201 Created
    data = response.json()
    assert "access_token" in data
    assert "encrypted_private_key" in data
    assert data["token_type"] == "bearer"

def test_register_user_duplicate_username(client: TestClient, register_user):
    """Prueba que no se puede registrar un usuario con un nombre de usuario existente."""
    # Registrar el primer usuario
    register_user("duplicate_user", "password123")

    # Intentar registrar de nuevo con el mismo nombre de usuario
    response = client.post(
        "/auth/register",
        json={"username": "duplicate_user", "email": "another@email.com", "password": "password123"},
    )
    assert response.status_code == 400
    assert "Username already taken" in response.json()["detail"] # El mensaje de error real de la API

def test_login_success(client: TestClient, register_user):
    """Prueba el inicio de sesión exitoso con credenciales correctas."""
    user = register_user("login_user", "password123")

    response = client.post(
        "/auth/login",
        data={"username": user["data"]["username"], "password": user["data"]["password"]},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "encrypted_private_key" in data

def test_login_incorrect_password(client: TestClient, register_user):
    """Prueba que el inicio de sesión falla con una contraseña incorrecta."""
    user = register_user("wrong_pass_user", "correct_password")

    response = client.post(
        "/auth/login",
        data={"username": user["data"]["username"], "password": "wrong_password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"
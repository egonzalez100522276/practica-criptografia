import pytest
import sqlite3
from fastapi.testclient import TestClient

# Monkeypatching para sobreescribir la conexión de la DB antes de importar la app
from app.db import database
database.DATABASE_URL = ":memory:"

from app.main import app
from app.db.database import get_db
from app.db.init_db import create_tables

# --- Configuración de la Base de Datos de Prueba ---
@pytest.fixture(scope="function")
def test_db():
    """
    Fixture para crear una base de datos SQLite en memoria para cada función de prueba.
    Esto asegura que cada prueba se ejecute en un entorno limpio y aislado.
    """
    # Ignoramos el get_connection() global y creamos una conexión nueva y fresca
    # a una base de datos en memoria para CADA test. Esto es clave para el aislamiento.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Habilitar claves foráneas
    conn.execute("PRAGMA foreign_keys = ON;")

    # Crear las tablas en la base de datos de prueba usando la conexión actual.
    # Esto asume que `create_tables` ha sido modificada para aceptar un objeto de conexión.
    create_tables(conn)

    # `yield` proporciona la conexión a la función de prueba
    yield conn

    # Después de que la prueba termina, se cierra la conexión
    conn.close()


@pytest.fixture(scope="function")
def client(test_db):
    """
    Fixture que crea un cliente de prueba de FastAPI.
    Sobrescribe la dependencia `get_db` para usar la base de datos de prueba en memoria.
    """

    def override_get_db():
        """
        Una dependencia de FastAPI que reemplaza la original `get_db`.
        Usa la conexión aislada del fixture `test_db` para esta prueba específica.
        """
        cursor = test_db.cursor()
        try:
            yield cursor
            test_db.commit()
        except:
            test_db.rollback()
            raise

    # Aplicar el override a la aplicación FastAPI
    app.dependency_overrides[get_db] = override_get_db

    # Crear y devolver el cliente de prueba
    with TestClient(app) as test_client:
        yield test_client

    # Limpiar el override después de la prueba para no afectar a otros tests si los hubiera
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def register_user(client, test_db): # Añadimos test_db como dependencia
    """Fixture de utilidad para registrar un usuario y devolver sus datos."""
    registered_users = {}

    def _register(username, password):
        # Si el usuario ya fue registrado en este test, devolver los datos cacheados.
        # Esto evita errores de "usuario ya existe" si se llama varias veces en el mismo test.
        if username in registered_users:
            return registered_users[username]

        user_data = {"username": username, "email": f"{username}@test.com", "password": password}
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 201, f"Failed to register user {username}. Response: {response.text}"
        
        response_json = response.json()

        # Consultar la base de datos para obtener el ID del usuario,
        # ya que el endpoint /auth/register podría no devolverlo directamente.
        cursor = test_db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id_row = cursor.fetchone()
        assert user_id_row is not None, f"User {username} not found in DB after registration."
        response_json['user_id'] = user_id_row['id'] # Añadimos el user_id a la respuesta para comodidad en los tests

        result = {"data": user_data, "response": response_json}
        registered_users[username] = result
        return result
    return _register
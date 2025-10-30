import pytest
import sqlite3
from fastapi.testclient import TestClient

# Monkeypatching to override the DB connection before importing the app
from app.db import database
database.DATABASE_URL = ":memory:"

from app.main import app
from app.db.database import get_db
from app.db.init_db import create_tables

# --- Test Database Configuration ---
@pytest.fixture(scope="function")
def test_db():
    """
    Fixture to create an in-memory SQLite database for each test function.
    This ensures that each test runs in a clean and isolated environment.
    """
    # We ignore the global get_connection() and create a new, fresh connection
    # to an in-memory database for EACH test. This is key for isolation.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON;")

    # Create the tables in the test database using the current connection.
    # This assumes that `create_tables` has been modified to accept a connection object.
    create_tables(conn)

    # `yield` provides the connection to the test function
    yield conn

    # After the test finishes, the connection is closed
    conn.close()


@pytest.fixture(scope="function")
def client(test_db):
    """
    Fixture that creates a FastAPI test client.
    It overrides the `get_db` dependency to use the in-memory test database.
    """

    def override_get_db():
        """
        A FastAPI dependency that replaces the original `get_db`.
        It uses the isolated connection from the `test_db` fixture for this specific test.
        """
        cursor = test_db.cursor()
        try:
            yield cursor
            test_db.commit()
        except:
            test_db.rollback()
            raise

    # Apply the override to the FastAPI application
    app.dependency_overrides[get_db] = override_get_db

    # Create and return the test client
    with TestClient(app) as test_client:
        yield test_client

    # Clean up the override after the test to not affect other tests if any
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def register_user(client, test_db): # We add test_db as a dependency
    """Utility fixture to register a user and return their data."""
    registered_users = {}

    def _register(username, password):
        # If the user was already registered in this test, return the cached data.
        # This avoids "user already exists" errors if called multiple times in the same test.
        if username in registered_users:
            return registered_users[username]

        user_data = {"username": username, "email": f"{username}@test.com", "password": password}
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 201, f"Failed to register user {username}. Response: {response.text}"

        response_json = response.json()

        # Query the database to get the user's ID,
        # as the /auth/register endpoint might not return it directly.
        cursor = test_db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id_row = cursor.fetchone()
        assert user_id_row is not None, f"User {username} not found in DB after registration."
        response_json['user_id'] = user_id_row['id'] # We add the user_id to the response for convenience in tests

        result = {"data": user_data, "response": response_json}
        registered_users[username] = result
        return result
    return _register
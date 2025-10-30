import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from app.core.security import decrypt_private_key

def test_create_mission_unauthenticated(client: TestClient):
    """Prueba que un usuario no autenticado no puede crear una misión."""
    response = client.post(
        "/missions/",
        json={"content": {"title": "Test Mission", "description": "This should fail."}},
    )
    assert response.status_code == 401  # Unauthorized

def test_create_and_decrypt_own_mission(client: TestClient, register_user):
    """Prueba el flujo completo: crear una misión y luego descifrarla."""
    # 1. Registrar y obtener token y clave
    agent1_data = register_user("agent1", "password123")
    agent1_token = agent1_data["response"]["access_token"]
    agent1_enc_key = agent1_data["response"]["encrypted_private_key"]
    agent1_password = agent1_data["data"]["password"]

    # 2. Crear una misión
    mission_content = {"title": "Solo Mission", "description": "My eyes only."}
    response_create = client.post(
        "/missions/",
        headers={"Authorization": f"Bearer {agent1_token}"},
        json={"content": mission_content},
    )
    assert response_create.status_code == 201
    created_mission = response_create.json()
    assert created_mission["content"]["title"] == mission_content["title"]

    # 3. Descifrar la clave privada del agente
    agent1_priv_key_obj = decrypt_private_key(agent1_enc_key, agent1_password)
    assert agent1_priv_key_obj is not None

    # Convertir el objeto de clave privada a formato PEM (string) para poder enviarlo como JSON
    agent1_priv_key_pem_str = agent1_priv_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # 4. Pedir al backend que descifre las misiones del agente
    response_decrypt = client.post(
        "/missions/mine/decrypt",
        headers={"Authorization": f"Bearer {agent1_token}"},
        json={"private_key_pem": agent1_priv_key_pem_str},
    )
    assert response_decrypt.status_code == 200
    decrypted_missions = response_decrypt.json()
    
    assert len(decrypted_missions) == 1
    assert decrypted_missions[0]["content"]["title"] == mission_content["title"]
    assert decrypted_missions[0]["content"]["description"] == mission_content["description"]

def test_share_and_receive_mission(client: TestClient, register_user):
    """Prueba el flujo de compartir una misión de un agente a otro."""
    # 1. Registrar dos agentes
    agent_creator_data = register_user("creator_agent", "pass_creator")
    agent_receiver_data = register_user("receiver_agent", "pass_receiver")
    # solo se recibe el access_token
    creator_token = agent_creator_data["response"]["access_token"]
    creator_enc_key = agent_creator_data["response"]["encrypted_private_key"]
    creator_password = agent_creator_data["data"]["password"]
    receiver_id = agent_receiver_data["response"]["user_id"] # Acceso correcto al ID del usuario
    receiver_enc_key = agent_receiver_data["response"]["encrypted_private_key"] 
    receiver_password = agent_receiver_data["data"]["password"]

    # 2. El agente creador crea una misión
    mission_content = {"title": "Shared Task", "description": "For your eyes only."}
    response_create = client.post(
        "/missions/",
        headers={"Authorization": f"Bearer {creator_token}"},
        json={"content": mission_content},
    )
    assert response_create.status_code == 201
    mission_id = response_create.json()["id"]

    # 3. El agente creador comparte la misión con el agente receptor
    # Primero, necesitamos la clave privada del creador en formato PEM.
    creator_priv_key_obj = decrypt_private_key(creator_enc_key, creator_password)
    assert creator_priv_key_obj is not None
    creator_priv_key_pem_str = creator_priv_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    response_share = client.post(
        f"/missions/{mission_id}/share",
        headers={"Authorization": f"Bearer {creator_token}"},
        # Usamos la clave PEM descifrada, no la cifrada.
        json={"user_ids": [receiver_id], "private_key_pem": creator_priv_key_pem_str},
    )
    assert response_share.status_code == 200
    assert "Mission shared successfully" in response_share.json()["message"]

    # 4. El agente receptor intenta descifrar sus misiones compartidas
    # Primero, el receptor necesita su propia clave privada PEM
    receiver_priv_key_obj = decrypt_private_key(receiver_enc_key, receiver_password)
    assert receiver_priv_key_obj is not None

    # Convertir el objeto de clave a formato PEM (string)
    receiver_priv_key_pem_str = receiver_priv_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Ahora, el receptor pide al backend que descifre las misiones compartidas con él
    receiver_token = agent_receiver_data["response"]["access_token"]
    response_decrypt_shared = client.post(
        "/missions/shared/decrypt",
        headers={"Authorization": f"Bearer {receiver_token}"},
        json={"private_key_pem": receiver_priv_key_pem_str},
    )
    assert response_decrypt_shared.status_code == 200
    
    shared_missions = response_decrypt_shared.json()
    assert len(shared_missions) == 1
    
    received_mission = shared_missions[0]
    assert received_mission["content"]["title"] == mission_content["title"]
    assert received_mission["content"]["description"] == mission_content["description"]
    assert received_mission["creator_username"] == "creator_agent"
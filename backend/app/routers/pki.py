from fastapi import APIRouter
from ..core import pki

router = APIRouter()

@router.get("/ca-public-key")
def get_ca_public_key():
    """
    Returns the CA's public key for client-side signature verification.
    """
    public_key_pem = pki.get_ca_public_key_pem()
    return {"public_key_pem": public_key_pem}

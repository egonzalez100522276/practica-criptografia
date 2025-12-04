from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
from dotenv import load_dotenv

# Load .env file
dotenv_path = Path(__file__).resolve().parent.parent.parent / '.env'
load_dotenv(dotenv_path)

# Paths for CA private key and certificate
BASE_DIR = Path(__file__).resolve().parent
CA_KEY_PATH = BASE_DIR / "ca_private_key.pem"
CA_CERT_PATH = BASE_DIR / "ca_certificate.pem"

# Load password for encrypting the CA private key
CA_PASSWORD_STR = os.getenv("CA_PASSWORD")
if not CA_PASSWORD_STR:
    raise RuntimeError("CA_PASSWORD is not set in the environment variables.")
CA_PASSWORD = CA_PASSWORD_STR.encode("utf-8")


# ---------------------------------------------------------
#  CA CREATION / LOADING
# ---------------------------------------------------------

def generate_or_load_ca(ca_key_path: Path = CA_KEY_PATH,
                        ca_cert_path: Path = CA_CERT_PATH):
    """
    Load existing CA key/certificate or generate a new pair.
    The CA private key is encrypted using a password from .env.
    """
    if ca_key_path.exists() and ca_cert_path.exists():
        # Load encrypted private key
        with open(ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=CA_PASSWORD
            )

        # Load certificate
        with open(ca_cert_path, "rb") as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read())

        return ca_private_key, ca_certificate

    # --- Create new CA ---

    # Generate RSA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Build self-signed CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiApp CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MiApp Root CA"),
    ])

    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    # Save encrypted CA private key
    with open(ca_key_path, "wb") as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSWORD)
            )
        )

    # Save CA certificate (always public)
    with open(ca_cert_path, "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    return ca_private_key, ca_certificate


# ---------------------------------------------------------
#  USER CERTIFICATE GENERATION
# ---------------------------------------------------------

def create_user_certificate(user_public_pem: str, username: str,
                            ca_private_key: rsa.RSAPrivateKey,
                            ca_certificate: x509.Certificate,
                            validity_days: int = 365) -> str:
    """
    Creates a X.509 certificate for a user, signed by the CA.
    """
    user_public_key = serialization.load_pem_public_key(user_public_pem.encode())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiApp Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# ---------------------------------------------------------
#  USER CERTIFICATE VALIDATION
# ---------------------------------------------------------

def validate_user_certificate(user_cert_pem: str, ca_certificate: x509.Certificate) -> bool:
    """
    Validates a user certificate by checking:
      1) The date validity
      2) The signature using the CA public key
    """
    try:
        user_cert = x509.load_pem_x509_certificate(user_cert_pem.encode())

        now = datetime.now(timezone.utc)
        if now < user_cert.not_valid_before_utc or now > user_cert.not_valid_after_utc:
            return False

        # Verify CA signature
        ca_public_key = ca_certificate.public_key()
        ca_public_key.verify(
            signature=user_cert.signature,
            data=user_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=user_cert.signature_hash_algorithm,
        )

        return True

    except InvalidSignature:
        return False
    except Exception:
        return False


if __name__ == "__main__":
    generate_or_load_ca()
    print("✅ CA generated or loaded successfully")

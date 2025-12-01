from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
from pathlib import Path
import os

# Route where the CA key and certificate will be saved
BASE_DIR = Path(__file__).resolve().parent
CA_KEY_PATH = BASE_DIR / "ca_private_key.pem"
CA_CERT_PATH = BASE_DIR / "ca_certificate.pem"

def generate_or_load_ca(ca_key_path: Path = CA_KEY_PATH, ca_cert_path: Path = CA_CERT_PATH):
    """
    Generate the CA root if it doesn't exist, or load the existing one.
    Returns (ca_private_key, ca_certificate)
    """
    if ca_key_path.exists() and ca_cert_path.exists():
        # Load private key
        with open(ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Load certificate
        with open(ca_cert_path, "rb") as f:
            ca_certificate = x509.load_pem_x509_certificate(f.read())

        return ca_private_key, ca_certificate

    # Generate new private key
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create self-signed certificate
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
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # Save to files
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(ca_cert_path, "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    return ca_private_key, ca_certificate





# --- X.509 certificates ---

def create_user_certificate(user_public_pem: str, username: str,
                            ca_private_key: rsa.RSAPrivateKey,
                            ca_certificate: x509.Certificate,
                            validity_days: int = 365) -> str:
    """
    Generates a X.509 certificate for a user, signed by the root CA.

    Args:
        user_public_pem: User's public RSA key in PEM format.
        username: Username of the user.
        ca_private_key: Root CA private key for signing.
        ca_certificate: Root CA certificate.
        validity_days: Validity of the certificate in days.

    Returns:
        User certificate in PEM format (str).
    """
    from cryptography.hazmat.primitives import serialization

    # Load user's public key from PEM
    user_public_key = serialization.load_pem_public_key(user_public_pem.encode())

    # Build the certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiApp Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    # Build the certificate
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    # Convert to PEM
    user_cert_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return user_cert_pem


if __name__ == "__main__":
    generate_or_load_ca()
    print("✅ CA generated successfully")
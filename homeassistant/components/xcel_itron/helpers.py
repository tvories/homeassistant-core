from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from datetime import datetime, timedelta
from .const import DEFAULT_GENERATED_CERT_FILENAME, DEFAULT_GENERATED_KEY_FILENAME, DEFAULT_FILE_ENCODING
import os


def generate_cert_and_key() -> dict:
    # Generate the private key
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Use prime256v1 curve for equivalent functionality
        default_backend(),
    )

    # Create a certificate signing request (CSR)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "MeterReaderHanClient"),
        ]
    )
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Create a self-signed certificate using the CSR
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=1094)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Serialize the private key and certificate to strings
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode(DEFAULT_FILE_ENCODING)

    cert_str = certificate.public_bytes(serialization.Encoding.PEM).decode(DEFAULT_FILE_ENCODING)

    # Calculate the lfdi fingerprint
    lfdi_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

    # Return the result as a dictionary
    return {
        "certificate": cert_str,
        "private_key": private_key_str,
        "lfdi": lfdi_fingerprint,
    }

def get_lfdi(certificate: str) -> str:
    """Return the lfdi fingerprint from a certificate."""
    cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex()

def get_existing_cert_and_key(hass_path: str, path: str) -> dict:
    """Check if a certificate and key already exist and return the values if they do."""
    cert_path = os.path.join(hass_path, path, DEFAULT_GENERATED_CERT_FILENAME)
    key_path = os.path.join(hass_path, path, DEFAULT_GENERATED_KEY_FILENAME)
    cert = None
    key = None

    if os.path.exists(cert_path):
        with open(cert_path, "r", encoding=DEFAULT_FILE_ENCODING) as file:
            cert = file.read()

    if os.path.exists(key_path):
        with open(key_path, "r", encoding=DEFAULT_FILE_ENCODING) as file:
            key = file.read()

    if cert is not None and key is not None:
        return {
            "certificate": cert,
            "private_key": key,
            "lfdi": get_lfdi(cert),
        }
    else:
        return None
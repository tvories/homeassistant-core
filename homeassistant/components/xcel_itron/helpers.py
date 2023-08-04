from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from datetime import datetime, timedelta
import os


def generate_cert_and_key():
    # Generate the private key
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Use prime256v1 curve for equivalent functionality
        default_backend(),
    )

    # Generate the public key and create a certificate signing request (CSR)
    public_key = private_key.public_key()
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
    ).decode("utf-8")

    cert_str = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Calculate the lfdi fingerprint
    lfdi_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

    # Return the result as a dictionary
    return {
        "certificate": cert_str,
        "private_key": private_key_str,
        "lfdi": lfdi_fingerprint,
    }


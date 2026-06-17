"""
Gera o par de chaves RSA 2048-bit e o certificado autoassinado do servidor.
"""
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID


def main():
    # key privada rsa 2048
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)


    # gravar pem
    with open("server_private.pem", "wb") as f:
        f.write(sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMessagingServer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TP3-SegInfo"),
    ])
    # certificado autoassinado x509 
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(sk, hashes.SHA256())
    ) #certificado é comparado com o certificado a copia local que o cliente possui
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    pk_fp = sk.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib
    fp = hashlib.sha256(pk_fp).hexdigest()
    print("Certificado gerado:")
    print(f"  server_private.pem  (chave privada RSA 2048-bit)")
    print(f"  server.crt          (certificado autoassinado)")
    print(f"  Fingerprint SHA-256: {fp[:32]}...")


if __name__ == "__main__":
    main()

"""为本地 MCP 和 OAuth 服务生成一套开发 CA 与 HTTPS 证书。"""

import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .settings import MockSettings

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048
CERTIFICATE_CLOCK_SKEW = timedelta(minutes=5)


def generate_certificates(settings: MockSettings):
    """生成服务证书及 CA；已有完整证书时直接复用。"""
    paths = settings.tls
    files = (
        paths.certificate,
        paths.private_key,
        paths.ca_certificate,
        paths.ca_private_key,
    )
    if all(path.is_file() for path in files):
        return
    if any(path.exists() for path in files):
        raise FileExistsError("TLS 文件不完整，请指定新的证书目录或恢复缺失文件")
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=paths.valid_days)
    ca_key = rsa.generate_private_key(RSA_PUBLIC_EXPONENT, RSA_KEY_SIZE)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "AgentKit Mock Development CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CERTIFICATE_CLOCK_SKEW)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(RSA_PUBLIC_EXPONENT, RSA_KEY_SIZE)
    names = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    if settings.public_host != "localhost":
        names.append(x509.DNSName(settings.public_host))
    server = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, settings.public_host)])
        )
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CERTIFICATE_CLOCK_SKEW)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    for path, key in ((paths.ca_private_key, ca_key), (paths.private_key, server_key)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
    paths.ca_certificate.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths.certificate.write_bytes(server.public_bytes(serialization.Encoding.PEM))

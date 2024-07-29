import os
from pathlib import Path

from OpenSSL import crypto


def create_CA(out_path: Path) -> tuple[crypto.X509, crypto.PKey]:
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(3)
    ca_cert.set_serial_number(int.from_bytes(os.urandom(4), "big"))

    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = "PyLocalSend CA"
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
    ])

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(1 * 365 * 24 * 60 * 60)

    ca_cert.sign(ca_key, "sha256")

    with open(out_path / "ca_cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

    with open(out_path / "ca_key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

    return ca_cert, ca_key


def create_cert(out_path: Path) -> str:
    ca_cert, ca_key = create_CA(out_path)
    ca_subj = ca_cert.get_issuer()

    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)

    client_cert = crypto.X509()
    client_cert.set_version(3)
    client_cert.set_serial_number(int.from_bytes(os.urandom(4), "big"))

    client_subj = client_cert.get_subject()
    client_subj.commonName = "PyLocalSend"

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    client_cert.sign(ca_key, "sha256")

    with open(out_path / "cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert))

    with open(out_path / "key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key))

    return client_cert.digest("sha256").replace(b":", b"").decode("utf8").upper()

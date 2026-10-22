"""Testes automatizados para o motor criptográfico (PFX, JKS, PEM, Montagem de PFX e ICP-Brasil)."""

import datetime
import os
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from core.crypto_engine import (
    build_pfx_from_files,
    extract_entry_files,
    inspect_certificate,
    load_keystore_file,
    save_jks_file,
    save_pkcs12_file,
    verify_key_matches_certificate,
)
from core.models import EntryType, KeyStoreFormat


def _encode_asn1_octet_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return bytes([0x04, len(raw)]) + raw


def test_full_workflow() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root_key = rsa.generate_private_key(65537, 2048)
        inter_key = rsa.generate_private_key(65537, 2048)
        leaf_key = rsa.generate_private_key(65537, 2048)

        now = datetime.datetime.now(datetime.timezone.utc)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC Raiz Corporativa ICP-Brasil")])
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC Intermediaria Corporativa")])
        leaf_name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ICP-Brasil"),
                x509.NameAttribute(NameOID.COMMON_NAME, "EMPRESA EXEMPLO S.A.:12345678000199"),
            ]
        )

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(100)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        inter_cert = (
            x509.CertificateBuilder()
            .subject_name(inter_name)
            .issuer_name(root_name)
            .public_key(inter_key.public_key())
            .serial_number(200)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        oid_resp_dados = "15051985" + "11122233344" + "12345678901" + "000000123456789" + "SSP/SP    "
        san_icp = x509.SubjectAlternativeName(
            [
                x509.DNSName("nfe.empresa.com.br"),
                x509.OtherName(ObjectIdentifier("2.16.76.1.3.2"), _encode_asn1_octet_string("JOAO DA SILVA")),
                x509.OtherName(ObjectIdentifier("2.16.76.1.3.3"), _encode_asn1_octet_string("12345678000199")),
                x509.OtherName(ObjectIdentifier("2.16.76.1.3.4"), _encode_asn1_octet_string(oid_resp_dados)),
            ]
        )

        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(inter_name)
            .public_key(leaf_key.public_key())
            .serial_number(300)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san_icp, critical=False)
            .sign(inter_key, hashes.SHA256())
        )

        cert_file = os.path.join(tmpdir, "servidor.crt")
        key_file = os.path.join(tmpdir, "servidor.key")
        bundle_file = os.path.join(tmpdir, "ca-bundle.crt")
        built_pfx_file = os.path.join(tmpdir, "montado.pfx")
        converted_jks_file = os.path.join(tmpdir, "convertido.jks")

        with open(cert_file, "wb") as f:
            f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb") as f:
            f.write(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(b"senha_key"),
                )
            )
        with open(bundle_file, "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
            f.write(inter_cert.public_bytes(serialization.Encoding.PEM))

        doc_pfx = build_pfx_from_files(
            cert_path=cert_file,
            key_path=key_file,
            key_password="senha_key",
            chain_paths=[bundle_file],
            output_pfx_path=built_pfx_file,
            pfx_password="senha_pfx_123",
            alias="cert_empresa",
            legacy_encryption=False,
        )
        assert os.path.isfile(built_pfx_file)
        assert len(doc_pfx.entries) == 1

        reloaded_pfx = load_keystore_file(built_pfx_file, "senha_pfx_123")
        entry = reloaded_pfx.entries[0]
        assert entry.alias == "cert_empresa"
        assert entry.entry_type == EntryType.KEY_PAIR
        assert verify_key_matches_certificate(entry.private_key, entry.certificate)
        assert len(entry.chain) == 2

        details = inspect_certificate(entry.certificate)
        assert details.icp_brasil.is_icp_brasil is True
        assert details.icp_brasil.cnpj == "12.345.678/0001-99"
        assert details.icp_brasil.cpf == "111.222.333-44"
        assert details.icp_brasil.nome_responsavel == "JOAO DA SILVA"

        save_jks_file(reloaded_pfx, converted_jks_file, password="senha_jks_123")
        reloaded_jks = load_keystore_file(converted_jks_file, "senha_jks_123")
        assert reloaded_jks.ks_format == KeyStoreFormat.JKS
        assert len(reloaded_jks.entries) == 1

        extract_dir = os.path.join(tmpdir, "extraidos")
        extracted = extract_entry_files(
            entry=reloaded_jks.entries[0],
            output_dir=extract_dir,
            base_filename="kit_servidor",
            export_cert_pem=True,
            export_cert_der=True,
            export_key_pem=True,
            key_password=None,
            export_chain_bundle=True,
            export_fullchain=True,
        )
        assert len(extracted) == 5

    print("TODOS OS TESTES PASSARAM COM SUCESSO!")


if __name__ == "__main__":
    test_full_workflow()

"""Motor criptográfico otimizado para leitura, edição, conversão e montagem de KeyStores (.pfx, .p12, .jks, .pem, .crt, .key)."""

import datetime
import os
import re
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple

warnings.filterwarnings("ignore", message=".*serial number.*")

import jks
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import NameOID

from core.models import (
    CertificateDetails,
    EntryType,
    ICPBrasilInfo,
    KeyStoreDocument,
    KeyStoreEntry,
    KeyStoreFormat,
)


def _decode_asn1_string(der_bytes: bytes) -> str:
    """Decodifica um valor ASN.1 DER simples (OCTET STRING, UTF8String, PrintableString, IA5String)."""
    if not der_bytes:
        return ""
    data = der_bytes
    for _ in range(3):
        if len(data) < 2:
            break
        tag = data[0]
        if tag in (0x04, 0x0C, 0x13, 0x16, 0x1E, 0xA0):
            length_byte = data[1]
            if length_byte < 0x80:
                header_len = 2
                content_len = length_byte
            else:
                num_len_bytes = length_byte & 0x7F
                if len(data) < 2 + num_len_bytes:
                    break
                content_len = int.from_bytes(data[2 : 2 + num_len_bytes], "big")
                header_len = 2 + num_len_bytes
            if len(data) >= header_len + content_len:
                data = data[header_len : header_len + content_len]
                continue
        break
    try:
        return data.decode("utf-8").strip("\x00")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace").strip("\x00")


def _format_cpf(cpf: str) -> str:
    digits = re.sub(r"\D", "", cpf)
    if len(digits) == 11 and digits != "0" * 11:
        return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"
    return ""


def _format_cnpj(cnpj: str) -> str:
    digits = re.sub(r"\D", "", cnpj)
    if len(digits) == 14 and digits != "0" * 14:
        return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"
    return ""


def extract_icp_brasil_info(cert: x509.Certificate) -> ICPBrasilInfo:
    """Extrai dados dos OIDs oficiais da ICP-Brasil (DOC-ICP-04) se presentes no certificado."""
    info = ICPBrasilInfo()

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for general_name in san:
            if isinstance(general_name, x509.OtherName):
                oid = general_name.type_id.dotted_string
                val = _decode_asn1_string(general_name.value)
                if not val:
                    continue

                if oid == "2.16.76.1.3.1":
                    info.is_icp_brasil = True
                    if not info.tipo_certificado:
                        info.tipo_certificado = "e-CPF (Pessoa Física)"
                    if len(val) >= 19:
                        info.cpf = _format_cpf(val[8:19]) or info.cpf

                elif oid == "2.16.76.1.3.2":
                    info.is_icp_brasil = True
                    info.nome_responsavel = val.strip()

                elif oid == "2.16.76.1.3.3":
                    info.is_icp_brasil = True
                    info.tipo_certificado = "e-CNPJ (Pessoa Jurídica)"
                    info.cnpj = _format_cnpj(val) or val.strip()

                elif oid == "2.16.76.1.3.4":
                    info.is_icp_brasil = True
                    info.tipo_certificado = "e-CNPJ (Pessoa Jurídica)"
                    if len(val) >= 19:
                        info.cpf = _format_cpf(val[8:19]) or info.cpf
    except Exception:
        pass

    try:
        for attr in cert.subject:
            val_str = str(attr.value)
            if attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME and "ICP-Brasil" in val_str:
                info.is_icp_brasil = True
            elif attr.oid == NameOID.COMMON_NAME and ":" in val_str:
                suffix = val_str.rsplit(":", 1)[1].strip()
                if len(suffix) == 14 and suffix.isdigit() and not info.cnpj:
                    info.is_icp_brasil = True
                    info.tipo_certificado = info.tipo_certificado or "e-CNPJ (Pessoa Jurídica)"
                    info.cnpj = _format_cnpj(suffix)
                elif len(suffix) == 11 and suffix.isdigit() and not info.cpf:
                    info.is_icp_brasil = True
                    info.tipo_certificado = info.tipo_certificado or "e-CPF (Pessoa Física)"
                    info.cpf = _format_cpf(suffix)
    except Exception:
        pass

    return info


def get_common_name(name: x509.Name) -> str:
    """Retorna o Common Name (CN) ou representação amigável do Subject/Issuer."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    attrs_ou = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if attrs_ou:
        return str(attrs_ou[0].value)
    attrs_o = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if attrs_o:
        return str(attrs_o[0].value)
    return name.rfc4514_string() or "(Sem Nome)"


_CERT_DETAILS_CACHE: Dict[int, Tuple[x509.Certificate, CertificateDetails]] = {}


def inspect_certificate(cert: x509.Certificate) -> CertificateDetails:
    """Extrai informações detalhadas de um objeto x509.Certificate com cache em memória."""
    cert_id = id(cert)
    cached = _CERT_DETAILS_CACHE.get(cert_id)
    if cached is not None and cached[0] is cert:
        return cached[1]

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    days_remaining = (not_after - now).days

    pub_key = cert.public_key()
    pub_size = getattr(pub_key, "key_size", 0)
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_alg = f"RSA ({pub_size} bits)"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_alg = f"ECC / ECDSA ({pub_key.curve.name}, {pub_size} bits)"
    else:
        pub_alg = f"{type(pub_key).__name__} ({pub_size} bits)" if pub_size else type(pub_key).__name__

    fp_sha256_bytes = cert.fingerprint(hashes.SHA256())
    fp_sha1_bytes = cert.fingerprint(hashes.SHA1())
    sha256_fp = ":".join(f"{b:02X}" for b in fp_sha256_bytes)
    sha1_fp = ":".join(f"{b:02X}" for b in fp_sha1_bytes)

    serial_num = cert.serial_number
    serial_hex_raw = f"{serial_num:X}"
    if len(serial_hex_raw) % 2 != 0:
        serial_hex_raw = "0" + serial_hex_raw
    serial_hex = ":".join(serial_hex_raw[i : i + 2] for i in range(0, len(serial_hex_raw), 2))

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        pass

    is_self_signed = cert.subject == cert.issuer

    san_entries: List[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for gn in san:
            if isinstance(gn, x509.DNSName):
                san_entries.append(f"DNS: {gn.value}")
            elif isinstance(gn, x509.RFC822Name):
                san_entries.append(f"E-mail: {gn.value}")
            elif isinstance(gn, x509.IPAddress):
                san_entries.append(f"IP: {gn.value}")
            elif isinstance(gn, x509.UniformResourceIdentifier):
                san_entries.append(f"URI: {gn.value}")
            elif isinstance(gn, x509.OtherName):
                decoded = _decode_asn1_string(gn.value)
                san_entries.append(f"OID {gn.type_id.dotted_string}: {decoded}")
    except x509.ExtensionNotFound:
        pass

    pem_text = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    sig_alg = getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string)

    details = CertificateDetails(
        common_name=get_common_name(cert.subject),
        subject_dn=cert.subject.rfc4514_string(),
        issuer_cn=get_common_name(cert.issuer),
        issuer_dn=cert.issuer.rfc4514_string(),
        serial_hex=serial_hex,
        not_before=not_before,
        not_after=not_after,
        is_expired=is_expired,
        is_not_yet_valid=is_not_yet_valid,
        days_remaining=days_remaining,
        signature_algorithm=sig_alg,
        public_key_algorithm=pub_alg,
        sha256_fingerprint=sha256_fp,
        sha1_fingerprint=sha1_fp,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        san_entries=san_entries,
        icp_brasil=extract_icp_brasil_info(cert),
        pem_text=pem_text,
    )
    if len(_CERT_DETAILS_CACHE) > 2000:
        _CERT_DETAILS_CACHE.clear()
    _CERT_DETAILS_CACHE[cert_id] = (cert, details)
    return details


def verify_key_matches_certificate(private_key: Any, cert: x509.Certificate) -> bool:
    """Verifica matematicamente se a chave privada corresponde à chave pública do certificado."""
    try:
        pub_from_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_from_cert = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_from_key == pub_from_cert
    except Exception:
        return False


def order_certificate_chain(
    leaf_cert: Optional[x509.Certificate],
    other_certs: List[x509.Certificate],
) -> Tuple[Optional[x509.Certificate], List[x509.Certificate]]:
    """Ordena automaticamente a cadeia de certificados: (certificado_principal, [intermediarias..., raiz])."""
    all_certs: List[x509.Certificate] = []
    seen_fps = set()

    for c in ([leaf_cert] if leaf_cert else []) + list(other_certs):
        if c is None:
            continue
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen_fps:
            seen_fps.add(fp)
            all_certs.append(c)

    if not all_certs:
        return None, []

    if leaf_cert is None:
        issuer_subjects = {c.issuer for c in all_certs if c.subject != c.issuer}
        candidates = [c for c in all_certs if c.subject not in issuer_subjects]
        leaf_cert = candidates[0] if candidates else all_certs[0]

    leaf_fp = leaf_cert.fingerprint(hashes.SHA256())
    remaining = [c for c in all_certs if c.fingerprint(hashes.SHA256()) != leaf_fp]

    ordered_chain: List[x509.Certificate] = []
    current = leaf_cert
    while remaining:
        next_cert = None
        for candidate in remaining:
            if candidate.subject == current.issuer:
                next_cert = candidate
                break
        if next_cert is None:
            ordered_chain.extend(remaining)
            break
        ordered_chain.append(next_cert)
        remaining.remove(next_cert)
        current = next_cert

    return leaf_cert, ordered_chain


def load_certificates_from_bytes(data: bytes) -> List[x509.Certificate]:
    """Carrega 1 ou mais certificados a partir de bytes (PEM múltiplos, DER único ou PKCS#7 .p7b)."""
    certs: List[x509.Certificate] = []

    if b"-----BEGIN CERTIFICATE-----" in data or b"-----BEGIN TRUSTED CERTIFICATE-----" in data:
        try:
            certs.extend(x509.load_pem_x509_certificates(data))
            if certs:
                return certs
        except Exception:
            pattern = re.compile(
                b"-----BEGIN (?:TRUSTED )?CERTIFICATE-----.+?-----END (?:TRUSTED )?CERTIFICATE-----",
                re.DOTALL,
            )
            for match in pattern.findall(data):
                try:
                    certs.append(x509.load_pem_x509_certificate(match))
                except Exception:
                    pass
            if certs:
                return certs

    if b"-----BEGIN PKCS7-----" in data:
        try:
            return pkcs7.load_pem_pkcs7_certificates(data)
        except Exception:
            pass

    try:
        return [x509.load_der_x509_certificate(data)]
    except Exception:
        pass

    try:
        return pkcs7.load_der_pkcs7_certificates(data)
    except Exception:
        pass

    raise ValueError("Não foi possível reconhecer certificados X.509 válidos no arquivo informado.")


def load_private_key_from_bytes(data: bytes, password: Optional[str] = None) -> Any:
    """Carrega uma chave privada (PEM ou DER, criptografada ou não)."""
    pwd_bytes = password.encode("utf-8") if password else None

    if b"-----BEGIN " in data and b"PRIVATE KEY-----" in data:
        try:
            return serialization.load_pem_private_key(data, password=pwd_bytes)
        except TypeError:
            return serialization.load_pem_private_key(data, password=None)

    try:
        return serialization.load_der_private_key(data, password=pwd_bytes)
    except TypeError:
        return serialization.load_der_private_key(data, password=None)


def load_keystore_file(file_path: str, password: Optional[str] = None) -> KeyStoreDocument:
    """Carrega arquivos PKCS#12 (.pfx / .p12), Java KeyStore (.jks / .jceks / cacerts) ou PEM/CRT/CER/KEY."""
    with open(file_path, "rb") as f:
        data = f.read()

    ext = os.path.splitext(file_path)[1].lower()
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    if data[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce"):
        return _load_jks_bytes(data, file_path, password)

    if ext in (".pfx", ".p12", ".jks", ".keystore"):
        try:
            doc = _load_pkcs12_bytes(data, file_path, password)
            if ext == ".jks":
                doc.ks_format = KeyStoreFormat.PKCS12
            return doc
        except ValueError as e:
            if ext == ".jks":
                return _load_jks_bytes(data, file_path, password)
            raise e

    entries: List[KeyStoreEntry] = []
    loaded_key = None
    loaded_certs: List[x509.Certificate] = []

    if b"PRIVATE KEY-----" in data or ext == ".key":
        try:
            loaded_key = load_private_key_from_bytes(data, password)
        except Exception as e:
            if ext == ".key":
                raise ValueError(f"Erro ao carregar chave privada (verifique a senha): {e}") from e

    try:
        loaded_certs = load_certificates_from_bytes(data)
    except Exception:
        if loaded_key is None:
            try:
                return _load_pkcs12_bytes(data, file_path, password)
            except Exception as exc:
                raise ValueError("Formato de arquivo não reconhecido ou senha incorreta.") from exc

    if loaded_key is not None and loaded_certs:
        matched_leaf = None
        others = []
        for c in loaded_certs:
            if matched_leaf is None and verify_key_matches_certificate(loaded_key, c):
                matched_leaf = c
            else:
                others.append(c)
        if matched_leaf is None:
            matched_leaf, others = order_certificate_chain(None, loaded_certs)
        else:
            matched_leaf, others = order_certificate_chain(matched_leaf, others)

        alias = get_common_name(matched_leaf.subject) if matched_leaf else base_name
        entries.append(
            KeyStoreEntry(
                alias=alias,
                entry_type=EntryType.KEY_PAIR,
                certificate=matched_leaf,
                chain=others,
                private_key=loaded_key,
            )
        )
    elif loaded_key is not None:
        entries.append(
            KeyStoreEntry(
                alias=base_name,
                entry_type=EntryType.PRIVATE_KEY,
                private_key=loaded_key,
            )
        )
    elif loaded_certs:
        for idx, c in enumerate(loaded_certs):
            cn = get_common_name(c.subject)
            alias = cn if len(loaded_certs) == 1 else f"{cn} ({idx + 1})"
            entries.append(
                KeyStoreEntry(
                    alias=alias,
                    entry_type=EntryType.TRUSTED_CERT,
                    certificate=c,
                )
            )

    return KeyStoreDocument(
        ks_format=KeyStoreFormat.PEM,
        file_path=file_path,
        password=password,
        entries=entries,
        modified=False,
    )


def _load_pkcs12_bytes(data: bytes, file_path: str, password: Optional[str]) -> KeyStoreDocument:
    """Carrega um KeyStore PKCS#12 (.pfx / .p12)."""
    candidates = []
    if password is not None:
        candidates.append(password.encode("utf-8"))
        if password == "":
            candidates.append(None)
    else:
        candidates.extend([None, b""])

    p12 = None
    last_err = None
    used_pwd = password
    for pwd_bytes in candidates:
        try:
            p12 = pkcs12.load_pkcs12(data, pwd_bytes)
            used_pwd = pwd_bytes.decode("utf-8") if pwd_bytes is not None else ""
            break
        except Exception as err:
            last_err = err

    if p12 is None:
        raise ValueError(f"Não foi possível abrir o arquivo PKCS#12 (senha incorreta ou arquivo inválido): {last_err}")

    entries: List[KeyStoreEntry] = []
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    if p12.cert is not None or p12.key is not None:
        main_cert = p12.cert.certificate if p12.cert else None
        friendly = None
        if p12.cert and p12.cert.friendly_name:
            try:
                friendly = p12.cert.friendly_name.decode("utf-8", errors="replace")
            except Exception:
                friendly = str(p12.cert.friendly_name)
        alias = friendly or (get_common_name(main_cert.subject) if main_cert else base_name)

        add_certs = [ac.certificate for ac in p12.additional_certs if ac.certificate is not None]
        if main_cert is not None:
            main_cert, ordered_chain = order_certificate_chain(main_cert, add_certs)
        else:
            ordered_chain = add_certs

        entry_type = EntryType.KEY_PAIR if p12.key is not None else EntryType.TRUSTED_CERT
        entries.append(
            KeyStoreEntry(
                alias=alias,
                entry_type=entry_type,
                certificate=main_cert,
                chain=ordered_chain,
                private_key=p12.key,
            )
        )
    else:
        for idx, ac in enumerate(p12.additional_certs):
            c = ac.certificate
            friendly = ac.friendly_name.decode("utf-8", errors="replace") if ac.friendly_name else ""
            alias = friendly or get_common_name(c.subject) or f"cert_{idx + 1}"
            entries.append(
                KeyStoreEntry(
                    alias=alias,
                    entry_type=EntryType.TRUSTED_CERT,
                    certificate=c,
                )
            )

    return KeyStoreDocument(
        ks_format=KeyStoreFormat.PKCS12,
        file_path=file_path,
        password=used_pwd,
        entries=entries,
        modified=False,
    )


def _load_jks_bytes(data: bytes, file_path: str, password: Optional[str]) -> KeyStoreDocument:
    """Carrega um Java KeyStore (.jks / .jceks / cacerts) nativamente via pyjks (com ou sem senha)."""
    pwd_str = password if password is not None else ""

    if not pwd_str:
        candidates: List[Optional[str]] = ["", "changeit", "changeme", None]
    else:
        candidates = [pwd_str]

    ks = None
    last_err = None
    effective_pwd = pwd_str
    for cand in candidates:
        try:
            ks = jks.KeyStore.loads(data, cand)
            if cand is not None:
                effective_pwd = cand
            break
        except Exception as err:
            last_err = err

    if ks is None:
        raise ValueError(f"Não foi possível abrir o Java KeyStore (.jks) — verifique a senha: {last_err}")

    entries: List[KeyStoreEntry] = []

    for alias, pk_entry in ks.private_keys.items():
        if not pk_entry.is_decrypted():
            for key_pwd in (pwd_str, effective_pwd, "", "changeit", "changeme"):
                if key_pwd is None:
                    continue
                try:
                    pk_entry.decrypt(key_pwd)
                    if pk_entry.is_decrypted():
                        break
                except Exception:
                    pass

        raw_bytes = None
        jks_raw_pkey = None
        jks_alg_oid = None
        if pk_entry.is_decrypted():
            raw_bytes = pk_entry.pkey_pkcs8
            jks_raw_pkey = pk_entry.pkey
            jks_alg_oid = getattr(pk_entry, "_algorithm_oid", None)

        chain_certs: List[x509.Certificate] = []
        for _, cert_bytes in pk_entry.cert_chain:
            try:
                chain_certs.append(x509.load_der_x509_certificate(cert_bytes))
            except Exception:
                pass

        main_cert = chain_certs[0] if chain_certs else None
        rest_chain = chain_certs[1:] if len(chain_certs) > 1 else []

        entries.append(
            KeyStoreEntry(
                alias=alias,
                entry_type=EntryType.KEY_PAIR,
                certificate=main_cert,
                chain=rest_chain,
                private_key=None,
                raw_private_key_bytes=raw_bytes,
                jks_raw_pkey=jks_raw_pkey,
                jks_algorithm_oid=jks_alg_oid,
            )
        )

    for alias, cert_entry in ks.certs.items():
        try:
            c = x509.load_der_x509_certificate(cert_entry.cert)
            entries.append(
                KeyStoreEntry(
                    alias=alias,
                    entry_type=EntryType.TRUSTED_CERT,
                    certificate=c,
                )
            )
        except Exception:
            pass

    return KeyStoreDocument(
        ks_format=KeyStoreFormat.JKS,
        file_path=file_path,
        password=pwd_str,
        entries=entries,
        modified=False,
    )


def save_pkcs12_file(
    doc: KeyStoreDocument,
    output_path: str,
    password: Optional[str] = None,
    legacy_encryption: bool = False,
) -> None:
    """Salva um KeyStoreDocument como arquivo PKCS#12 (.pfx / .p12)."""
    pwd_to_use = password if password is not None else (doc.password or "")
    pwd_bytes = pwd_to_use.encode("utf-8") if pwd_to_use else None

    main_entry: Optional[KeyStoreEntry] = None
    extra_certs: List[x509.Certificate] = []

    for entry in doc.entries:
        if entry.entry_type == EntryType.KEY_PAIR and main_entry is None:
            main_entry = entry
        else:
            if entry.certificate is not None:
                extra_certs.append(entry.certificate)
            extra_certs.extend(entry.chain)

    if main_entry is not None:
        alias_bytes = main_entry.alias.encode("utf-8")
        priv_key = main_entry.private_key
        main_cert = main_entry.certificate
        cas = list(main_entry.chain) + extra_certs
    elif doc.entries:
        first = doc.entries[0]
        alias_bytes = first.alias.encode("utf-8")
        priv_key = None
        main_cert = first.certificate
        cas = list(first.chain) + extra_certs[1:] if extra_certs else list(first.chain)
    else:
        raise ValueError("O KeyStore está vazio. Adicione ao menos um certificado ou par de chaves antes de salvar.")

    unique_cas: List[x509.Certificate] = []
    seen = set()
    if main_cert is not None:
        seen.add(main_cert.fingerprint(hashes.SHA256()))
    for c in cas:
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            unique_cas.append(c)

    if pwd_bytes:
        if legacy_encryption:
            enc_algorithm = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .hmac_hash(hashes.SHA1())
                .build(pwd_bytes)
            )
        else:
            enc_algorithm = serialization.BestAvailableEncryption(pwd_bytes)
    else:
        enc_algorithm = serialization.NoEncryption()

    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=alias_bytes,
        key=priv_key,
        cert=main_cert,
        cas=unique_cas if unique_cas else None,
        encryption_algorithm=enc_algorithm,
    )

    with open(output_path, "wb") as f:
        f.write(p12_bytes)


def save_jks_file(
    doc: KeyStoreDocument,
    output_path: str,
    password: Optional[str] = None,
) -> None:
    """Salva o KeyStoreDocument no formato nativo Java KeyStore (.jks) de forma otimizada (com ou sem senha)."""
    pwd_to_use = password if password is not None else (doc.password if doc.password is not None else "")
    now_ms = int(time.time()) * 1000
    jks_entries = []

    for entry in doc.entries:
        if entry.entry_type == EntryType.KEY_PAIR and entry.certificate is not None:
            certs_list = [entry.certificate] + list(entry.chain)
            certs_der = [c.public_bytes(serialization.Encoding.DER) for c in certs_list]

            if entry.jks_raw_pkey is not None and entry.jks_algorithm_oid is not None:
                pk_obj = jks.PrivateKeyEntry(
                    timestamp=now_ms,
                    alias=entry.alias.lower(),
                    cert_chain=[("X.509", b) for b in certs_der],
                )
                pk_obj._algorithm_oid = entry.jks_algorithm_oid
                pk_obj.pkey = entry.jks_raw_pkey
                pk_obj.pkey_pkcs8 = entry.raw_private_key_bytes
                pk_obj.encrypt(pwd_to_use)
                jks_entries.append(pk_obj)
            elif entry.raw_private_key_bytes is not None and entry._private_key is None:
                pk_obj = jks.PrivateKeyEntry.new(
                    alias=entry.alias,
                    certs=certs_der,
                    key=entry.raw_private_key_bytes,
                    key_format="pkcs8",
                )
                pk_obj.encrypt(pwd_to_use)
                jks_entries.append(pk_obj)
            elif entry.private_key is not None:
                if isinstance(entry.private_key, rsa.RSAPrivateKey):
                    key_der = entry.private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    pk_obj = jks.PrivateKeyEntry.new(
                        alias=entry.alias,
                        certs=certs_der,
                        key=key_der,
                        key_format="rsa_raw",
                    )
                else:
                    key_der = entry.private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    pk_obj = jks.PrivateKeyEntry.new(
                        alias=entry.alias,
                        certs=certs_der,
                        key=key_der,
                        key_format="pkcs8",
                    )
                entry.jks_raw_pkey = pk_obj.pkey
                entry.jks_algorithm_oid = getattr(pk_obj, "_algorithm_oid", None)
                entry.raw_private_key_bytes = pk_obj.pkey_pkcs8
                pk_obj.encrypt(pwd_to_use)
                jks_entries.append(pk_obj)
        elif entry.certificate is not None:
            tc_obj = jks.TrustedCertEntry.new(
                alias=entry.alias,
                cert=entry.certificate.public_bytes(serialization.Encoding.DER),
            )
            jks_entries.append(tc_obj)

    ks = jks.KeyStore.new("jks", jks_entries)
    ks.save(output_path, pwd_to_use)


def build_pfx_from_files(
    cert_path: str,
    key_path: str,
    key_password: Optional[str],
    chain_paths: List[str],
    output_pfx_path: str,
    pfx_password: str,
    alias: Optional[str] = None,
    legacy_encryption: bool = False,
) -> KeyStoreDocument:
    """Monta um arquivo .pfx / .p12 a partir de Certificado (.crt) + Private Key (.key) + Cadeia."""
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    main_certs = load_certificates_from_bytes(cert_bytes)
    if not main_certs:
        raise ValueError("Nenhum certificado encontrado no arquivo de Certificado Principal.")

    with open(key_path, "rb") as f:
        key_bytes = f.read()
    priv_key = load_private_key_from_bytes(key_bytes, key_password)

    all_chain_certs: List[x509.Certificate] = list(main_certs[1:])
    for cp in chain_paths:
        if cp and os.path.isfile(cp):
            with open(cp, "rb") as cf:
                c_bytes = cf.read()
            all_chain_certs.extend(load_certificates_from_bytes(c_bytes))

    leaf_cert = main_certs[0]
    if not verify_key_matches_certificate(priv_key, leaf_cert):
        found_match = None
        for candidate in main_certs + all_chain_certs:
            if verify_key_matches_certificate(priv_key, candidate):
                found_match = candidate
                break
        if found_match is None:
            raise ValueError(
                "A Chave Privada informada NÃO corresponde à chave pública do Certificado selecionado! "
                "Verifique se o arquivo .key e o arquivo .crt pertencem ao mesmo par de chaves."
            )
        leaf_cert = found_match

    leaf_cert, ordered_chain = order_certificate_chain(leaf_cert, main_certs + all_chain_certs)
    final_alias = (alias or get_common_name(leaf_cert.subject) or "certificado").strip()

    entry = KeyStoreEntry(
        alias=final_alias,
        entry_type=EntryType.KEY_PAIR,
        certificate=leaf_cert,
        chain=ordered_chain,
        private_key=priv_key,
    )
    doc = KeyStoreDocument(
        ks_format=KeyStoreFormat.PKCS12,
        file_path=output_pfx_path,
        password=pfx_password,
        entries=[entry],
        modified=False,
        legacy_encryption=legacy_encryption,
    )
    save_pkcs12_file(doc, output_pfx_path, password=pfx_password, legacy_encryption=legacy_encryption)
    return doc


def extract_entry_files(
    entry: KeyStoreEntry,
    output_dir: str,
    base_filename: str,
    export_cert_pem: bool = True,
    export_cert_der: bool = False,
    export_key_pem: bool = True,
    key_password: Optional[str] = None,
    export_chain_bundle: bool = True,
    export_fullchain: bool = True,
) -> List[str]:
    """Extrai os componentes de uma entrada em arquivos separados (.crt, .key, .ca-bundle, fullchain)."""
    os.makedirs(output_dir, exist_ok=True)
    safe_base = re.sub(r'[<>:"/\\|?*]', "_", base_filename).strip() or "certificado"
    created_files: List[str] = []

    if export_cert_pem and entry.certificate is not None:
        cert_pem_path = os.path.join(output_dir, f"{safe_base}.crt")
        with open(cert_pem_path, "wb") as f:
            f.write(entry.certificate.public_bytes(serialization.Encoding.PEM))
        created_files.append(cert_pem_path)

    if export_cert_der and entry.certificate is not None:
        cert_der_path = os.path.join(output_dir, f"{safe_base}.cer")
        with open(cert_der_path, "wb") as f:
            f.write(entry.certificate.public_bytes(serialization.Encoding.DER))
        created_files.append(cert_der_path)

    if export_key_pem and entry.private_key is not None:
        key_path = os.path.join(output_dir, f"{safe_base}.key")
        if key_password:
            enc = serialization.BestAvailableEncryption(key_password.encode("utf-8"))
        else:
            enc = serialization.NoEncryption()
        key_bytes = entry.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        created_files.append(key_path)

    if export_chain_bundle and entry.chain:
        bundle_path = os.path.join(output_dir, f"{safe_base}-ca-bundle.crt")
        with open(bundle_path, "wb") as f:
            for c in entry.chain:
                f.write(c.public_bytes(serialization.Encoding.PEM))
        created_files.append(bundle_path)

    if export_fullchain and entry.certificate is not None:
        fullchain_path = os.path.join(output_dir, f"{safe_base}-fullchain.pem")
        with open(fullchain_path, "wb") as f:
            for c in entry.full_chain:
                f.write(c.public_bytes(serialization.Encoding.PEM))
        created_files.append(fullchain_path)

    return created_files

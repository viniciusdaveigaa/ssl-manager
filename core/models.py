"""Modelos de dados enxutos e otimizados para entradas de KeyStore, documentos e informações de certificados."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


class EntryType(str, Enum):
    KEY_PAIR = "KEY_PAIR"          # Chave Privada + Certificado (+ Cadeia)
    TRUSTED_CERT = "TRUSTED_CERT"  # Apenas Certificado Confiável / CA
    PRIVATE_KEY = "PRIVATE_KEY"    # Apenas Chave Privada isolada (ex: arquivo .key aberto)


class KeyStoreFormat(str, Enum):
    PKCS12 = "PKCS#12 (.pfx / .p12)"
    JKS = "Java KeyStore (.jks)"
    PEM = "Certificado / Chave (.pem / .crt / .cer / .key)"


@dataclass
class ICPBrasilInfo:
    """Informações principais extraídas dos OIDs padrão ICP-Brasil (e-CPF / e-CNPJ)."""
    is_icp_brasil: bool = False
    tipo_certificado: str = ""
    cnpj: str = ""
    cpf: str = ""
    nome_responsavel: str = ""


@dataclass
class CertificateDetails:
    """Detalhes estruturados de um certificado X.509 utilizados na interface."""
    common_name: str
    subject_dn: str
    issuer_cn: str
    issuer_dn: str
    serial_hex: str
    not_before: datetime
    not_after: datetime
    is_expired: bool
    is_not_yet_valid: bool
    days_remaining: int
    signature_algorithm: str
    public_key_algorithm: str
    sha256_fingerprint: str
    sha1_fingerprint: str
    is_ca: bool
    is_self_signed: bool
    san_entries: List[str] = field(default_factory=list)
    icp_brasil: ICPBrasilInfo = field(default_factory=ICPBrasilInfo)
    pem_text: str = ""

    @property
    def status_label(self) -> str:
        if self.is_not_yet_valid:
            return "Ainda não válido"
        if self.is_expired:
            return f"Expirado ({abs(self.days_remaining)}d)"
        if self.days_remaining <= 30:
            return f"Expira em {self.days_remaining} dias"
        return f"Válido ({self.days_remaining} dias)"

    @property
    def status_color(self) -> str:
        if self.is_expired or self.is_not_yet_valid:
            return "#ef4444"
        if self.days_remaining <= 30:
            return "#f59e0b"
        return "#10b981"


class KeyStoreEntry:
    """Representa uma entrada (alias) dentro de um KeyStore com carregamento sob demanda (lazy)."""

    __slots__ = (
        "alias",
        "entry_type",
        "certificate",
        "chain",
        "_private_key",
        "raw_private_key_bytes",
        "jks_raw_pkey",
        "jks_algorithm_oid",
    )

    def __init__(
        self,
        alias: str,
        entry_type: EntryType,
        certificate: Optional[x509.Certificate] = None,
        chain: Optional[List[x509.Certificate]] = None,
        private_key: Optional[Any] = None,
        raw_private_key_bytes: Optional[bytes] = None,
        jks_raw_pkey: Optional[bytes] = None,
        jks_algorithm_oid: Optional[tuple] = None,
    ) -> None:
        self.alias = alias
        self.entry_type = entry_type
        self.certificate = certificate
        self.chain = list(chain) if chain else []
        self._private_key = private_key
        self.raw_private_key_bytes = raw_private_key_bytes
        self.jks_raw_pkey = jks_raw_pkey
        self.jks_algorithm_oid = jks_algorithm_oid

    @property
    def private_key(self) -> Optional[Any]:
        """Carrega o objeto de chave privada sob demanda para não travar em arquivos grandes."""
        if self._private_key is None and self.raw_private_key_bytes is not None:
            try:
                self._private_key = serialization.load_der_private_key(
                    self.raw_private_key_bytes, password=None
                )
            except Exception:
                pass
        return self._private_key

    @private_key.setter
    def private_key(self, value: Optional[Any]) -> None:
        self._private_key = value

    @property
    def has_private_key(self) -> bool:
        return self._private_key is not None or self.raw_private_key_bytes is not None

    @property
    def type_display(self) -> str:
        if self.entry_type == EntryType.KEY_PAIR:
            return "Par de Chaves"
        if self.entry_type == EntryType.TRUSTED_CERT:
            return "Certificado CA"
        return "Chave Privada"

    @property
    def chain_count(self) -> int:
        return (1 if self.certificate is not None else 0) + len(self.chain)

    @property
    def full_chain(self) -> List[x509.Certificate]:
        """Retorna [certificado_principal] + certificados_da_cadeia sem duplicatas."""
        result: List[x509.Certificate] = []
        seen_fps = set()
        if self.certificate is not None:
            fp = self.certificate.fingerprint(hashes.SHA256())
            seen_fps.add(fp)
            result.append(self.certificate)
        for cert in self.chain:
            fp = cert.fingerprint(hashes.SHA256())
            if fp not in seen_fps:
                seen_fps.add(fp)
                result.append(cert)
        return result


@dataclass
class KeyStoreDocument:
    """Representa o KeyStore atualmente aberto no aplicativo."""
    ks_format: KeyStoreFormat = KeyStoreFormat.PKCS12
    file_path: Optional[str] = None
    password: Optional[str] = None
    entries: List[KeyStoreEntry] = field(default_factory=list)
    modified: bool = False
    legacy_encryption: bool = False

    def ensure_unique_alias(self, base_alias: str) -> str:
        clean = (base_alias or "certificado").strip()
        existing = {e.alias.lower() for e in self.entries}
        if clean.lower() not in existing:
            return clean
        idx = 2
        while f"{clean}_{idx}".lower() in existing:
            idx += 1
        return f"{clean}_{idx}"

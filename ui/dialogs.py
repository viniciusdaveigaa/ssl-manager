"""Diálogos modernos do SSL Manager: Senha, Nova JKS, Inserir PFX selecionado, Salvar JKS com Senha/Confirmação e Detalhes."""

import os
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.crypto_engine import (
    build_pfx_from_files,
    extract_entry_files,
    get_common_name,
    inspect_certificate,
    load_certificates_from_bytes,
    load_keystore_file,
    load_private_key_from_bytes,
    verify_key_matches_certificate,
)
from core.icons import vector_icon
from core.models import KeyStoreDocument, KeyStoreEntry, KeyStoreFormat


class PasswordPromptDialog(QDialog):
    """Diálogo limpo para informar a senha ao abrir um arquivo .JKS ou .PFX."""

    def __init__(self, file_path: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Desbloquear Arquivo")
        self.setMinimumWidth(450)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        filename = os.path.basename(file_path)
        lbl_title = QLabel("Informe a senha do arquivo (ou deixe em branco caso não possua senha):")
        lbl_title.setStyleSheet("font-size: 13px; color: #475569;")
        layout.addWidget(lbl_title)

        file_box = QFrame()
        file_box.setStyleSheet(
            "QFrame { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px; }"
        )
        fb_layout = QHBoxLayout(file_box)
        fb_layout.setContentsMargins(10, 6, 10, 6)
        lbl_file = QLabel(filename)
        lbl_file.setStyleSheet("font-size: 14px; font-weight: 700; color: #0f172a; border: none;")
        lbl_path = QLabel(file_path)
        lbl_path.setStyleSheet("font-size: 11px; color: #64748b; border: none;")
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(lbl_file)
        col.addWidget(lbl_path)
        fb_layout.addLayout(col)
        layout.addWidget(file_box)

        pwd_row = QHBoxLayout()
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_edit.setPlaceholderText("Digite a senha (ou deixe vazio se for sem senha)...")
        self.pwd_edit.setMinimumHeight(38)
        pwd_row.addWidget(self.pwd_edit, 1)

        self.chk_show = QCheckBox("Mostrar")
        self.chk_show.toggled.connect(self._toggle_echo)
        pwd_row.addWidget(self.chk_show)
        layout.addLayout(pwd_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Abrir Arquivo")
        btn_ok.setMinimumHeight(36)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(36)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.pwd_edit.setFocus()

    def _toggle_echo(self, checked: bool) -> None:
        self.pwd_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )

    def get_password(self) -> str:
        return self.pwd_edit.text()


class NewKeyStoreDialog(QDialog):
    """Diálogo para criar uma nova KeyStore (.JKS) vazia e pronta para receber um .PFX."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nova Java KeyStore (.JKS)")
        self.setMinimumWidth(460)
        self.insert_pfx_immediately: bool = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        lbl_desc = QLabel(
            "Defina a senha inicial da nova Java KeyStore (.JKS) ou deixe em branco. "
            "Você poderá alterá-la novamente no momento de salvar o arquivo."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #475569;")
        layout.addWidget(lbl_desc)

        form = QFormLayout()
        form.setSpacing(12)

        self.pwd_edit = QLineEdit("changeit")
        self.pwd_edit.setMinimumHeight(36)
        self.pwd_edit.setPlaceholderText("Senha inicial da .JKS (ou deixe em branco)")
        form.addRow("Senha Inicial (.JKS):", self.pwd_edit)
        layout.addLayout(form)

        self.chk_insert_now = QCheckBox("Abrir seleção para inserir certificado na .JKS imediatamente após criar")
        self.chk_insert_now.setChecked(True)
        layout.addWidget(self.chk_insert_now)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Criar .JKS")
        btn_ok.setMinimumHeight(36)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(36)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        self.insert_pfx_immediately = self.chk_insert_now.isChecked()
        self.accept()

    def get_password(self) -> str:
        return self.pwd_edit.text()


class InsertSelectedPfxDialog(QDialog):
    """
    Exibido APÓS o usuário selecionar o certificado (.PFX, .P12, .CRT, .CER, .PEM) na janela nativa do Windows.
    Mostra as informações da .JKS selecionada, solicita a senha (se for .PFX) e insere na .JKS.
    """

    def __init__(
        self,
        pfx_path: str,
        target_jks: KeyStoreDocument,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.pfx_path = pfx_path
        self.target_jks = target_jks
        self.loaded_entries: List[KeyStoreEntry] = []
        ext = os.path.splitext(pfx_path)[1].lower()
        self.requires_password = ext in (".pfx", ".p12", ".jks", ".jceks")

        self.setWindowTitle("Inserir certificado na .JKS")
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        # 1. Resumo da JKS de Destino e do Certificado Selecionado
        info_card = QFrame()
        info_card.setStyleSheet(
            "QFrame { background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; }"
        )
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(6)

        jks_name = os.path.basename(target_jks.file_path) if target_jks.file_path else "Nova KeyStore (.jks) em memória"
        total_existing = len(target_jks.entries)
        if total_existing == 0:
            aliases_str = "Nenhuma entrada (vazia)"
        elif total_existing <= 5:
            aliases_str = ", ".join(e.alias for e in target_jks.entries)
        else:
            first_five = ", ".join(e.alias for e in target_jks.entries[:5])
            aliases_str = f"{first_five} ... (total de {total_existing} certificados)"

        lbl_jks = QLabel(f"KeyStore (.JKS) Selecionada:  {jks_name}")
        lbl_jks.setStyleSheet("font-weight: 700; color: #0f172a; font-size: 13px; border: none;")
        lbl_jks_sub = QLabel(f"Certificados atuais na .JKS:  {aliases_str}")
        lbl_jks_sub.setWordWrap(True)
        lbl_jks_sub.setStyleSheet("color: #475569; font-size: 12px; border: none;")

        lbl_pfx = QLabel(f"Certificado Selecionado:  {os.path.basename(pfx_path)}")
        lbl_pfx.setStyleSheet("font-weight: 700; color: #0284c7; font-size: 13px; border: none; margin-top: 4px;")

        info_layout.addWidget(lbl_jks)
        info_layout.addWidget(lbl_jks_sub)
        info_layout.addWidget(lbl_pfx)
        layout.addWidget(info_card)

        # 2. Senha do Certificado (se .PFX) e Alias de Destino
        grp_pwd = QGroupBox("Autenticação e Identificação na .JKS")
        form = QFormLayout(grp_pwd)
        form.setSpacing(12)

        pwd_row = QHBoxLayout()
        self.pfx_pwd_edit = QLineEdit()
        self.pfx_pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pfx_pwd_edit.setPlaceholderText(
            "Digite a senha do certificado .PFX..." if self.requires_password else "Arquivo sem senha (.crt / .cer / .pem)"
        )
        self.pfx_pwd_edit.setMinimumHeight(36)
        self.pfx_pwd_edit.setEnabled(self.requires_password)
        self.pfx_pwd_edit.textChanged.connect(self._try_preview_pfx)
        chk_show = QCheckBox("Mostrar")
        chk_show.setEnabled(self.requires_password)
        chk_show.toggled.connect(
            lambda c: self.pfx_pwd_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password
            )
        )
        pwd_row.addWidget(self.pfx_pwd_edit, 1)
        pwd_row.addWidget(chk_show)
        form.addRow("Senha do Certificado:", pwd_row)

        self.lbl_preview = QLabel("Digite a senha acima para validar e carregar os dados do certificado.")
        self.lbl_preview.setWordWrap(True)
        self.lbl_preview.setStyleSheet(
            "background-color: #fffbeb; color: #92400e; padding: 10px; border-radius: 6px; border: 1px solid #fde68a;"
        )
        form.addRow("Status:", self.lbl_preview)

        self.alias_edit = QLineEdit()
        self.alias_edit.setMinimumHeight(36)
        if total_existing == 1:
            self.alias_edit.setText(target_jks.entries[0].alias)
        self.alias_edit.setPlaceholderText("Nome do Alias que ficará dentro da .JKS")
        form.addRow("Alias na .JKS:", self.alias_edit)

        self.chk_replace = QCheckBox("Substituir entrada existente caso o Alias já exista na .JKS")
        self.chk_replace.setChecked(True)
        form.addRow("", self.chk_replace)

        layout.addWidget(grp_pwd)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Inserir certificado na .JKS")
        btn_ok.setMinimumHeight(38)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(38)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self._on_confirm)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._try_preview_pfx()
        if self.requires_password:
            self.pfx_pwd_edit.setFocus()
        else:
            self.alias_edit.setFocus()

    def _try_preview_pfx(self) -> None:
        pwd = self.pfx_pwd_edit.text()
        self.loaded_entries = []
        try:
            doc = load_keystore_file(self.pfx_path, pwd)
            self.loaded_entries = doc.entries
            if doc.entries and doc.entries[0].certificate:
                e = doc.entries[0]
                info = inspect_certificate(e.certificate)
                self.lbl_preview.setText(
                    f"Certificado validado com sucesso!\n"
                    f"Titular: {info.common_name}  |  Validade: {info.not_after.strftime('%d/%m/%Y')} ({info.status_label})\n"
                    f"Cadeia incluída: {len(e.full_chain)} certificado(s)"
                )
                self.lbl_preview.setStyleSheet(
                    "background-color: #ecfdf5; color: #065f46; font-weight: 600; padding: 10px; border-radius: 6px; border: 1px solid #6ee7b7;"
                )
                if not self.alias_edit.text().strip():
                    self.alias_edit.setText(e.alias)
        except Exception:
            if pwd:
                self.lbl_preview.setText("Senha incorreta para este arquivo .PFX. Verifique e tente novamente.")
                self.lbl_preview.setStyleSheet(
                    "background-color: #fef2f2; color: #991b1b; padding: 10px; border-radius: 6px; border: 1px solid #fecaca;"
                )
            else:
                self.lbl_preview.setText("Aguardando digitação da senha do arquivo .PFX...")
                self.lbl_preview.setStyleSheet(
                    "background-color: #fffbeb; color: #92400e; padding: 10px; border-radius: 6px; border: 1px solid #fde68a;"
                )

    def _on_confirm(self) -> None:
        pwd = self.pfx_pwd_edit.text()
        try:
            doc = load_keystore_file(self.pfx_path, pwd)
            if not doc.entries:
                QMessageBox.warning(self, "PFX Vazio", "Nenhum certificado ou chave encontrado no arquivo .PFX.")
                return
            self.loaded_entries = doc.entries
            custom_alias = self.alias_edit.text().strip()
            if custom_alias:
                self.loaded_entries[0].alias = custom_alias
            self.accept()
        except Exception as err:
            QMessageBox.critical(
                self,
                "Senha do .PFX Incorreta",
                f"Não foi possível desbloquear o arquivo .PFX.\nVerifique a senha informada.\n\nDetalhe: {err}",
            )


class SaveJksPasswordDialog(QDialog):
    """
    Exibido ao salvar a .JKS alterada: solicita a definição/alteração da senha da .JKS
    com campos de Senha e Confirmação de Senha.
    """

    def __init__(
        self,
        current_password: Optional[str] = None,
        target_path: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Definir / Alterar Senha para Salvar .JKS")
        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        lbl_info = QLabel(
            "Para salvar a KeyStore (.JKS) alterada, informe ou altere a senha de proteção do arquivo "
            "e confirme abaixo (ou deixe em branco para salvar sem senha):"
        )
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet("color: #334155;")
        layout.addWidget(lbl_info)

        if target_path:
            lbl_dest = QLabel(f"Destino: {target_path}")
            lbl_dest.setWordWrap(True)
            lbl_dest.setStyleSheet(
                "background-color: #f8fafc; color: #0f172a; font-weight: 600; padding: 8px 10px; "
                "border-radius: 6px; border: 1px solid #cbd5e1; font-size: 12px;"
            )
            layout.addWidget(lbl_dest)

        form = QFormLayout()
        form.setSpacing(12)

        self.new_pwd = QLineEdit(current_password or "")
        self.new_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pwd.setMinimumHeight(36)
        self.new_pwd.setPlaceholderText("Digite a senha da .JKS (ou deixe vazio para sem senha)")

        self.confirm_pwd = QLineEdit(current_password or "")
        self.confirm_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pwd.setMinimumHeight(36)
        self.confirm_pwd.setPlaceholderText("Confirme a senha da .JKS (ou deixe vazio)")

        self.chk_show = QCheckBox("Mostrar senhas")
        self.chk_show.toggled.connect(self._toggle_show)

        form.addRow("Senha da .JKS:", self.new_pwd)
        form.addRow("Confirmar Senha:", self.confirm_pwd)
        form.addRow("", self.chk_show)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Confirmar e Salvar .JKS")
        btn_ok.setMinimumHeight(38)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(38)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.new_pwd.setFocus()
        self.new_pwd.selectAll()

    def _toggle_show(self, checked: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.new_pwd.setEchoMode(mode)
        self.confirm_pwd.setEchoMode(mode)

    def _validate_and_accept(self) -> None:
        pwd = self.new_pwd.text()
        conf = self.confirm_pwd.text()
        if pwd != conf:
            QMessageBox.warning(
                self,
                "Senhas Não Conferem",
                "A senha e a confirmação de senha digitadas são diferentes. Verifique e tente novamente.",
            )
            return
        self.accept()

    def get_password(self) -> str:
        return self.new_pwd.text()


class PfxBuilderDialog(QDialog):
    """
    Construtor de .PFX quando o cliente envia os arquivos separados:
    - Certificado Principal (.crt, .cer, .pem)
    - Private Key (.key, .pem)
    - Cadeia / Intermediárias (.crt, .ca-bundle, .pem, .p7b)
    """

    def __init__(self, has_open_jks: bool = False, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Montar .PFX a partir de Certificado (.crt) + Private Key (.key)")
        self.setMinimumSize(660, 600)
        self.created_document: Optional[KeyStoreDocument] = None
        self.insert_into_current_jks: bool = False

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(22, 20, 22, 20)
        main_layout.setSpacing(12)

        lbl_intro = QLabel(
            "Quando o cliente não envia o .PFX pronto, selecione abaixo o Certificado (.crt/.cer), "
            "a Private Key (.key) e a Cadeia para gerar o arquivo .PFX:"
        )
        lbl_intro.setWordWrap(True)
        lbl_intro.setStyleSheet("color: #475569;")
        main_layout.addWidget(lbl_intro)

        # 1. Certificado Principal
        grp_cert = QGroupBox("1. Certificado Principal (.crt, .cer, .pem)")
        cert_layout = QVBoxLayout(grp_cert)
        cert_row = QHBoxLayout()
        self.cert_path_edit = QLineEdit()
        self.cert_path_edit.setPlaceholderText("Caminho do certificado (.crt, .cer, .pem)...")
        self.cert_path_edit.textChanged.connect(self._on_inputs_changed)
        btn_cert = QPushButton("Selecionar Certificado...")
        btn_cert.setIcon(vector_icon("folder", "#ffffff", 16))
        btn_cert.clicked.connect(self._browse_cert)
        cert_row.addWidget(self.cert_path_edit, 1)
        cert_row.addWidget(btn_cert)
        cert_layout.addLayout(cert_row)

        self.lbl_cert_status = QLabel("Aguardando seleção do certificado.")
        self.lbl_cert_status.setStyleSheet("color: #64748b; font-size: 12px;")
        cert_layout.addWidget(self.lbl_cert_status)
        main_layout.addWidget(grp_cert)

        # 2. Private Key
        grp_key = QGroupBox("2. Private Key / Chave Privada (.key, .pem)")
        key_layout = QVBoxLayout(grp_key)
        key_row = QHBoxLayout()
        self.key_path_edit = QLineEdit()
        self.key_path_edit.setPlaceholderText("Caminho da Private Key (.key / .pem)...")
        self.key_path_edit.textChanged.connect(self._on_inputs_changed)
        btn_key = QPushButton("Selecionar Private Key...")
        btn_key.setIcon(vector_icon("key", "#ffffff", 16))
        btn_key.clicked.connect(self._browse_key)
        key_row.addWidget(self.key_path_edit, 1)
        key_row.addWidget(btn_key)
        key_layout.addLayout(key_row)

        key_pwd_row = QHBoxLayout()
        key_pwd_row.addWidget(QLabel("Senha da Private Key (se houver):"))
        self.key_pwd_edit = QLineEdit()
        self.key_pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_pwd_edit.setPlaceholderText("Deixe vazio se a chave .key não possuir senha")
        self.key_pwd_edit.textChanged.connect(self._on_inputs_changed)
        key_pwd_row.addWidget(self.key_pwd_edit, 1)
        key_layout.addLayout(key_pwd_row)

        self.lbl_match_status = QLabel("Selecione o certificado e a Private Key para validar o par.")
        self.lbl_match_status.setStyleSheet("color: #64748b; font-weight: 600;")
        key_layout.addWidget(self.lbl_match_status)
        main_layout.addWidget(grp_key)

        # 3. Cadeia CA
        grp_chain = QGroupBox("3. Cadeia Certificadora / Intermediários (Opcional)")
        chain_layout = QVBoxLayout(grp_chain)
        self.chain_list = QListWidget()
        self.chain_list.setMaximumHeight(80)
        chain_layout.addWidget(self.chain_list)

        chain_btn_row = QHBoxLayout()
        btn_add_chain = QPushButton("Adicionar Arquivos de Cadeia (.crt / .ca-bundle)")
        btn_add_chain.setProperty("secondary", True)
        btn_add_chain.clicked.connect(self._add_chain_files)
        btn_rem_chain = QPushButton("Remover")
        btn_rem_chain.setProperty("secondary", True)
        btn_rem_chain.clicked.connect(self._remove_chain_file)
        chain_btn_row.addWidget(btn_add_chain)
        chain_btn_row.addWidget(btn_rem_chain)
        chain_btn_row.addStretch()
        chain_layout.addLayout(chain_btn_row)
        main_layout.addWidget(grp_chain)

        # 4. Saída do PFX
        grp_out = QGroupBox("4. Configuração do Arquivo .PFX")
        out_form = QFormLayout(grp_out)
        out_form.setSpacing(10)

        self.alias_edit = QLineEdit()
        self.alias_edit.setPlaceholderText("Nome do Alias (preenchido automaticamente)")
        out_form.addRow("Alias:", self.alias_edit)

        pwd_out_row = QHBoxLayout()
        self.pfx_pwd_edit = QLineEdit()
        self.pfx_pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pfx_pwd_edit.setPlaceholderText("Senha do novo .PFX")
        self.pfx_pwd_confirm = QLineEdit()
        self.pfx_pwd_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.pfx_pwd_confirm.setPlaceholderText("Confirmar senha")
        chk_show_pfx = QCheckBox("Mostrar")
        chk_show_pfx.toggled.connect(self._toggle_pfx_pwd)
        pwd_out_row.addWidget(self.pfx_pwd_edit, 1)
        pwd_out_row.addWidget(self.pfx_pwd_confirm, 1)
        pwd_out_row.addWidget(chk_show_pfx)
        out_form.addRow("Senha do .PFX:", pwd_out_row)

        out_path_row = QHBoxLayout()
        self.out_path_edit = QLineEdit()
        self.out_path_edit.setPlaceholderText("Onde salvar o arquivo .pfx...")
        btn_out = QPushButton("Salvar Como...")
        btn_out.setProperty("secondary", True)
        btn_out.clicked.connect(self._browse_output)
        out_path_row.addWidget(self.out_path_edit, 1)
        out_path_row.addWidget(btn_out)
        out_form.addRow("Arquivo .PFX:", out_path_row)

        self.chk_insert_jks = QCheckBox(
            "Inserir automaticamente este .PFX na KeyStore (.JKS) ativa após gerar"
        )
        self.chk_insert_jks.setChecked(has_open_jks)
        self.chk_insert_jks.setEnabled(has_open_jks)
        out_form.addRow("", self.chk_insert_jks)

        main_layout.addWidget(grp_out)

        footer_row = QHBoxLayout()
        btn_clear_all = QPushButton("  Limpar Selecionado")
        btn_clear_all.setIcon(vector_icon("clear", "#dc2626", 16))
        btn_clear_all.setProperty("danger", True)
        btn_clear_all.setMinimumHeight(38)
        btn_clear_all.clicked.connect(self._clear_all_fields)
        footer_row.addWidget(btn_clear_all)
        footer_row.addStretch()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Montar e Salvar .PFX")
        btn_ok.setMinimumHeight(38)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(38)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self._on_build_clicked)
        buttons.rejected.connect(self.reject)
        footer_row.addWidget(buttons)
        main_layout.addLayout(footer_row)

    def _clear_all_fields(self) -> None:
        self.cert_path_edit.clear()
        self.key_path_edit.clear()
        self.key_pwd_edit.clear()
        self.chain_list.clear()
        self.alias_edit.clear()
        self.pfx_pwd_edit.clear()
        self.pfx_pwd_confirm.clear()
        self.out_path_edit.clear()
        self.lbl_cert_status.setText("Aguardando seleção do certificado.")
        self.lbl_cert_status.setStyleSheet("color: #64748b; font-size: 12px;")
        self.lbl_match_status.setText("Selecione o certificado e a Private Key para validar o par.")
        self.lbl_match_status.setStyleSheet("color: #64748b; font-weight: 600;")

    def _toggle_pfx_pwd(self, checked: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.pfx_pwd_edit.setEchoMode(mode)
        self.pfx_pwd_confirm.setEchoMode(mode)

    def _browse_cert(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar Certificado Principal",
            "",
            "Certificados (*.crt *.cer *.pem *.der *.p7b);;Todos os Arquivos (*.*)",
        )
        if path:
            self.cert_path_edit.setText(path)
            if not self.out_path_edit.text():
                base = os.path.splitext(path)[0]
                self.out_path_edit.setText(f"{base}.pfx")

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar Private Key",
            "",
            "Chaves Privadas (*.key *.pem *.pkcs8);;Todos os Arquivos (*.*)",
        )
        if path:
            self.key_path_edit.setText(path)

    def _add_chain_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Selecionar Certificados da Cadeia",
            "",
            "Certificados e Bundles (*.crt *.cer *.pem *.ca-bundle *.p7b *.der);;Todos os Arquivos (*.*)",
        )
        existing = {self.chain_list.item(i).text() for i in range(self.chain_list.count())}
        for p in paths:
            if p not in existing:
                self.chain_list.addItem(p)

    def _remove_chain_file(self) -> None:
        row = self.chain_list.currentRow()
        if row >= 0:
            self.chain_list.takeItem(row)

    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Novo Arquivo PFX",
            self.out_path_edit.text() or "certificado.pfx",
            "PKCS#12 KeyStore (*.pfx *.p12)",
        )
        if path:
            self.out_path_edit.setText(path)

    def _on_inputs_changed(self) -> None:
        cert_path = self.cert_path_edit.text().strip()
        key_path = self.key_path_edit.text().strip()
        key_pwd = self.key_pwd_edit.text() or None

        loaded_cert = None
        if cert_path and os.path.isfile(cert_path):
            try:
                with open(cert_path, "rb") as f:
                    certs = load_certificates_from_bytes(f.read())
                if certs:
                    loaded_cert = certs[0]
                    info = inspect_certificate(loaded_cert)
                    self.lbl_cert_status.setText(
                        f"Certificado válido: {info.common_name}  |  Emissor: {info.issuer_cn}  |  {info.status_label}"
                    )
                    self.lbl_cert_status.setStyleSheet("color: #059669; font-size: 12px; font-weight: 600;")
                    if not self.alias_edit.text().strip():
                        self.alias_edit.setText(info.common_name)
            except Exception as e:
                self.lbl_cert_status.setText(f"Erro ao ler certificado: {e}")
                self.lbl_cert_status.setStyleSheet("color: #dc2626; font-size: 12px;")

        if loaded_cert and key_path and os.path.isfile(key_path):
            try:
                with open(key_path, "rb") as f:
                    priv_key = load_private_key_from_bytes(f.read(), key_pwd)
                if verify_key_matches_certificate(priv_key, loaded_cert):
                    self.lbl_match_status.setText(
                        "Par validado: A Private Key corresponde exatamente ao Certificado selecionado."
                    )
                    self.lbl_match_status.setStyleSheet("color: #059669; font-weight: 700;")
                else:
                    self.lbl_match_status.setText(
                        "Atenção: Esta Private Key NÃO pertence a este Certificado!"
                    )
                    self.lbl_match_status.setStyleSheet("color: #dc2626; font-weight: 700;")
            except Exception as e:
                self.lbl_match_status.setText(f"Não foi possível ler a Private Key (verifique a senha): {e}")
                self.lbl_match_status.setStyleSheet("color: #d97706; font-weight: 600;")

    def _on_build_clicked(self) -> None:
        cert_path = self.cert_path_edit.text().strip()
        key_path = self.key_path_edit.text().strip()
        out_path = self.out_path_edit.text().strip()

        if not cert_path or not os.path.isfile(cert_path):
            QMessageBox.warning(self, "Certificado Obrigatório", "Selecione um arquivo de Certificado (.crt/.cer/.pem).")
            return
        if not key_path or not os.path.isfile(key_path):
            QMessageBox.warning(self, "Private Key Obrigatória", "Selecione o arquivo da Private Key (.key/.pem).")
            return
        if not out_path:
            QMessageBox.warning(self, "Destino Obrigatório", "Informe onde deseja salvar o novo arquivo .pfx.")
            return
        if self.pfx_pwd_edit.text() != self.pfx_pwd_confirm.text():
            QMessageBox.warning(self, "Senhas Diferentes", "A confirmação de senha do .PFX não confere.")
            return

        chain_paths = [self.chain_list.item(i).text() for i in range(self.chain_list.count())]

        try:
            self.created_document = build_pfx_from_files(
                cert_path=cert_path,
                key_path=key_path,
                key_password=self.key_pwd_edit.text() or None,
                chain_paths=chain_paths,
                output_pfx_path=out_path,
                pfx_password=self.pfx_pwd_edit.text(),
                alias=self.alias_edit.text().strip() or None,
                legacy_encryption=False,
            )
            self.insert_into_current_jks = self.chk_insert_jks.isChecked()
            self.accept()
        except Exception as err:
            QMessageBox.critical(self, "Erro ao Montar PFX", str(err))


class CertificateDetailsDialog(QDialog):
    """Janela de Detalhes do Certificado exibida sob demanda."""

    def __init__(self, entry: KeyStoreEntry, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.entry = entry
        self.setWindowTitle(f"Detalhes do Certificado — {entry.alias}")
        self.setMinimumSize(780, 540)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        if entry.certificate is None:
            layout.addWidget(QLabel("Esta entrada contém apenas uma Chave Privada isolada (sem certificado X.509)."))
            return

        info = inspect_certificate(entry.certificate)

        banner = QFrame()
        banner.setStyleSheet(
            "QFrame { background-color: #0f172a; border-radius: 10px; padding: 12px; }"
        )
        b_layout = QHBoxLayout(banner)
        lbl_cn = QLabel(f"Titular: {info.common_name}\nAlias na KeyStore: {entry.alias}")
        lbl_cn.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc; border: none;")
        b_layout.addWidget(lbl_cn, 1)

        lbl_status = QLabel(info.status_label)
        lbl_status.setStyleSheet(
            f"font-size: 12px; font-weight: 700; color: #ffffff; background-color: {info.status_color}; "
            "padding: 6px 14px; border-radius: 6px; border: none;"
        )
        b_layout.addWidget(lbl_status)
        layout.addWidget(banner)

        tabs = QTabWidget()

        # Aba 1: Informações Gerais
        tab_general = QWidget()
        gen_layout = QVBoxLayout(tab_general)
        gen_layout.setContentsMargins(16, 16, 16, 16)
        form = QFormLayout()
        form.setSpacing(10)

        form.addRow("Tipo na KeyStore:", self._ro_line(entry.type_display))
        form.addRow("Titular (Common Name):", self._ro_line(info.common_name))
        form.addRow("Subject DN Completo:", self._ro_line(info.subject_dn))
        form.addRow("Emissor (Autoridade CA):", self._ro_line(info.issuer_cn))
        form.addRow("Issuer DN Completo:", self._ro_line(info.issuer_dn))
        form.addRow(
            "Período de Validade:",
            self._ro_line(
                f"De {info.not_before.strftime('%d/%m/%Y %H:%M')} até {info.not_after.strftime('%d/%m/%Y %H:%M')}"
            ),
        )
        form.addRow("Chave Pública:", self._ro_line(info.public_key_algorithm))
        form.addRow("Algoritmo de Assinatura:", self._ro_line(info.signature_algorithm))
        form.addRow("Número de Série (Hex):", self._ro_line(info.serial_hex, mono=True))

        sha256_row = QHBoxLayout()
        le_sha256 = self._ro_line(info.sha256_fingerprint, mono=True)
        btn_cp256 = QPushButton("Copiar SHA-256")
        btn_cp256.setProperty("secondary", True)
        btn_cp256.clicked.connect(lambda: QApplication.clipboard().setText(info.sha256_fingerprint))
        sha256_row.addWidget(le_sha256, 1)
        sha256_row.addWidget(btn_cp256)
        form.addRow("Impressão Digital SHA-256:", sha256_row)

        sha1_row = QHBoxLayout()
        le_sha1 = self._ro_line(info.sha1_fingerprint, mono=True)
        btn_cp1 = QPushButton("Copiar SHA-1")
        btn_cp1.setProperty("secondary", True)
        btn_cp1.clicked.connect(lambda: QApplication.clipboard().setText(info.sha1_fingerprint))
        sha1_row.addWidget(le_sha1, 1)
        sha1_row.addWidget(btn_cp1)
        form.addRow("Impressão Digital SHA-1:", sha1_row)

        if info.icp_brasil.is_icp_brasil:
            icp = info.icp_brasil
            icp_text = (
                f"Tipo: {icp.tipo_certificado or '-'} | "
                f"CNPJ: {icp.cnpj or '-'} | "
                f"Responsável: {icp.nome_responsavel or '-'} | "
                f"CPF: {icp.cpf or '-'}"
            )
            form.addRow("Dados ICP-Brasil:", self._ro_line(icp_text))

        gen_layout.addLayout(form)
        gen_layout.addStretch()
        tabs.addTab(tab_general, "Informações do Certificado")

        # Aba 2: Cadeia de Certificação
        tab_chain = QWidget()
        chain_layout = QVBoxLayout(tab_chain)
        chain_layout.setContentsMargins(16, 16, 16, 16)
        chain_layout.addWidget(
            QLabel("Hierarquia da Cadeia de Certificação (Autoridade Raiz -> Intermediárias -> Certificado Final):")
        )
        self.tree_chain = QTreeWidget()
        self.tree_chain.setHeaderLabels(["Certificado na Cadeia", "Emissor", "Validade", "Papel"])
        self.tree_chain.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree_chain.itemSelectionChanged.connect(self._on_chain_selected)
        chain_layout.addWidget(self.tree_chain, 1)

        self.txt_chain_detail = QTextEdit()
        self.txt_chain_detail.setReadOnly(True)
        self.txt_chain_detail.setFont(QFont("Consolas", 9))
        self.txt_chain_detail.setMaximumHeight(140)
        chain_layout.addWidget(self.txt_chain_detail)

        btn_exp_cert = QPushButton("Exportar Certificado Selecionado da Cadeia (.crt)")
        btn_exp_cert.setProperty("secondary", True)
        btn_exp_cert.clicked.connect(self._export_chain_cert)
        chain_layout.addWidget(btn_exp_cert)

        self._populate_chain(entry)
        tabs.addTab(tab_chain, f"Cadeia de Certificação ({len(entry.full_chain)})")

        # Aba 3: Domínios (SAN) & PEM
        tab_pem = QWidget()
        pem_layout = QVBoxLayout(tab_pem)
        pem_layout.setContentsMargins(16, 16, 16, 16)
        pem_layout.addWidget(QLabel("Domínios / Nomes Alternativos Cobertos pelo Certificado (SAN):"))
        txt_san = QTextEdit()
        txt_san.setReadOnly(True)
        txt_san.setMaximumHeight(90)
        txt_san.setPlainText("\n".join(info.san_entries) if info.san_entries else "Nenhum domínio alternativo (SAN).")
        pem_layout.addWidget(txt_san)

        pem_layout.addWidget(QLabel("Conteúdo Base64 (PEM) do Certificado:"))
        txt_pem = QTextEdit()
        txt_pem.setReadOnly(True)
        txt_pem.setFont(QFont("Consolas", 9))
        txt_pem.setPlainText(info.pem_text)
        pem_layout.addWidget(txt_pem, 1)

        btn_cp_pem = QPushButton("Copiar Certificado PEM")
        btn_cp_pem.setProperty("secondary", True)
        btn_cp_pem.clicked.connect(lambda: QApplication.clipboard().setText(info.pem_text))
        pem_layout.addWidget(btn_cp_pem)

        tabs.addTab(tab_pem, "Domínios (SAN) && PEM")

        layout.addWidget(tabs, 1)

        btn_close = QPushButton("Fechar Detalhes")
        btn_close.setMinimumHeight(36)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

    def _ro_line(self, text: str, mono: bool = False) -> QLineEdit:
        le = QLineEdit(text)
        le.setReadOnly(True)
        if mono:
            le.setFont(QFont("Consolas", 9))
        return le

    def _populate_chain(self, entry: KeyStoreEntry) -> None:
        reversed_chain = list(reversed(entry.full_chain))
        parent_node = None
        for idx, cert_obj in enumerate(reversed_chain):
            c_info = inspect_certificate(cert_obj)
            is_leaf = idx == len(reversed_chain) - 1
            if c_info.is_self_signed and c_info.is_ca:
                role = "Autoridade Raiz (Root CA)"
            elif c_info.is_ca:
                role = "Autoridade Intermediária"
            elif is_leaf:
                role = "Certificado Principal"
            else:
                role = "Certificado da Cadeia"

            node = QTreeWidgetItem(
                [c_info.common_name, c_info.issuer_cn, c_info.not_after.strftime("%d/%m/%Y"), role]
            )
            node.setData(0, Qt.ItemDataRole.UserRole, cert_obj)
            if parent_node is None:
                self.tree_chain.addTopLevelItem(node)
            else:
                parent_node.addChild(node)
            parent_node = node

        self.tree_chain.expandAll()
        if parent_node:
            self.tree_chain.setCurrentItem(parent_node)

    def _on_chain_selected(self) -> None:
        items = self.tree_chain.selectedItems()
        if not items:
            return
        cert_obj: Optional[x509.Certificate] = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not cert_obj:
            return
        ci = inspect_certificate(cert_obj)
        self.txt_chain_detail.setPlainText(
            f"Titular:  {ci.subject_dn}\n"
            f"Emissor:  {ci.issuer_dn}\n"
            f"Validade: {ci.not_before.strftime('%d/%m/%Y')} até {ci.not_after.strftime('%d/%m/%Y')} ({ci.status_label})\n"
            f"SHA-256:  {ci.sha256_fingerprint}"
        )

    def _export_chain_cert(self) -> None:
        items = self.tree_chain.selectedItems()
        if not items:
            return
        cert_obj: Optional[x509.Certificate] = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not cert_obj:
            return
        cn = get_common_name(cert_obj.subject).replace(" ", "_").replace(":", "_")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar Certificado",
            f"{cn}.crt",
            "Certificado PEM (*.crt *.pem);;Certificado DER (*.cer)",
        )
        if path:
            ext = os.path.splitext(path)[1].lower()
            enc = serialization.Encoding.DER if ext == ".cer" else serialization.Encoding.PEM
            with open(path, "wb") as f:
                f.write(cert_obj.public_bytes(enc))
            QMessageBox.information(self, "Exportado", f"Certificado salvo em:\n{path}")


class ExtractKitDialog(QDialog):
    """Diálogo para extrair Certificado (.crt), Private Key (.key) e Cadeia de uma entrada."""

    def __init__(
        self,
        entry: KeyStoreEntry,
        default_dir: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.entry = entry
        self.created_files: List[str] = []
        self.setWindowTitle(f"Extrair Arquivos — {entry.alias}")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        grp_opts = QGroupBox(f"Arquivos para extrair de '{entry.alias}'")
        opts_layout = QVBoxLayout(grp_opts)

        self.chk_cert_pem = QCheckBox("Certificado Principal (.crt)")
        self.chk_cert_pem.setChecked(entry.certificate is not None)
        self.chk_cert_pem.setEnabled(entry.certificate is not None)
        opts_layout.addWidget(self.chk_cert_pem)

        self.chk_key_pem = QCheckBox("Private Key desencriptada sem senha (.key)")
        self.chk_key_pem.setChecked(entry.private_key is not None)
        self.chk_key_pem.setEnabled(entry.private_key is not None)
        opts_layout.addWidget(self.chk_key_pem)

        has_chain = len(entry.chain) > 0
        self.chk_chain = QCheckBox(f"Cadeia de Certificados Intermediários / Raiz (-ca-bundle.crt) [{len(entry.chain)}]")
        self.chk_chain.setChecked(has_chain)
        self.chk_chain.setEnabled(has_chain)
        opts_layout.addWidget(self.chk_chain)

        self.chk_fullchain = QCheckBox("Cadeia Completa Concatenada (-fullchain.pem)")
        self.chk_fullchain.setChecked(has_chain and entry.certificate is not None)
        self.chk_fullchain.setEnabled(entry.certificate is not None)
        opts_layout.addWidget(self.chk_fullchain)

        layout.addWidget(grp_opts)

        grp_dest = QGroupBox("Pasta de Destino")
        dest_form = QFormLayout(grp_dest)

        dir_row = QHBoxLayout()
        self.dir_edit = QLineEdit(default_dir or os.path.expanduser("~\\Desktop"))
        btn_dir = QPushButton("Escolher Pasta...")
        btn_dir.setProperty("secondary", True)
        btn_dir.clicked.connect(self._browse_dir)
        dir_row.addWidget(self.dir_edit, 1)
        dir_row.addWidget(btn_dir)
        dest_form.addRow("Salvar na Pasta:", dir_row)

        clean_alias = entry.alias.split(":")[0].strip().replace(" ", "_") or "certificado"
        self.base_name_edit = QLineEdit(clean_alias)
        dest_form.addRow("Nome Base:", self.base_name_edit)
        layout.addWidget(grp_dest)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        btn_ok.setText("Extrair Arquivos")
        btn_ok.setMinimumHeight(36)
        btn_cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        btn_cancel.setText("Cancelar")
        btn_cancel.setMinimumHeight(36)
        btn_cancel.setProperty("secondary", True)
        buttons.accepted.connect(self._on_extract)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Selecionar Pasta", self.dir_edit.text())
        if folder:
            self.dir_edit.setText(folder)

    def _on_extract(self) -> None:
        out_dir = self.dir_edit.text().strip()
        base_name = self.base_name_edit.text().strip() or "certificado"
        if not out_dir:
            QMessageBox.warning(self, "Pasta Obrigatória", "Selecione uma pasta de destino.")
            return

        try:
            self.created_files = extract_entry_files(
                entry=self.entry,
                output_dir=out_dir,
                base_filename=base_name,
                export_cert_pem=self.chk_cert_pem.isChecked(),
                export_cert_der=False,
                export_key_pem=self.chk_key_pem.isChecked(),
                key_password=None,
                export_chain_bundle=self.chk_chain.isChecked(),
                export_fullchain=self.chk_fullchain.isChecked(),
            )
            if not self.created_files:
                QMessageBox.warning(self, "Nenhuma Opção", "Marque pelo menos um item para extrair.")
                return
            self.accept()
        except Exception as err:
            QMessageBox.critical(self, "Erro na Extração", str(err))

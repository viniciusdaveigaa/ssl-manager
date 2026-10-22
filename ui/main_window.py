"""Janela principal do SSL Manager — Design Desktop Moderno (Sidebar Escura + Cards com Sombra + Ícones Vetoriais)."""

import os
from typing import Optional

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QAction, QColor, QDragEnterEvent, QDropEvent, QFont, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.branding import APP_FULL_TITLE, get_app_icon, render_app_logo_image
from core.crypto_engine import (
    inspect_certificate,
    load_certificates_from_bytes,
    load_keystore_file,
    order_certificate_chain,
    save_jks_file,
    save_pkcs12_file,
)
from core.icons import vector_icon
from core.models import KeyStoreDocument, KeyStoreEntry, KeyStoreFormat
from ui.dialogs import (
    CertificateDetailsDialog,
    ExtractKitDialog,
    InsertSelectedPfxDialog,
    NewKeyStoreDialog,
    PasswordPromptDialog,
    PfxBuilderDialog,
    SaveJksPasswordDialog,
)


APP_STYLESHEET = """
QMainWindow, QDialog {
    background-color: #f1f5f9;
    color: #0f172a;
}
QWidget {
    color: #0f172a;
    font-family: "Segoe UI";
    font-size: 13px;
}
QMenuBar {
    background-color: #0b1120;
    color: #e2e8f0;
    border-bottom: 1px solid #1e293b;
    padding: 3px 8px;
    font-weight: 600;
}
QMenuBar::item {
    background-color: transparent;
    color: #e2e8f0;
    padding: 5px 12px;
    border-radius: 4px;
}
QMenuBar::item:selected {
    background-color: #1e293b;
    color: #ffffff;
}
QMenu {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 7px 24px;
    color: #0f172a;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #eff6ff;
    color: #0284c7;
}
QGroupBox {
    font-weight: 700;
    color: #0f172a;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 14px;
    background-color: #ffffff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #0f172a;
}
QLabel {
    color: #0f172a;
}
QCheckBox {
    color: #1e293b;
    spacing: 8px;
}
QTableWidget, QTreeWidget, QListWidget {
    background-color: #ffffff;
    alternate-background-color: #f8fafc;
    color: #0f172a;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    gridline-color: #f1f5f9;
    selection-background-color: #e0f2fe;
    selection-color: #0c4a6e;
    font-size: 13px;
    outline: none;
}
QTableWidget::item {
    color: #0f172a;
    padding: 8px 12px;
    border-bottom: 1px solid #f1f5f9;
}
QTableWidget::item:selected {
    background-color: #e0f2fe;
    color: #0c4a6e;
}
QHeaderView::section {
    background-color: #f8fafc;
    color: #475569;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    padding: 10px 12px;
    border: none;
    border-bottom: 1px solid #e2e8f0;
    border-right: 1px solid #f1f5f9;
}
QHeaderView::section:hover {
    background-color: #e2e8f0;
    color: #0f172a;
}
QLineEdit, QComboBox, QTextEdit {
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 6px 10px;
    background-color: #ffffff;
    color: #0f172a;
    selection-background-color: #0284c7;
    selection-color: #ffffff;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
    border: 1.5px solid #0284c7;
    background-color: #ffffff;
}
QPushButton {
    background-color: #0284c7;
    color: #ffffff;
    border: 1px solid #0284c7;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #0369a1;
    border-color: #0369a1;
}
QPushButton:disabled {
    background-color: #e2e8f0;
    color: #94a3b8;
    border-color: #e2e8f0;
}
QPushButton[secondary="true"] {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #cbd5e1;
}
QPushButton[secondary="true"]:hover {
    background-color: #f8fafc;
    border-color: #94a3b8;
    color: #0f172a;
}
QPushButton[secondary="true"]:disabled {
    background-color: #f8fafc;
    color: #cbd5e1;
    border-color: #e2e8f0;
}
QPushButton[danger="true"] {
    background-color: #ffffff;
    color: #dc2626;
    border: 1px solid #fecaca;
}
QPushButton[danger="true"]:hover {
    background-color: #fef2f2;
    border-color: #ef4444;
    color: #b91c1c;
}
QPushButton[danger="true"]:disabled {
    background-color: #f8fafc;
    color: #cbd5e1;
    border-color: #e2e8f0;
}
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background-color: #ffffff;
}
QTabBar::tab {
    background-color: #f1f5f9;
    color: #475569;
    padding: 9px 18px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background-color: #ffffff;
    color: #0284c7;
    border: 1px solid #e2e8f0;
    border-bottom: none;
}
QStatusBar {
    background-color: #ffffff;
    color: #475569;
    border-top: 1px solid #e2e8f0;
    font-size: 12px;
}
"""

SIDEBAR_BTN_STYLE = """
QPushButton {
    background-color: #162032;
    color: #f1f5f9;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #1e293b;
    border-color: #334155;
    color: #ffffff;
}
QPushButton:disabled {
    background-color: #0f172a;
    color: #475569;
    border-color: #162032;
}
"""

SIDEBAR_ACCENT_BTN_STYLE = """
QPushButton {
    background-color: #0284c7;
    color: #ffffff;
    border: 1px solid #38bdf8;
    border-radius: 8px;
    padding: 11px 14px;
    text-align: left;
    font-weight: 700;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #0369a1;
    border-color: #7dd3fc;
}
QPushButton:disabled {
    background-color: #111827;
    color: #475569;
    border: 1px solid #1e293b;
}
"""

SIDEBAR_SAVE_BTN_STYLE = """
QPushButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #10b981;
    border-radius: 8px;
    padding: 10px 14px;
    text-align: left;
    font-weight: 700;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #047857;
}
QPushButton:disabled {
    background-color: #111827;
    color: #475569;
    border: 1px solid #1e293b;
}
"""


class SortableTableWidgetItem(QTableWidgetItem):
    """Item de tabela com suporte a ordenação inteligente (por data, número ou texto sem diferenciar maiúsculas)."""

    def __init__(self, text: str, sort_key=None) -> None:
        super().__init__(text)
        self._sort_key = sort_key if sort_key is not None else text.lower()

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, SortableTableWidgetItem):
            try:
                return self._sort_key < other._sort_key
            except TypeError:
                return str(self._sort_key) < str(other._sort_key)
        return super().__lt__(other)


class MainWindow(QMainWindow):
    """Janela Principal do SSL Manager."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_FULL_TITLE)
        self.setWindowIcon(get_app_icon())
        self.resize(1180, 700)
        self.setAcceptDrops(True)

        # Inicia sem nenhuma JKS selecionada até o usuário abrir uma .jks ou criar uma Nova .jks
        self.doc: KeyStoreDocument = KeyStoreDocument(ks_format=KeyStoreFormat.JKS)
        self.has_active_keystore: bool = False

        self._build_menubar()
        self._build_central_ui()
        self._update_ui_state()

    def _add_card_shadow(self, widget: QWidget) -> None:
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(15, 23, 42, 18))
        widget.setGraphicsEffect(shadow)

    def _build_menubar(self) -> None:
        menubar = self.menuBar()

        menu_file = menubar.addMenu("&Arquivo")
        act_open = QAction("Abrir KeyStore (.JKS / .PFX)...", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self.action_open_file)
        menu_file.addAction(act_open)

        act_new = QAction("Criar Nova .JKS...", self)
        act_new.setShortcut("Ctrl+N")
        act_new.triggered.connect(self.action_new_keystore)
        menu_file.addAction(act_new)

        self.act_menu_clear = QAction("Limpar Selecionado", self)
        self.act_menu_clear.setShortcut("Ctrl+L")
        self.act_menu_clear.triggered.connect(self.action_clear_selected)
        menu_file.addAction(self.act_menu_clear)

        menu_file.addSeparator()

        act_save_jks = QAction("Salvar .JKS Alterada...", self)
        act_save_jks.setShortcut("Ctrl+S")
        act_save_jks.triggered.connect(self.action_save_as_jks)
        menu_file.addAction(act_save_jks)

        act_save_pfx = QAction("Exportar como .PFX...", self)
        act_save_pfx.triggered.connect(self.action_save_as_pfx)
        menu_file.addAction(act_save_pfx)

        menu_file.addSeparator()
        act_exit = QAction("Sair", self)
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        menu_ops = menubar.addMenu("&Certificados")
        self.act_menu_insert_pfx = QAction("Inserir certificado na .JKS...", self)
        self.act_menu_insert_pfx.triggered.connect(self.action_insert_pfx_into_keystore)
        menu_ops.addAction(self.act_menu_insert_pfx)

        act_build_pfx = QAction("Montar .PFX (.crt + Private Key .key)...", self)
        act_build_pfx.triggered.connect(self.action_open_pfx_builder)
        menu_ops.addAction(act_build_pfx)

        act_details = QAction("Ver Detalhes do Certificado Selecionado...", self)
        act_details.triggered.connect(self.action_view_details)
        menu_ops.addAction(act_details)

    def _build_central_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_h_layout = QHBoxLayout(central)
        main_h_layout.setContentsMargins(0, 0, 0, 0)
        main_h_layout.setSpacing(0)

        # =========================================================================
        # 1. SIDEBAR LATERAL ESCURA
        # =========================================================================
        sidebar = QFrame()
        sidebar.setFixedWidth(280)
        sidebar.setStyleSheet(
            "QFrame { background-color: #0b1120; border-right: 1px solid #1e293b; }"
        )
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(18, 22, 18, 20)
        sb_layout.setSpacing(10)

        # Identidade Visual
        brand_row = QHBoxLayout()
        brand_row.setSpacing(12)
        lbl_logo = QLabel()
        lbl_logo.setPixmap(QPixmap.fromImage(render_app_logo_image(40)))
        lbl_logo.setStyleSheet("border: none; background: transparent;")
        brand_row.addWidget(lbl_logo)

        brand_text_col = QVBoxLayout()
        brand_text_col.setSpacing(1)
        lbl_brand = QLabel("KEYSTORE & PKCS#12")
        lbl_brand.setStyleSheet(
            "color: #38bdf8; font-size: 10px; font-weight: 800; letter-spacing: 1.2px; border: none; background: transparent;"
        )
        lbl_product = QLabel("SSL Manager")
        lbl_product.setStyleSheet(
            "color: #f8fafc; font-size: 17px; font-weight: 800; border: none; background: transparent;"
        )
        brand_text_col.addWidget(lbl_brand)
        brand_text_col.addWidget(lbl_product)
        brand_row.addLayout(brand_text_col, 1)
        sb_layout.addLayout(brand_row)

        sb_layout.addSpacing(8)

        # Card de Status da JKS Selecionada na Sidebar
        self.jks_status_card = QFrame()
        self.jks_status_card.setStyleSheet(
            "QFrame { background-color: #162032; border: 1px solid #1e293b; border-radius: 8px; }"
        )
        status_card_layout = QVBoxLayout(self.jks_status_card)
        status_card_layout.setContentsMargins(12, 10, 12, 10)
        status_card_layout.setSpacing(4)

        lbl_ctx_header = QLabel("KEYSTORE SELECIONADA")
        lbl_ctx_header.setStyleSheet(
            "color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1px; border: none; background: transparent;"
        )
        self.lbl_sidebar_jks_name = QLabel("Nenhuma .JKS aberta")
        self.lbl_sidebar_jks_name.setWordWrap(True)
        self.lbl_sidebar_jks_name.setStyleSheet(
            "color: #f8fafc; font-size: 13px; font-weight: 700; border: none; background: transparent;"
        )
        self.lbl_sidebar_jks_meta = QLabel("Abra ou crie uma .JKS abaixo")
        self.lbl_sidebar_jks_meta.setWordWrap(True)
        self.lbl_sidebar_jks_meta.setStyleSheet(
            "color: #94a3b8; font-size: 11px; border: none; background: transparent;"
        )
        status_card_layout.addWidget(lbl_ctx_header)
        status_card_layout.addWidget(self.lbl_sidebar_jks_name)
        status_card_layout.addWidget(self.lbl_sidebar_jks_meta)
        sb_layout.addWidget(self.jks_status_card)

        sb_layout.addSpacing(8)

        # Seção: KeyStore (.JKS)
        lbl_sec1 = QLabel("ARQUIVO KEYSTORE")
        lbl_sec1.setStyleSheet(
            "color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1px; padding-left: 4px; border: none;"
        )
        sb_layout.addWidget(lbl_sec1)

        self.btn_open = QPushButton("  Abrir .JKS / .PFX")
        self.btn_open.setIcon(vector_icon("folder", "#38bdf8", 18))
        self.btn_open.setIconSize(QSize(18, 18))
        self.btn_open.setStyleSheet(SIDEBAR_BTN_STYLE)
        self.btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_open.clicked.connect(self.action_open_file)
        sb_layout.addWidget(self.btn_open)

        self.btn_new_jks = QPushButton("  Criar Nova .JKS")
        self.btn_new_jks.setIcon(vector_icon("plus-file", "#38bdf8", 18))
        self.btn_new_jks.setIconSize(QSize(18, 18))
        self.btn_new_jks.setStyleSheet(SIDEBAR_BTN_STYLE)
        self.btn_new_jks.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_new_jks.clicked.connect(self.action_new_keystore)
        sb_layout.addWidget(self.btn_new_jks)

        sb_layout.addSpacing(10)

        # Seção: Certificados & PFX
        lbl_sec2 = QLabel("OPERAÇÕES DE CERTIFICADO")
        lbl_sec2.setStyleSheet(
            "color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1px; padding-left: 4px; border: none;"
        )
        sb_layout.addWidget(lbl_sec2)

        self.btn_insert_pfx = QPushButton("  Inserir certificado na .JKS")
        self.btn_insert_pfx.setIcon(vector_icon("import", "#ffffff", 18))
        self.btn_insert_pfx.setIconSize(QSize(18, 18))
        self.btn_insert_pfx.setStyleSheet(SIDEBAR_ACCENT_BTN_STYLE)
        self.btn_insert_pfx.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_insert_pfx.setToolTip(
            "Disponível quando uma .JKS está selecionada. Abre o Windows Explorer para escolher o certificado (.PFX, .P12, .CRT, .CER, .PEM) e inserir na .JKS."
        )
        self.btn_insert_pfx.clicked.connect(self.action_insert_pfx_into_keystore)
        sb_layout.addWidget(self.btn_insert_pfx)

        self.btn_build_pfx = QPushButton("  Montar .PFX (.crt + .key)")
        self.btn_build_pfx.setIcon(vector_icon("layers", "#38bdf8", 18))
        self.btn_build_pfx.setIconSize(QSize(18, 18))
        self.btn_build_pfx.setStyleSheet(SIDEBAR_BTN_STYLE)
        self.btn_build_pfx.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_build_pfx.clicked.connect(self.action_open_pfx_builder)
        sb_layout.addWidget(self.btn_build_pfx)

        sb_layout.addStretch(1)

        # Seção: Salvar e Finalizar
        lbl_sec3 = QLabel("FINALIZAR E SALVAR")
        lbl_sec3.setStyleSheet(
            "color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: 1px; padding-left: 4px; border: none;"
        )
        sb_layout.addWidget(lbl_sec3)

        self.btn_save_jks = QPushButton("  Salvar .JKS Alterada")
        self.btn_save_jks.setIcon(vector_icon("save", "#ffffff", 18))
        self.btn_save_jks.setIconSize(QSize(18, 18))
        self.btn_save_jks.setStyleSheet(SIDEBAR_SAVE_BTN_STYLE)
        self.btn_save_jks.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save_jks.clicked.connect(self.action_save_as_jks)
        sb_layout.addWidget(self.btn_save_jks)

        self.btn_save_pfx = QPushButton("  Exportar como .PFX")
        self.btn_save_pfx.setIcon(vector_icon("export", "#94a3b8", 18))
        self.btn_save_pfx.setIconSize(QSize(18, 18))
        self.btn_save_pfx.setStyleSheet(SIDEBAR_BTN_STYLE)
        self.btn_save_pfx.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save_pfx.clicked.connect(self.action_save_as_pfx)
        sb_layout.addWidget(self.btn_save_pfx)

        main_h_layout.addWidget(sidebar)

        # =========================================================================
        # 2. ÁREA CENTRAL DE TRABALHO (CARDS ELEVADOS COM SOMBRA)
        # =========================================================================
        workspace = QWidget()
        ws_layout = QVBoxLayout(workspace)
        ws_layout.setContentsMargins(22, 20, 22, 20)
        ws_layout.setSpacing(16)

        # Card Superior: Informações do Arquivo Ativo
        top_card = QFrame()
        top_card.setStyleSheet(
            "QFrame { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; }"
        )
        self._add_card_shadow(top_card)
        top_card_layout = QHBoxLayout(top_card)
        top_card_layout.setContentsMargins(20, 16, 20, 16)
        top_card_layout.setSpacing(16)

        file_text_col = QVBoxLayout()
        file_text_col.setSpacing(4)
        self.lbl_main_title = QLabel("Nenhuma KeyStore Selecionada")
        self.lbl_main_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #0f172a; border: none;")
        self.lbl_main_subtitle = QLabel(
            "Para começar, clique em 'Abrir .JKS / .PFX' ou 'Criar Nova .JKS' no menu lateral."
        )
        self.lbl_main_subtitle.setWordWrap(True)
        self.lbl_main_subtitle.setStyleSheet("font-size: 12px; color: #64748b; border: none;")
        file_text_col.addWidget(self.lbl_main_title)
        file_text_col.addWidget(self.lbl_main_subtitle)
        top_card_layout.addLayout(file_text_col, 1)

        self.lbl_format_badge = QLabel("AGUARDANDO ARQUIVO")
        self.lbl_format_badge.setStyleSheet(
            "background-color: #f1f5f9; color: #475569; font-weight: 700; font-size: 11px; "
            "padding: 6px 14px; border-radius: 6px; border: 1px solid #e2e8f0;"
        )
        top_card_layout.addWidget(self.lbl_format_badge)

        self.btn_top_clear = QPushButton("  Limpar Selecionado")
        self.btn_top_clear.setIcon(vector_icon("clear", "#dc2626", 16))
        self.btn_top_clear.setProperty("danger", True)
        self.btn_top_clear.setMinimumHeight(34)
        self.btn_top_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_top_clear.setToolTip("Fecha e limpa tudo o que está selecionado até o momento.")
        self.btn_top_clear.clicked.connect(self.action_clear_selected)
        top_card_layout.addWidget(self.btn_top_clear)
        ws_layout.addWidget(top_card)

        # Card Central: Tabela de Certificados + Barra de Ações Contextuais
        table_card = QFrame()
        table_card.setStyleSheet(
            "QFrame { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; }"
        )
        self._add_card_shadow(table_card)
        tc_layout = QVBoxLayout(table_card)
        tc_layout.setContentsMargins(18, 16, 18, 16)
        tc_layout.setSpacing(14)

        table_header_row = QHBoxLayout()
        lbl_tbl_title = QLabel("Certificados e Chaves na KeyStore")
        lbl_tbl_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0f172a; border: none;")
        lbl_tbl_hint = QLabel("Clique nas colunas para ordenar ou arraste-as para reordenar")
        lbl_tbl_hint.setStyleSheet("font-size: 11px; color: #94a3b8; border: none;")
        self.lbl_entry_count = QLabel("0 entradas")
        self.lbl_entry_count.setStyleSheet("font-size: 12px; font-weight: 600; color: #64748b; border: none;")
        table_header_row.addWidget(lbl_tbl_title)
        table_header_row.addSpacing(8)
        table_header_row.addWidget(lbl_tbl_hint)
        table_header_row.addStretch()
        table_header_row.addWidget(self.lbl_entry_count)
        tc_layout.addLayout(table_header_row)

        self.table_entries = QTableWidget(0, 7)
        self.table_entries.setHorizontalHeaderLabels(
            [
                "Tipo",
                "Alias",
                "Titular (Domínio)",
                "Emissor",
                "Validade",
                "Status",
                "Cadeia",
            ]
        )
        self.table_entries.setAlternatingRowColors(True)
        self.table_entries.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_entries.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table_entries.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_entries.setShowGrid(False)
        self.table_entries.verticalHeader().setVisible(False)
        self.table_entries.verticalHeader().setDefaultSectionSize(44)

        # Permite ordenar clicando nas colunas E arrastar/redimensionar colunas livremente
        header = self.table_entries.horizontalHeader()
        header.setSectionsMovable(True)
        header.setFirstSectionMovable(True)
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setToolTip("Clique para ordenar ou segure e arraste para mudar a posição da coluna.")

        # Larguras iniciais confortáveis (redimensionáveis pelo usuário)
        initial_widths = [130, 150, 210, 170, 105, 130, 85]
        for col_idx, width in enumerate(initial_widths):
            self.table_entries.setColumnWidth(col_idx, width)

        self.table_entries.setSortingEnabled(True)
        self.table_entries.itemSelectionChanged.connect(self._on_selection_changed)
        self.table_entries.cellDoubleClicked.connect(lambda _r, _c: self.action_view_details())
        self.table_entries.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_entries.customContextMenuRequested.connect(self._show_context_menu)
        tc_layout.addWidget(self.table_entries, 1)

        # Barra Inferior de Ações da Entrada Selecionada (Design Neutro e Limpo)
        bottom_bar = QHBoxLayout()
        bottom_bar.setSpacing(10)

        self.btn_details = QPushButton("  Ver Detalhes do Certificado")
        self.btn_details.setIcon(vector_icon("eye", "#ffffff", 16))
        self.btn_details.setMinimumHeight(36)
        self.btn_details.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_details.clicked.connect(self.action_view_details)

        self.btn_rename = QPushButton("  Renomear Alias")
        self.btn_rename.setIcon(vector_icon("edit", "#334155", 16))
        self.btn_rename.setProperty("secondary", True)
        self.btn_rename.setMinimumHeight(36)
        self.btn_rename.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_rename.clicked.connect(self.action_rename_entry)

        self.btn_add_chain = QPushButton("  Anexar Cadeia (.crt)")
        self.btn_add_chain.setIcon(vector_icon("link", "#334155", 16))
        self.btn_add_chain.setProperty("secondary", True)
        self.btn_add_chain.setMinimumHeight(36)
        self.btn_add_chain.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_add_chain.clicked.connect(self.action_append_to_chain)

        self.btn_extract = QPushButton("  Extrair .CRT / .KEY")
        self.btn_extract.setIcon(vector_icon("export", "#334155", 16))
        self.btn_extract.setProperty("secondary", True)
        self.btn_extract.setMinimumHeight(36)
        self.btn_extract.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_extract.clicked.connect(self.action_extract_selected)

        self.btn_delete = QPushButton("  Excluir")
        self.btn_delete.setIcon(vector_icon("trash", "#dc2626", 16))
        self.btn_delete.setProperty("danger", True)
        self.btn_delete.setMinimumHeight(36)
        self.btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_delete.clicked.connect(self.action_delete_entry)

        bottom_bar.addWidget(self.btn_details)
        bottom_bar.addWidget(self.btn_rename)
        bottom_bar.addWidget(self.btn_add_chain)
        bottom_bar.addWidget(self.btn_extract)
        bottom_bar.addStretch()
        bottom_bar.addWidget(self.btn_delete)
        tc_layout.addLayout(bottom_bar)

        ws_layout.addWidget(table_card, 1)
        main_h_layout.addWidget(workspace, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Dica: Selecione ou crie uma .JKS para habilitar o botão 'Inserir certificado na .JKS'.")

    # --- Drag & Drop ---
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self._open_file_by_path(path)

    def _is_jks_selected(self) -> bool:
        """Retorna True somente quando há uma KeyStore .JKS aberta ou recém-criada na tela."""
        return self.has_active_keystore and self.doc.ks_format == KeyStoreFormat.JKS

    def _selected_entry(self) -> Optional[KeyStoreEntry]:
        row = self.table_entries.currentRow()
        if row < 0:
            return None
        item = self.table_entries.item(row, 0)
        if item is not None:
            entry = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(entry, KeyStoreEntry):
                return entry
        return None

    def _select_entry_object(self, target_entry: Optional[KeyStoreEntry]) -> None:
        if target_entry is None:
            return
        for row in range(self.table_entries.rowCount()):
            item = self.table_entries.item(row, 0)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) is target_entry:
                self.table_entries.selectRow(row)
                return

    def _on_selection_changed(self) -> None:
        has_sel = self._selected_entry() is not None
        self.btn_details.setEnabled(has_sel)
        self.btn_rename.setEnabled(has_sel)
        self.btn_add_chain.setEnabled(has_sel)
        self.btn_extract.setEnabled(has_sel)
        self.btn_delete.setEnabled(has_sel)

    def _make_cell(
        self,
        text: str,
        bold: bool = False,
        color: str = "#0f172a",
        sort_key=None,
    ) -> SortableTableWidgetItem:
        item = SortableTableWidgetItem(text, sort_key=sort_key)
        item.setForeground(QColor(color))
        font = QFont("Segoe UI", 10)
        if bold:
            font.setBold(True)
        item.setFont(font)
        return item

    def _update_ui_state(self, select_entry: Optional[KeyStoreEntry] = None) -> None:
        if select_entry is None:
            select_entry = self._selected_entry()

        jks_active = self._is_jks_selected()

        # Habilita "Inserir certificado na .JKS" SOMENTE quando uma .JKS estiver selecionada!
        self.btn_insert_pfx.setEnabled(jks_active)
        self.act_menu_insert_pfx.setEnabled(jks_active)
        self.btn_top_clear.setEnabled(self.has_active_keystore)
        self.act_menu_clear.setEnabled(self.has_active_keystore)
        self.btn_save_jks.setEnabled(self.has_active_keystore and len(self.doc.entries) > 0)
        self.btn_save_pfx.setEnabled(self.has_active_keystore and len(self.doc.entries) > 0)

        if not self.has_active_keystore:
            self.lbl_sidebar_jks_name.setText("Nenhuma .JKS selecionada")
            self.lbl_sidebar_jks_meta.setText("Abra uma .JKS ou clique em Criar Nova .JKS")
            self.lbl_main_title.setText("Nenhuma KeyStore Selecionada")
            self.lbl_main_subtitle.setText(
                "Abra um arquivo .JKS existente ou clique em 'Criar Nova .JKS' para habilitar a inserção de certificados."
            )
            self.lbl_format_badge.setText("AGUARDANDO ARQUIVO")
            self.lbl_format_badge.setStyleSheet(
                "background-color: #f1f5f9; color: #475569; font-weight: 700; font-size: 11px; "
                "padding: 6px 14px; border-radius: 6px; border: 1px solid #e2e8f0;"
            )
        else:
            fname = os.path.basename(self.doc.file_path) if self.doc.file_path else "Nova KeyStore (.jks)"
            mod_tag = "  •  Alterado (Não salvo)" if self.doc.modified else ""
            self.lbl_sidebar_jks_name.setText(fname)
            self.lbl_sidebar_jks_meta.setText(f"{len(self.doc.entries)} certificado(s){mod_tag}")

            self.lbl_main_title.setText(f"{fname}{mod_tag}")
            self.lbl_main_subtitle.setText(
                self.doc.file_path
                if self.doc.file_path
                else "KeyStore criada em memória — Insira o certificado e clique em 'Salvar .JKS Alterada'."
            )

            if jks_active:
                self.lbl_format_badge.setText("JKS SELECIONADA")
                self.lbl_format_badge.setStyleSheet(
                    "background-color: #e0f2fe; color: #0369a1; font-weight: 800; font-size: 11px; "
                    "padding: 6px 14px; border-radius: 6px; border: 1px solid #bae6fd;"
                )
            else:
                self.lbl_format_badge.setText(self.doc.ks_format.value.upper())
                self.lbl_format_badge.setStyleSheet(
                    "background-color: #f1f5f9; color: #334155; font-weight: 700; font-size: 11px; "
                    "padding: 6px 14px; border-radius: 6px; border: 1px solid #cbd5e1;"
                )

        self.lbl_entry_count.setText(f"{len(self.doc.entries)} entrada(s)")

        # Desativa repintura e ordenação durante o preenchimento em lote (evita travamento com 143+ certificados)
        was_sorting = self.table_entries.isSortingEnabled()
        self.table_entries.setUpdatesEnabled(False)
        self.table_entries.setSortingEnabled(False)
        self.table_entries.blockSignals(True)
        try:
            self.table_entries.setRowCount(len(self.doc.entries))
            icon_key = vector_icon("key", "#0284c7", 16)
            icon_shield = vector_icon("shield", "#64748b", 16)

            for row, entry in enumerate(self.doc.entries):
                type_item = self._make_cell(entry.type_display)
                type_item.setIcon(icon_key if entry.has_private_key else icon_shield)
                type_item.setData(Qt.ItemDataRole.UserRole, entry)
                self.table_entries.setItem(row, 0, type_item)
                self.table_entries.setItem(
                    row, 1, self._make_cell(entry.alias, bold=True, color="#0c4a6e")
                )

                if entry.certificate is not None:
                    info = inspect_certificate(entry.certificate)
                    self.table_entries.setItem(
                        row, 2, self._make_cell(info.common_name, bold=True)
                    )
                    self.table_entries.setItem(
                        row, 3, self._make_cell(info.issuer_cn, color="#475569")
                    )
                    self.table_entries.setItem(
                        row,
                        4,
                        self._make_cell(
                            info.not_after.strftime("%d/%m/%Y"),
                            color="#334155",
                            sort_key=info.not_after.timestamp(),
                        ),
                    )
                    self.table_entries.setItem(
                        row,
                        5,
                        self._make_cell(
                            info.status_label,
                            bold=True,
                            color=info.status_color,
                            sort_key=info.days_remaining,
                        ),
                    )
                else:
                    self.table_entries.setItem(row, 2, self._make_cell("(Apenas Chave Privada)"))
                    self.table_entries.setItem(row, 3, self._make_cell("-"))
                    self.table_entries.setItem(row, 4, self._make_cell("-", sort_key=0.0))
                    self.table_entries.setItem(row, 5, self._make_cell("-", sort_key=-999999))

                c_count = entry.chain_count
                self.table_entries.setItem(
                    row,
                    6,
                    self._make_cell(
                        f"{c_count} cert(s)" if c_count else "-",
                        color="#475569",
                        sort_key=c_count,
                    ),
                )
        finally:
            self.table_entries.blockSignals(False)
            self.table_entries.setSortingEnabled(was_sorting)
            self.table_entries.setUpdatesEnabled(True)

        if select_entry is not None:
            self._select_entry_object(select_entry)
        if self.doc.entries and self.table_entries.currentRow() < 0:
            self.table_entries.selectRow(0)

        self._on_selection_changed()

    def _show_context_menu(self, pos) -> None:
        entry = self._selected_entry()
        if not entry:
            return
        menu = QMenu(self)
        menu.addAction("Ver Detalhes do Certificado...", self.action_view_details)
        menu.addAction("Renomear Alias...", self.action_rename_entry)
        menu.addAction("Anexar Cadeia (.crt)...", self.action_append_to_chain)
        menu.addAction("Extrair .CRT / .KEY...", self.action_extract_selected)
        menu.addSeparator()
        menu.addAction("Excluir Entrada", self.action_delete_entry)
        menu.exec(self.table_entries.viewport().mapToGlobal(pos))

    # --- Ações ---
    def action_view_details(self) -> None:
        entry = self._selected_entry()
        if not entry:
            QMessageBox.information(
                self,
                "Selecione um Certificado",
                "Selecione uma linha na tabela para visualizar os detalhes completos do certificado.",
            )
            return
        dlg = CertificateDetailsDialog(entry, self)
        dlg.exec()

    def action_new_keystore(self) -> None:
        dlg = NewKeyStoreDialog(self)
        if dlg.exec() != NewKeyStoreDialog.DialogCode.Accepted:
            return

        self.doc = KeyStoreDocument(
            ks_format=KeyStoreFormat.JKS,
            file_path=None,
            password=dlg.get_password(),
            entries=[],
            modified=True,
        )
        self.has_active_keystore = True
        self._update_ui_state()
        self.status_bar.showMessage(
            "Nova .JKS ativa! O botão 'Inserir certificado na .JKS' está habilitado.", 5000
        )

        if dlg.insert_pfx_immediately:
            self.action_insert_pfx_into_keystore()

    def action_clear_selected(self) -> None:
        """Limpa tudo o que está selecionado até o momento (KeyStore aberta, certificados na tabela e estado)."""
        if not self.has_active_keystore and not self.doc.entries:
            self.table_entries.clearSelection()
            self.status_bar.showMessage("Tudo limpo! Nenhuma KeyStore ou certificado selecionado no momento.", 4000)
            return

        if self.doc.modified and len(self.doc.entries) > 0:
            resp = QMessageBox.question(
                self,
                "Limpar Selecionado",
                "Existem alterações ainda não salvas na KeyStore atual.\n"
                "Deseja realmente limpar tudo o que está selecionado até o momento?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                return

        self.doc = KeyStoreDocument(ks_format=KeyStoreFormat.JKS)
        self.has_active_keystore = False
        self.table_entries.clearSelection()
        self._update_ui_state()
        self.status_bar.showMessage(
            "Seleção limpa. Nenhuma KeyStore ou certificado selecionado no momento.", 5000
        )

    def action_open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar KeyStore (.JKS / cacerts / .PFX) ou Certificado",
            "",
            "KeyStores e Certificados (*.jks *.jceks *.keystore cacerts* *.pfx *.p12 *.crt *.cer *.pem *.key);;"
            "Java KeyStore (*.jks *.jceks *.keystore cacerts*);;"
            "PKCS#12 (*.pfx *.p12);;"
            "Certificados (*.crt *.cer *.pem *.der *.p7b);;"
            "Todos os Arquivos (*.*)",
        )
        if path:
            self._open_file_by_path(path)

    def _open_file_by_path(self, path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        base_lower = os.path.basename(path).lower()
        needs_pwd = ext in (".pfx", ".p12", ".jks", ".jceks", ".keystore") or base_lower.startswith("cacerts")

        if not needs_pwd:
            try:
                with open(path, "rb") as f:
                    head = f.read(4096)
                if b"ENCRYPTED" in head or head[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce"):
                    needs_pwd = True
            except Exception:
                pass

        password: Optional[str] = None
        if needs_pwd:
            dlg = PasswordPromptDialog(path, self)
            if dlg.exec() != PasswordPromptDialog.DialogCode.Accepted:
                return
            password = dlg.get_password()

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            loaded_doc = load_keystore_file(path, password)
            # Se o arquivo tem extensão .jks ou é cacerts, trata como JKS selecionada
            if ext in (".jks", ".jceks", ".keystore") or base_lower.startswith("cacerts"):
                loaded_doc.ks_format = KeyStoreFormat.JKS
            self.doc = loaded_doc
            self.has_active_keystore = True
            self._update_ui_state()
            self.status_bar.showMessage(f"Arquivo carregado: {path}", 5000)
        except Exception as err:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Erro ao Abrir Arquivo", str(err))
            return
        finally:
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

    def action_insert_pfx_into_keystore(self) -> None:
        """
        Fluxo solicitado:
        1. Só fica habilitado quando uma .JKS está selecionada.
        2. Abre diretamente a tela do Windows Explorer para escolher o certificado (.PFX, .P12, .CRT, .CER, .PEM).
        3. Após selecionar o arquivo, abre o diálogo com as informações da .JKS e pede a senha (se for .PFX/.P12).
        """
        if not self._is_jks_selected():
            QMessageBox.information(
                self,
                "Selecione uma .JKS",
                "Abra ou crie uma KeyStore .JKS primeiro para inserir um certificado nela.",
            )
            return

        default_dir = os.path.dirname(self.doc.file_path) if self.doc.file_path else ""
        pfx_path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecionar Certificado para Inserir na .JKS",
            default_dir,
            "Certificados e PKCS#12 (*.pfx *.p12 *.crt *.cer *.pem *.der *.p7b);;"
            "PKCS#12 (*.pfx *.p12);;"
            "Certificados Públicos (*.crt *.cer *.pem *.der *.p7b);;"
            "Todos os Arquivos (*.*)",
        )
        if not pfx_path:
            return

        dlg = InsertSelectedPfxDialog(pfx_path=pfx_path, target_jks=self.doc, parent=self)
        if dlg.exec() != InsertSelectedPfxDialog.DialogCode.Accepted or not dlg.loaded_entries:
            return

        replace_existing = dlg.chk_replace.isChecked()
        inserted_names = []
        last_inserted: Optional[KeyStoreEntry] = None

        for new_entry in dlg.loaded_entries:
            existing_idx = None
            for idx, cur in enumerate(self.doc.entries):
                if cur.alias.lower() == new_entry.alias.lower():
                    existing_idx = idx
                    break

            if existing_idx is not None and replace_existing:
                self.doc.entries[existing_idx] = new_entry
            else:
                new_entry.alias = self.doc.ensure_unique_alias(new_entry.alias)
                self.doc.entries.append(new_entry)
            inserted_names.append(new_entry.alias)
            last_inserted = new_entry

        self.doc.modified = True
        self._update_ui_state(select_entry=last_inserted)
        self.status_bar.showMessage(
            f"Certificado '{', '.join(inserted_names)}' inserido na .JKS! Clique em 'Salvar .JKS Alterada' para gravar.",
            6000,
        )

    def action_open_pfx_builder(self) -> None:
        jks_active = self._is_jks_selected()
        dlg = PfxBuilderDialog(has_open_jks=jks_active, parent=self)
        if dlg.exec() == PfxBuilderDialog.DialogCode.Accepted and dlg.created_document:
            created = dlg.created_document
            if jks_active and dlg.insert_into_current_jks:
                last_entry = None
                for entry in created.entries:
                    entry.alias = self.doc.ensure_unique_alias(entry.alias)
                    self.doc.entries.append(entry)
                    last_entry = entry
                self.doc.modified = True
                self._update_ui_state(select_entry=last_entry)
                QMessageBox.information(
                    self,
                    "PFX Gerado e Inserido na .JKS",
                    f"1) O arquivo .PFX foi gerado em:\n{created.file_path}\n\n"
                    f"2) Ele também já foi inserido dentro da sua .JKS selecionada!\n"
                    "Clique em 'Salvar .JKS Alterada' para finalizar.",
                )
            else:
                self.doc = created
                self.has_active_keystore = True
                self._update_ui_state()
                QMessageBox.information(
                    self,
                    "PFX Montado com Sucesso",
                    f"O arquivo .PFX foi salvo com sucesso em:\n{created.file_path}",
                )

    def action_append_to_chain(self) -> None:
        entry = self._selected_entry()
        if not entry or entry.certificate is None:
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Selecionar Certificados da Cadeia (.crt, .cer, .pem, .ca-bundle)",
            "",
            "Certificados (*.crt *.cer *.pem *.ca-bundle *.p7b *.der);;Todos os Arquivos (*.*)",
        )
        if not paths:
            return
        try:
            new_certs = list(entry.chain)
            for p in paths:
                with open(p, "rb") as f:
                    new_certs.extend(load_certificates_from_bytes(f.read()))
            entry.certificate, entry.chain = order_certificate_chain(entry.certificate, new_certs)
            self.doc.modified = True
            self._update_ui_state(select_entry=entry)
            QMessageBox.information(
                self,
                "Cadeia Atualizada",
                f"A cadeia de '{entry.alias}' agora possui {entry.chain_count} certificado(s).",
            )
        except Exception as err:
            QMessageBox.critical(self, "Erro ao Anexar Cadeia", str(err))

    def action_rename_entry(self) -> None:
        entry = self._selected_entry()
        if not entry:
            return
        new_alias, ok = QInputDialog.getText(
            self,
            "Renomear Alias",
            "Informe o novo nome (Alias) para a entrada:",
            QLineEdit.EchoMode.Normal,
            entry.alias,
        )
        if ok and new_alias.strip():
            entry.alias = new_alias.strip()
            self.doc.modified = True
            self._update_ui_state(select_entry=entry)

    def action_extract_selected(self) -> None:
        entry = self._selected_entry()
        if not entry:
            return
        default_dir = os.path.dirname(self.doc.file_path) if self.doc.file_path else ""
        dlg = ExtractKitDialog(entry, default_dir=default_dir, parent=self)
        if dlg.exec() == ExtractKitDialog.DialogCode.Accepted and dlg.created_files:
            files_list = "\n".join(f"• {p}" for p in dlg.created_files)
            QMessageBox.information(self, "Arquivos Extraídos", f"Arquivos gerados:\n\n{files_list}")

    def action_delete_entry(self) -> None:
        entry = self._selected_entry()
        if not entry:
            return
        resp = QMessageBox.question(
            self,
            "Excluir Entrada",
            f"Deseja remover '{entry.alias}' desta KeyStore?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            if entry in self.doc.entries:
                self.doc.entries.remove(entry)
                self.doc.modified = True
                self._update_ui_state()

    def action_save_as_jks(self) -> None:
        """
        Ao salvar o .JKS alterado:
        1. Seleciona onde salvar o arquivo .jks (sugerindo o arquivo atual).
        2. Solicita a definição/alteração de senha da .JKS com Senha e Confirmação de Senha!
        """
        if not self.doc.entries:
            QMessageBox.warning(
                self,
                "KeyStore Vazia",
                "Insira pelo menos um certificado antes de salvar o arquivo .JKS.",
            )
            return

        default_path = self.doc.file_path or "keystore.jks"
        base_lower = os.path.basename(default_path).lower()
        if not default_path.lower().endswith(".jks") and not base_lower.startswith("cacerts"):
            default_path = os.path.splitext(default_path)[0] + ".jks"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Java KeyStore (.JKS / cacerts)",
            default_path,
            "Java KeyStore (*.jks *.keystore cacerts*);;Todos os Arquivos (*.*)",
        )
        if not path:
            return

        pwd_dlg = SaveJksPasswordDialog(
            current_password=self.doc.password or "",
            target_path=path,
            parent=self,
        )
        if pwd_dlg.exec() != SaveJksPasswordDialog.DialogCode.Accepted:
            return

        new_pwd = pwd_dlg.get_password()

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            save_jks_file(self.doc, path, password=new_pwd)
            self.doc.file_path = path
            self.doc.password = new_pwd
            self.doc.ks_format = KeyStoreFormat.JKS
            self.doc.modified = False
            self.has_active_keystore = True
            self._update_ui_state()
        except Exception as err:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Erro ao Salvar .JKS", str(err))
            return
        finally:
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

        QMessageBox.information(
            self,
            "JKS Salva com Sucesso",
            f"O arquivo Java KeyStore (.jks) foi salvo com a senha definida em:\n{path}",
        )

    def action_save_as_pfx(self) -> None:
        if not self.doc.entries:
            QMessageBox.warning(
                self,
                "KeyStore Vazia",
                "Adicione um certificado antes de exportar como .PFX.",
            )
            return

        default_path = self.doc.file_path or "certificado.pfx"
        if not default_path.lower().endswith((".pfx", ".p12")):
            default_path = os.path.splitext(default_path)[0] + ".pfx"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar como PKCS#12 (.PFX / .P12)",
            default_path,
            "PKCS#12 KeyStore (*.pfx *.p12)",
        )
        if not path:
            return

        pwd_dlg = SaveJksPasswordDialog(
            current_password=self.doc.password or "",
            target_path=path,
            parent=self,
        )
        pwd_dlg.setWindowTitle("Definir Senha para o Arquivo .PFX")
        if pwd_dlg.exec() != SaveJksPasswordDialog.DialogCode.Accepted:
            return

        new_pwd = pwd_dlg.get_password()

        try:
            save_pkcs12_file(self.doc, path, password=new_pwd, legacy_encryption=False)
            QMessageBox.information(self, "PFX Exportado com Sucesso", f"Arquivo .PFX salvo em:\n{path}")
        except Exception as err:
            QMessageBox.critical(self, "Erro ao Exportar .PFX", str(err))

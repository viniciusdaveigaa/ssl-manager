"""Ponto de entrada principal do SSL Manager."""

import os
import sys

from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import QApplication

from core.branding import APP_NAME, ORG_NAME, get_app_icon
from ui.main_window import APP_STYLESHEET, MainWindow


def _apply_clean_light_palette(app: QApplication) -> None:
    """Força paleta limpa com contraste máximo mesmo quando o Windows 11 está em Modo Escuro."""
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#dc2626"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#dbeafe"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#1e3a8a"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#64748b"))
    app.setPalette(palette)
    app.setStyleSheet(APP_STYLESHEET)


def main() -> None:
    app = QApplication(sys.argv)
    _apply_clean_light_palette(app)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setWindowIcon(get_app_icon())
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    window.show()

    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        window._open_file_by_path(sys.argv[1])

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

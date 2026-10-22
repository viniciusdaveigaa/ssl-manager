"""Identidade visual e gerador de ícone oficial para o SSL Manager."""

from functools import lru_cache
from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

APP_NAME = "SSL Manager"
APP_SUBTITLE = "Gerenciador de KeyStores (.JKS / .PFX) e Certificados"
APP_FULL_TITLE = f"{APP_NAME} — {APP_SUBTITLE}"
ORG_NAME = "SSLManager"


@lru_cache(maxsize=16)
def render_app_logo_image(size: int = 256) -> QImage:
    """Desenha o ícone vetorial do SSL Manager com cache em memória."""
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

    s = float(size)

    bg_grad = QLinearGradient(0, 0, s, s)
    bg_grad.setColorAt(0.0, QColor("#0c4a6e"))
    bg_grad.setColorAt(0.5, QColor("#0284c7"))
    bg_grad.setColorAt(1.0, QColor("#0369a1"))

    shield = QPainterPath()
    shield.moveTo(s * 0.50, s * 0.06)
    shield.lineTo(s * 0.88, s * 0.20)
    shield.lineTo(s * 0.88, s * 0.52)
    shield.cubicTo(s * 0.88, s * 0.76, s * 0.68, s * 0.90, s * 0.50, s * 0.95)
    shield.cubicTo(s * 0.32, s * 0.90, s * 0.12, s * 0.76, s * 0.12, s * 0.52)
    shield.lineTo(s * 0.12, s * 0.20)
    shield.closeSubpath()

    p.setPen(QPen(QColor("#38bdf8"), max(2.0, s * 0.025)))
    p.setBrush(bg_grad)
    p.drawPath(shield)

    shackle_pen = QPen(QColor("#f8fafc"), max(2.5, s * 0.055), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
    p.setPen(shackle_pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    shackle_rect = QRectF(s * 0.36, s * 0.22, s * 0.28, s * 0.28)
    p.drawArc(shackle_rect, 0 * 16, 180 * 16)
    p.drawLine(QPointF(s * 0.36, s * 0.36), QPointF(s * 0.36, s * 0.44))
    p.drawLine(QPointF(s * 0.64, s * 0.36), QPointF(s * 0.64, s * 0.44))

    lock_grad = QLinearGradient(s * 0.28, s * 0.41, s * 0.72, s * 0.78)
    lock_grad.setColorAt(0.0, QColor("#10b981"))
    lock_grad.setColorAt(1.0, QColor("#059669"))

    p.setPen(QPen(QColor("#a7f3d0"), max(1.5, s * 0.015)))
    p.setBrush(lock_grad)
    lock_rect = QRectF(s * 0.28, s * 0.41, s * 0.44, s * 0.34)
    p.drawRoundedRect(lock_rect, s * 0.05, s * 0.05)

    if size >= 48:
        font = QFont("Segoe UI", max(6, int(s * 0.11)), QFont.Weight.Black)
        p.setFont(font)
        p.setPen(QColor("#ffffff"))
        p.drawText(lock_rect, Qt.AlignmentFlag.AlignCenter, "SSL")

    p.end()
    return img


@lru_cache(maxsize=1)
def get_app_icon() -> QIcon:
    """Retorna o QIcon multi-resolução do SSL Manager (renderizado apenas uma vez)."""
    icon = QIcon()
    for sz in (16, 32, 48, 256):
        img = render_app_logo_image(sz)
        icon.addPixmap(QPixmap.fromImage(img))
    return icon

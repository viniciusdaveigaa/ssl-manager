"""Renderizador de ícones vetoriais modernos (estilo Lucide / Fluent UI) com cache em memória."""

from functools import lru_cache
from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap


@lru_cache(maxsize=64)
def vector_icon(name: str, color_hex: str = "#1e293b", size: int = 20) -> QIcon:
    """Desenha ícones vetoriais nítidos em alta resolução (1x e 2x) para botões e tabelas."""
    icon = QIcon()
    for scale in (1, 2):
        px_size = size * scale
        img = QImage(px_size, px_size, QImage.Format.Format_ARGB32)
        img.fill(Qt.GlobalColor.transparent)

        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        pen = QPen(QColor(color_hex), 1.8 * scale, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)

        s = float(px_size)
        _draw_glyph(p, name, s, color_hex)
        p.end()

        pix = QPixmap.fromImage(img)
        pix.setDevicePixelRatio(float(scale))
        icon.addPixmap(pix)
    return icon


def _draw_glyph(p: QPainter, name: str, s: float, color_hex: str) -> None:
    if name == "folder":
        path = QPainterPath()
        path.moveTo(s * 0.12, s * 0.28)
        path.lineTo(s * 0.38, s * 0.28)
        path.lineTo(s * 0.46, s * 0.38)
        path.lineTo(s * 0.88, s * 0.38)
        path.lineTo(s * 0.88, s * 0.78)
        path.lineTo(s * 0.12, s * 0.78)
        path.closeSubpath()
        p.drawPath(path)

    elif name == "plus-file":
        # Documento com sinal de +
        path = QPainterPath()
        path.moveTo(s * 0.22, s * 0.14)
        path.lineTo(s * 0.58, s * 0.14)
        path.lineTo(s * 0.78, s * 0.34)
        path.lineTo(s * 0.78, s * 0.86)
        path.lineTo(s * 0.22, s * 0.86)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.50, s * 0.44), QPointF(s * 0.50, s * 0.68))
        p.drawLine(QPointF(s * 0.38, s * 0.56), QPointF(s * 0.62, s * 0.56))

    elif name == "import":
        # Caixa de entrada com seta para baixo
        p.drawLine(QPointF(s * 0.50, s * 0.15), QPointF(s * 0.50, s * 0.62))
        p.drawLine(QPointF(s * 0.34, s * 0.46), QPointF(s * 0.50, s * 0.62))
        p.drawLine(QPointF(s * 0.66, s * 0.46), QPointF(s * 0.50, s * 0.62))
        tray = QPainterPath()
        tray.moveTo(s * 0.16, s * 0.58)
        tray.lineTo(s * 0.16, s * 0.82)
        tray.lineTo(s * 0.84, s * 0.82)
        tray.lineTo(s * 0.84, s * 0.58)
        p.drawPath(tray)

    elif name == "export":
        # Caixa com seta para cima
        p.drawLine(QPointF(s * 0.50, s * 0.62), QPointF(s * 0.50, s * 0.16))
        p.drawLine(QPointF(s * 0.34, s * 0.32), QPointF(s * 0.50, s * 0.16))
        p.drawLine(QPointF(s * 0.66, s * 0.32), QPointF(s * 0.50, s * 0.16))
        tray = QPainterPath()
        tray.moveTo(s * 0.16, s * 0.58)
        tray.lineTo(s * 0.16, s * 0.82)
        tray.lineTo(s * 0.84, s * 0.82)
        tray.lineTo(s * 0.84, s * 0.58)
        p.drawPath(tray)

    elif name == "layers":
        # Camadas (Montar PFX)
        top = QPainterPath()
        top.moveTo(s * 0.50, s * 0.16)
        top.lineTo(s * 0.86, s * 0.34)
        top.lineTo(s * 0.50, s * 0.52)
        top.lineTo(s * 0.14, s * 0.34)
        top.closeSubpath()
        p.drawPath(top)

        mid = QPainterPath()
        mid.moveTo(s * 0.14, s * 0.50)
        mid.lineTo(s * 0.50, s * 0.68)
        mid.lineTo(s * 0.86, s * 0.50)
        p.drawPath(mid)

        bot = QPainterPath()
        bot.moveTo(s * 0.14, s * 0.66)
        bot.lineTo(s * 0.50, s * 0.84)
        bot.lineTo(s * 0.86, s * 0.66)
        p.drawPath(bot)

    elif name == "save":
        # Disquete / Salvar moderno
        path = QPainterPath()
        path.moveTo(s * 0.18, s * 0.16)
        path.lineTo(s * 0.70, s * 0.16)
        path.lineTo(s * 0.84, s * 0.30)
        path.lineTo(s * 0.84, s * 0.84)
        path.lineTo(s * 0.18, s * 0.84)
        path.closeSubpath()
        p.drawPath(path)
        p.drawRect(QRectF(s * 0.32, s * 0.16, s * 0.32, s * 0.22))
        p.drawRect(QRectF(s * 0.28, s * 0.54, s * 0.44, s * 0.30))

    elif name == "eye":
        # Olho (Ver Detalhes)
        path = QPainterPath()
        path.moveTo(s * 0.10, s * 0.50)
        path.cubicTo(s * 0.28, s * 0.22, s * 0.72, s * 0.22, s * 0.90, s * 0.50)
        path.cubicTo(s * 0.72, s * 0.78, s * 0.28, s * 0.78, s * 0.10, s * 0.50)
        p.drawPath(path)
        p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.12, s * 0.12)

    elif name == "edit":
        # Lápis (Renomear)
        path = QPainterPath()
        path.moveTo(s * 0.66, s * 0.18)
        path.lineTo(s * 0.82, s * 0.34)
        path.lineTo(s * 0.34, s * 0.82)
        path.lineTo(s * 0.16, s * 0.84)
        path.lineTo(s * 0.18, s * 0.66)
        path.closeSubpath()
        p.drawPath(path)

    elif name == "link":
        # Elo de corrente (Cadeia CA)
        p.drawRoundedRect(QRectF(s * 0.14, s * 0.36, s * 0.42, s * 0.28), s * 0.14, s * 0.14)
        p.drawRoundedRect(QRectF(s * 0.44, s * 0.36, s * 0.42, s * 0.28), s * 0.14, s * 0.14)

    elif name == "key":
        # Chave (Senha / Par de chaves)
        p.drawEllipse(QPointF(s * 0.34, s * 0.50), s * 0.18, s * 0.18)
        p.drawLine(QPointF(s * 0.52, s * 0.50), QPointF(s * 0.86, s * 0.50))
        p.drawLine(QPointF(s * 0.72, s * 0.50), QPointF(s * 0.72, s * 0.66))
        p.drawLine(QPointF(s * 0.84, s * 0.50), QPointF(s * 0.84, s * 0.68))

    elif name == "shield":
        # Escudo (Certificado)
        path = QPainterPath()
        path.moveTo(s * 0.50, s * 0.14)
        path.lineTo(s * 0.82, s * 0.26)
        path.lineTo(s * 0.82, s * 0.52)
        path.cubicTo(s * 0.82, s * 0.72, s * 0.66, s * 0.84, s * 0.50, s * 0.88)
        path.cubicTo(s * 0.34, s * 0.84, s * 0.18, s * 0.72, s * 0.18, s * 0.52)
        path.lineTo(s * 0.18, s * 0.26)
        path.closeSubpath()
        p.drawPath(path)

    elif name == "trash":
        # Lixeira (Excluir)
        p.drawLine(QPointF(s * 0.18, s * 0.26), QPointF(s * 0.82, s * 0.26))
        p.drawLine(QPointF(s * 0.38, s * 0.16), QPointF(s * 0.62, s * 0.16))
        box = QPainterPath()
        box.moveTo(s * 0.26, s * 0.26)
        box.lineTo(s * 0.30, s * 0.84)
        box.lineTo(s * 0.70, s * 0.84)
        box.lineTo(s * 0.74, s * 0.26)
        p.drawPath(box)
        p.drawLine(QPointF(s * 0.43, s * 0.40), QPointF(s * 0.43, s * 0.70))
        p.drawLine(QPointF(s * 0.57, s * 0.40), QPointF(s * 0.57, s * 0.70))

    elif name == "clear":
        # Círculo com X (Limpar Selecionado / Resetar)
        p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.36, s * 0.36)
        p.drawLine(QPointF(s * 0.36, s * 0.36), QPointF(s * 0.64, s * 0.64))
        p.drawLine(QPointF(s * 0.64, s * 0.36), QPointF(s * 0.36, s * 0.64))

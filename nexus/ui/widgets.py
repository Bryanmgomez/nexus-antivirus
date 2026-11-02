from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .theme import ACCENT, ACCENT_2, CARD, GREEN, MUTED, RED, TEXT, YELLOW


class Page(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.container = QWidget()
        self.container.setObjectName("ContentArea")
        self.setWidget(self.container)
        self.root = QVBoxLayout(self.container)
        self.root.setContentsMargins(30, 24, 30, 28)
        self.root.setSpacing(16)

    def add(self, widget: QWidget) -> None:
        self.root.addWidget(widget)


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None, accent: bool = False):
        super().__init__(parent)
        self.setObjectName("CardAccent" if accent else "Card")


class StatCard(Card):
    def __init__(self, label: str, value: str = "0", hint: str = "", color: str = ACCENT_2, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(5)
        self.label = QLabel(label.upper())
        self.label.setObjectName("CardLabel")
        self.value = QLabel(value)
        self.value.setObjectName("StatValue")
        self.value.setStyleSheet(f"color: {color};")
        self.hint = QLabel(hint)
        self.hint.setObjectName("StatHint")
        self.hint.setWordWrap(True)
        layout.addWidget(self.label)
        layout.addWidget(self.value)
        layout.addWidget(self.hint)
        self.setMinimumHeight(112)

    def set_value(self, value: str, hint: str | None = None, color: str | None = None) -> None:
        self.value.setText(value)
        if hint is not None:
            self.hint.setText(hint)
        if color:
            self.value.setStyleSheet(f"color: {color};")


class Badge(QLabel):
    def __init__(self, text: str = "", state: str = "muted", parent=None):
        super().__init__(text, parent)
        self.setProperty("badge", "true")
        self.set_state(state)
        self.setAlignment(Qt.AlignCenter)

    def set_state(self, state: str, text: str | None = None) -> None:
        self.setProperty("state", state)
        if text is not None:
            self.setText(text)
        self.style().unpolish(self)
        self.style().polish(self)


class Switch(QAbstractButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(52, 28)
        self._offset = 0.0
        self._animation = QPropertyAnimation(self, b"offset", self)
        self._animation.setDuration(160)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self.toggled.connect(self._animate)

    def sizeHint(self) -> QSize:
        return QSize(52, 28)

    def _animate(self, checked: bool) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._offset)
        self._animation.setEndValue(1.0 if checked else 0.0)
        self._animation.start()

    def get_offset(self) -> float:
        return self._offset

    def set_offset(self, value: float) -> None:
        self._offset = value
        self.update()

    offset = Property(float, get_offset, set_offset)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        track = QRectF(2, 4, self.width() - 4, self.height() - 8)
        off_color = QColor("#12283b")
        on_color = QColor(ACCENT)
        color = QColor(
            int(off_color.red() + (on_color.red() - off_color.red()) * self._offset),
            int(off_color.green() + (on_color.green() - off_color.green()) * self._offset),
            int(off_color.blue() + (on_color.blue() - off_color.blue()) * self._offset),
        )
        painter.setPen(QPen(QColor("#2b5879") if not self.isChecked() else QColor(ACCENT_2), 1))
        painter.setBrush(color)
        painter.drawRoundedRect(track, 10, 10)
        knob_x = 5 + self._offset * (self.width() - 30)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#ffffff") if self.isChecked() else QColor("#7d99ae"))
        painter.drawEllipse(QRectF(knob_x, 7, 18, 18))
        painter.end()


class StatusRing(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._phase = 0.0
        self._color = QColor(GREEN)
        self._caption = "PROTEGIDO"
        self.setMinimumSize(230, 230)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._animation = QPropertyAnimation(self, b"displayValue", self)
        self._animation.setDuration(800)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._pulse)
        self._timer.start(55)

    def _pulse(self) -> None:
        self._phase = (self._phase + 0.06) % (math.pi * 2)
        self.update()

    def get_display_value(self) -> float:
        return self._value

    def set_display_value(self, value: float) -> None:
        self._value = max(0.0, min(100.0, float(value)))
        self.update()

    displayValue = Property(float, get_display_value, set_display_value)

    def set_score(self, value: float, caption: str, color: str) -> None:
        self._caption = caption
        self._color = QColor(color)
        self._animation.stop()
        self._animation.setStartValue(self._value)
        self._animation.setEndValue(float(value))
        self._animation.start()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        size = min(self.width(), self.height()) - 38
        rect = QRectF((self.width() - size) / 2, (self.height() - size) / 2, size, size)
        painter.setPen(QPen(QColor("#102a3f"), 12, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        glow = QColor(self._color)
        pulse = 26 + int(15 * (1 + math.sin(self._phase)) / 2)
        glow.setAlpha(pulse)
        painter.setPen(QPen(glow, 22, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, int(-360 * 16 * self._value / 100))
        painter.setPen(QPen(self._color, 11, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, int(-360 * 16 * self._value / 100))
        painter.setPen(QColor(TEXT))
        font = QFont("Segoe UI", 32, QFont.DemiBold)
        painter.setFont(font)
        value_text = f"{int(round(self._value))}%"
        painter.drawText(rect.adjusted(0, -10, 0, -10), Qt.AlignCenter, value_text)
        painter.setPen(QColor(self._color))
        font = QFont("Segoe UI", 9, QFont.Bold)
        font.setLetterSpacing(QFont.AbsoluteSpacing, 2.5)
        painter.setFont(font)
        painter.drawText(rect.adjusted(0, 54, 0, 54), Qt.AlignCenter, self._caption)
        painter.end()


class ActivityChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: list[dict[str, Any]] = []
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_data(self, data: list[dict[str, Any]]) -> None:
        self._data = data
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(14, 16, -14, -32)
        painter.setPen(QPen(QColor("#102235"), 1))
        for index in range(5):
            y = rect.top() + rect.height() * index / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
        if not self._data:
            painter.setPen(QColor(MUTED))
            painter.drawText(rect, Qt.AlignCenter, "Sin datos de actividad")
            painter.end()
            return
        maximum = max(
            [max(int(row.get("scans", 0)), int(row.get("threats", 0)), 1) for row in self._data] + [1]
        )
        count = len(self._data)
        slot = rect.width() / max(1, count)
        bar_width = max(6.0, min(24.0, slot * 0.27))
        for index, row in enumerate(self._data):
            center = rect.left() + slot * (index + 0.5)
            scans = int(row.get("scans", 0))
            threats = int(row.get("threats", 0))
            scans_height = (scans / maximum) * rect.height()
            threats_height = (threats / maximum) * rect.height()
            base = rect.bottom()
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#1b6fa8"))
            painter.drawRoundedRect(
                QRectF(center - bar_width - 2, base - scans_height, bar_width, scans_height), 3, 3
            )
            painter.setBrush(QColor(RED) if threats else QColor("#17364b"))
            painter.drawRoundedRect(
                QRectF(center + 2, base - max(2, threats_height), bar_width, max(2, threats_height)), 3, 3
            )
            day = str(row.get("day", ""))
            try:
                label = datetime.fromisoformat(day).strftime("%d/%m")
            except ValueError:
                label = day
            painter.setPen(QColor(MUTED))
            font = QFont("Segoe UI", 8)
            painter.setFont(font)
            painter.drawText(
                QRectF(center - slot / 2, base + 7, slot, 20), Qt.AlignHCenter | Qt.AlignTop, label
            )
        painter.setPen(QColor(ACCENT_2))
        painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
        painter.drawText(rect.adjusted(0, -2, 0, -2), Qt.AlignTop | Qt.AlignLeft, "ANALISIS")
        painter.setPen(QColor(RED))
        painter.drawText(rect.adjusted(62, -2, 0, -2), Qt.AlignTop | Qt.AlignLeft, "DETECCIONES")
        painter.end()


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self.title = QLabel(title)
        self.title.setObjectName("PageTitle")
        row.addWidget(self.title)
        row.addStretch(1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(8)
        row.addLayout(self.actions)
        layout.addLayout(row)
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("PageSubtitle")
        self.subtitle.setWordWrap(True)
        layout.addWidget(self.subtitle)

    def add_action(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)


def make_table(headers: list[str], stretch_column: int | None = None) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setSelectionMode(QTableWidget.SingleSelection)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.setShowGrid(False)
    table.setWordWrap(False)
    table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    table.verticalHeader().setDefaultSectionSize(33)
    if stretch_column is not None:
        from PySide6.QtWidgets import QHeaderView

        table.horizontalHeader().setSectionResizeMode(stretch_column, QHeaderView.Stretch)
    return table


def item(text: Any, color: str | None = None, tooltip: str | None = None) -> QTableWidgetItem:
    cell = QTableWidgetItem(str(text))
    if color:
        cell.setForeground(QColor(color))
    if tooltip:
        cell.setToolTip(tooltip)
    return cell


def severity_color(severity: str) -> str:
    return {
        "critical": RED,
        "high": RED,
        "medium": YELLOW,
        "low": ACCENT_2,
        "test": ACCENT_2,
        "info": MUTED,
    }.get(severity.lower(), TEXT)


def verdict_color(verdict: str) -> str:
    return {"malware": RED, "suspicious": YELLOW, "clean": GREEN}.get(verdict.lower(), TEXT)


def elide(text: str, length: int = 70) -> str:
    return text if len(text) <= length else text[: length - 1] + "..."


def draw_hexagon_badge(color: str, size: int = 34) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(QColor(color), 1.5))
    painter.setBrush(QColor(CARD))
    center = size / 2
    points = [
        (center, 1),
        (size - 2, size * 0.27),
        (size - 2, size * 0.73),
        (center, size - 1),
        (2, size * 0.73),
        (2, size * 0.27),
    ]
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QPolygonF

    painter.drawPolygon(QPolygonF([QPointF(x, y) for x, y in points]))
    painter.end()
    return pixmap

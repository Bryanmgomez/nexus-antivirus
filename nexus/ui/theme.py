from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import QApplication

BG = "#05080f"
BG_2 = "#070d16"
CARD = "#0a1421"
CARD_2 = "#0d1a2a"
BORDER = "#17304a"
BORDER_LIGHT = "#1f4162"
TEXT = "#dbe9f6"
MUTED = "#718ca3"
ACCENT = "#25a9ff"
ACCENT_2 = "#5be2ff"
GREEN = "#3ee6a5"
YELLOW = "#ffc857"
RED = "#ff5d73"
ORANGE = "#ff9950"


def app_icon() -> QIcon:
    pixmap = QPixmap(128, 128)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    gradient = QLinearGradient(0, 0, 128, 128)
    gradient.setColorAt(0, QColor(ACCENT_2))
    gradient.setColorAt(1, QColor("#0a5fff"))
    painter.setBrush(gradient)
    painter.setPen(QPen(QColor(ACCENT_2), 3))
    points = [
        QPointF(64, 8),
        QPointF(116, 38),
        QPointF(116, 90),
        QPointF(64, 120),
        QPointF(12, 90),
        QPointF(12, 38),
    ]
    painter.drawPolygon(QPolygonF(points))
    painter.setBrush(QColor(5, 8, 15))
    painter.setPen(Qt.NoPen)
    inner = [
        QPointF(64, 22),
        QPointF(101, 43),
        QPointF(101, 85),
        QPointF(64, 106),
        QPointF(27, 85),
        QPointF(27, 43),
    ]
    painter.drawPolygon(QPolygonF(inner))
    painter.setPen(QPen(QColor(ACCENT_2), 5))
    painter.drawLine(46, 44, 46, 84)
    painter.drawLine(46, 44, 82, 84)
    painter.drawLine(82, 84, 82, 44)
    painter.end()
    return QIcon(pixmap)


STYLESHEET = f"""
* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    outline: none;
}}
QMainWindow, QWidget {{
    background: {BG};
    color: {TEXT};
    font-size: 13px;
}}
QWidget#Sidebar {{
    background: {BG_2};
    border-right: 1px solid {BORDER};
}}
QWidget#ContentArea {{
    background: qradialgradient(cx:0.75, cy:0.05, radius:1.3, fx:0.75, fy:0.05,
        stop:0 #0a1726, stop:0.45 #060c15, stop:1 {BG});
}}
QLabel#Logo {{
    font-size: 25px;
    font-weight: 800;
    letter-spacing: 5px;
    color: {TEXT};
}}
QLabel#LogoSub {{
    font-size: 9px;
    letter-spacing: 4px;
    color: {ACCENT};
}}
QLabel#PageTitle {{
    font-size: 26px;
    font-weight: 700;
    letter-spacing: 1px;
    color: {TEXT};
}}
QLabel#PageSubtitle {{
    color: {MUTED};
    font-size: 12px;
}}
QLabel#Muted {{ color: {MUTED}; }}
QLabel#CardLabel {{
    color: {MUTED};
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: 600;
}}
QLabel#StatValue {{
    font-size: 30px;
    font-weight: 700;
    color: {TEXT};
}}
QLabel#StatHint {{ color: {MUTED}; font-size: 11px; }}
QLabel#SectionTitle {{
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1px;
    color: {TEXT};
}}
QLabel#Accent {{ color: {ACCENT_2}; }}
QLabel#Danger {{ color: {RED}; }}
QLabel#Good {{ color: {GREEN}; }}
QLabel#Warning {{ color: {YELLOW}; }}
QLabel[badge="true"] {{
    border-radius: 10px;
    padding: 3px 10px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    background: #0e2234;
    color: {ACCENT_2};
    border: 1px solid #17476b;
}}
QLabel[badge="true"][state="ok"] {{ color: {GREEN}; border-color: #15563f; background: #0b241d; }}
QLabel[badge="true"][state="warning"] {{ color: {YELLOW}; border-color: #5e4a18; background: #241e0a; }}
QLabel[badge="true"][state="danger"] {{ color: {RED}; border-color: #612b34; background: #240e12; }}
QLabel[badge="true"][state="muted"] {{ color: {MUTED}; border-color: {BORDER}; background: #0b111a; }}

QFrame#Card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QFrame#CardAccent {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0b1a2b, stop:1 #08111c);
    border: 1px solid {BORDER_LIGHT};
    border-radius: 14px;
}}
QFrame#HeroCard {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #081522, stop:0.55 #0a1726, stop:1 #07101a);
    border: 1px solid #1b3e5d;
    border-radius: 18px;
}}
QFrame#Divider {{ background: {BORDER}; max-height: 1px; }}

QPushButton {{
    background: #0e1b2a;
    color: {TEXT};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 8px;
    padding: 9px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background: #12263a; border-color: {ACCENT}; }}
QPushButton:pressed {{ background: #0a1521; }}
QPushButton:disabled {{ color: #4c6579; border-color: #122438; background: #09111b; }}
QPushButton#Primary {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #136dff, stop:1 {ACCENT});
    color: #ffffff;
    border: 1px solid #4dc6ff;
    border-radius: 9px;
    padding: 12px 22px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 1px;
}}
QPushButton#Primary:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d82ff, stop:1 #53ccff);
}}
QPushButton#Danger {{
    background: #2a1016;
    color: #ff8b9b;
    border: 1px solid #6b2a36;
}}
QPushButton#Danger:hover {{ background: #3a141c; border-color: {RED}; }}
QPushButton#Ghost {{
    background: transparent;
    border: 1px solid {BORDER};
    color: {MUTED};
}}
QPushButton#Ghost:hover {{ color: {TEXT}; border-color: {BORDER_LIGHT}; background: #0a1522; }}
QPushButton#NavButton {{
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    text-align: left;
    padding: 12px 20px;
    color: {MUTED};
    font-weight: 600;
    letter-spacing: 0.4px;
}}
QPushButton#NavButton:hover {{ color: {TEXT}; background: #0a1522; }}
QPushButton#NavButton:checked {{
    color: {ACCENT_2};
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0b2033, stop:1 transparent);
    border-left: 3px solid {ACCENT};
}}
QPushButton#ScanTile {{
    text-align: left;
    padding: 18px;
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 12px;
    font-size: 14px;
}}
QPushButton#ScanTile:hover {{
    background: {CARD_2};
    border-color: {ACCENT};
}}
QPushButton#ScanTile:pressed {{ background: #0c2235; }}
QPushButton#LinkButton {{
    background: transparent;
    border: none;
    color: {ACCENT_2};
    padding: 2px 4px;
    text-align: left;
}}
QPushButton#LinkButton:hover {{ color: #9decff; text-decoration: underline; }}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {{
    background: #08111c;
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 8px 10px;
    color: {TEXT};
    selection-background-color: #15598a;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{
    border-color: {ACCENT};
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: #0b1624;
    border: 1px solid {BORDER_LIGHT};
    selection-background-color: #123b59;
    color: {TEXT};
}}
QSpinBox::up-button, QSpinBox::down-button {{
    background: #102033;
    border: none;
    width: 16px;
}}
QCheckBox {{ color: {TEXT}; spacing: 9px; }}
QCheckBox::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {BORDER_LIGHT};
    border-radius: 4px;
    background: #08111c;
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT_2};
}}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}

QProgressBar {{
    background: #07111b;
    border: 1px solid {BORDER};
    border-radius: 6px;
    text-align: center;
    color: {TEXT};
    min-height: 16px;
}}
QProgressBar::chunk {{
    border-radius: 5px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0b5cff, stop:1 {ACCENT_2});
}}

QTableWidget {{
    background: #070f19;
    alternate-background-color: #091421;
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: #102235;
    selection-background-color: #123b59;
    selection-color: #ffffff;
    padding: 4px;
}}
QTableWidget::item {{
    padding: 7px;
    border-bottom: 1px solid #0d1c2b;
}}
QHeaderView::section {{
    background: #0a1624;
    color: #6fa9cb;
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 9px 7px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QTableCornerButton::section {{ background: #0a1624; border: none; }}

QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    background: transparent;
    top: -1px;
}}
QTabBar::tab {{
    background: transparent;
    color: {MUTED};
    padding: 9px 16px;
    border-bottom: 2px solid transparent;
    font-weight: 600;
}}
QTabBar::tab:selected {{ color: {ACCENT_2}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 9px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #1a3b57; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #27628e; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 9px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #1a3b57; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QToolTip {{
    background: #0d1c2b;
    color: {TEXT};
    border: 1px solid {BORDER_LIGHT};
    padding: 6px;
}}
QStatusBar {{ background: {BG_2}; color: {MUTED}; border-top: 1px solid {BORDER}; }}
QMenu {{ background: #0b1624; border: 1px solid {BORDER}; color: {TEXT}; }}
QMenu::item {{ padding: 8px 22px; }}
QMenu::item:selected {{ background: #123b59; }}
QMessageBox {{ background: {CARD}; }}
QInputDialog {{ background: {CARD}; }}
QFileDialog {{ background: {CARD}; }}
QSplitter::handle {{ background: {BORDER}; }}
QListWidget {{
    background: #070f19;
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 4px;
}}
QListWidget::item {{ padding: 6px; border-bottom: 1px solid #0d1c2b; }}
QListWidget::item:selected {{ background: #123b59; }}
"""


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    app.setWindowIcon(app_icon())

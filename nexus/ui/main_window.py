from __future__ import annotations

import ctypes
import logging
import sys

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from ..models import Detection
from ..security.ransomware import RansomAlert
from ..services import NexusServices
from .pages import (
    DashboardPage,
    ProtectionPage,
    QuarantinePage,
    ScanPage,
    SettingsPage,
    SystemPage,
    ThreatsPage,
    ToolsPage,
    UpdatesPage,
)
from .theme import ACCENT_2, GREEN, MUTED, RED, YELLOW, app_icon
from .widgets import Badge

log = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    detection_signal = Signal(object)
    ransomware_signal = Signal(object)
    usb_signal = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NEXUS ANTIVIRUS")
        self.setMinimumSize(1180, 760)
        self.resize(1420, 900)
        self._syncing_tray = False
        self._shutdown_done = False
        self._tray_hint_shown = False

        self.detection_signal.connect(self._detection_ui, Qt.QueuedConnection)
        self.ransomware_signal.connect(self._ransomware_ui, Qt.QueuedConnection)
        self.usb_signal.connect(self._usb_ui, Qt.QueuedConnection)

        self.services = NexusServices(
            on_detection=self.detection_signal.emit,
            on_ransomware=self.ransomware_signal.emit,
            on_usb=self.usb_signal.emit,
        )

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(232)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.setSpacing(0)

        logo_box = QWidget()
        logo_layout = QVBoxLayout(logo_box)
        logo_layout.setContentsMargins(24, 26, 20, 22)
        logo_layout.setSpacing(2)
        logo = QLabel("NEXUS")
        logo.setObjectName("Logo")
        sub = QLabel("ANTIVIRUS / ENDPOINT")
        sub.setObjectName("LogoSub")
        logo_layout.addWidget(logo)
        logo_layout.addWidget(sub)
        side_layout.addWidget(logo_box)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        nav_items = [
            ("dashboard", "01   PANEL"),
            ("scan", "02   ANALISIS"),
            ("quarantine", "03   CUARENTENA"),
            ("threats", "04   AMENAZAS"),
            ("protection", "05   PROTECCION"),
            ("system", "06   SISTEMA"),
            ("tools", "07   HERRAMIENTAS"),
            ("updates", "08   ACTUALIZACIONES"),
            ("settings", "09   CONFIGURACION"),
        ]
        for index, (key, label) in enumerate(nav_items):
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setMinimumHeight(44)
            button.clicked.connect(lambda _checked=False, k=key: self.show_page(k))
            self.nav_group.addButton(button, index)
            side_layout.addWidget(button)
            button.setProperty("page_key", key)
        side_layout.addStretch(1)

        side_status = QWidget()
        side_status_layout = QVBoxLayout(side_status)
        side_status_layout.setContentsMargins(22, 14, 18, 20)
        side_status_layout.setSpacing(8)
        self.side_realtime = QLabel("PROTECCION: INACTIVA")
        self.side_realtime.setObjectName("CardLabel")
        self.side_engines = QLabel()
        self.side_engines.setObjectName("Muted")
        self.side_engines.setWordWrap(True)
        version = QLabel("NEXUS 1.0.0 / LOCAL")
        version.setObjectName("Muted")
        version.setStyleSheet("font-size: 10px; letter-spacing: 1px;")
        side_status_layout.addWidget(self.side_realtime)
        side_status_layout.addWidget(self.side_engines)
        side_status_layout.addWidget(version)
        side_layout.addWidget(side_status)

        content = QWidget()
        content.setObjectName("ContentArea")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 12, 20, 12)
        content_layout.setSpacing(0)
        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack)
        root.addWidget(sidebar)
        root.addWidget(content, 1)
        self.setCentralWidget(central)

        self.pages: dict[str, QWidget] = {
            "dashboard": DashboardPage(self),
            "scan": ScanPage(self),
            "quarantine": QuarantinePage(self),
            "threats": ThreatsPage(self),
            "protection": ProtectionPage(self),
            "system": SystemPage(self),
            "tools": ToolsPage(self),
            "updates": UpdatesPage(self),
            "settings": SettingsPage(self),
        }
        self.dashboard_page = self.pages["dashboard"]
        self.scan_page = self.pages["scan"]
        self.quarantine_page = self.pages["quarantine"]
        self.threats_page = self.pages["threats"]
        self.protection_page = self.pages["protection"]
        self.system_page = self.pages["system"]
        self.tools_page = self.pages["tools"]
        self.updates_page = self.pages["updates"]
        self.settings_page = self.pages["settings"]
        for page in self.pages.values():
            self.stack.addWidget(page)

        self._build_status_bar()
        self._build_tray()
        self.show_page("dashboard")

        QTimer.singleShot(0, self._start_background)
        QTimer.singleShot(200, self._startup_visibility)

    def _build_status_bar(self) -> None:
        bar = QStatusBar()
        bar.setSizeGripEnabled(False)
        self.setStatusBar(bar)
        self.status_message = QLabel("Listo")
        self.status_message.setObjectName("Muted")
        bar.addWidget(self.status_message, 1)
        self.engine_badge = Badge("MOTORES", "muted")
        self.realtime_badge = Badge("TIEMPO REAL: INACTIVA", "muted")
        self.admin_badge = Badge("USUARIO", "muted")
        bar.addPermanentWidget(self.engine_badge)
        bar.addPermanentWidget(self.realtime_badge)
        bar.addPermanentWidget(self.admin_badge)

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(app_icon(), self)
        self.tray.setToolTip("NEXUS ANTIVIRUS")
        menu = QMenu()
        show_action = QAction("Abrir NEXUS", self)
        show_action.triggered.connect(self.show_from_tray)
        quick_action = QAction("Analisis rapido", self)
        quick_action.triggered.connect(lambda: self.start_scan("quick"))
        full_action = QAction("Analisis completo", self)
        full_action.triggered.connect(lambda: self.start_scan("full"))
        self.tray_realtime = QAction("Proteccion en tiempo real", self)
        self.tray_realtime.setCheckable(True)
        self.tray_realtime.toggled.connect(self._tray_realtime_toggled)
        quit_action = QAction("Salir", self)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(show_action)
        menu.addSeparator()
        menu.addAction(quick_action)
        menu.addAction(full_action)
        menu.addSeparator()
        menu.addAction(self.tray_realtime)
        menu.addSeparator()
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()
        self.refresh_tray_state()

    def _tray_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_from_tray()

    def _tray_realtime_toggled(self, enabled: bool) -> None:
        if self._syncing_tray:
            return
        self.set_realtime_enabled(enabled)

    def _start_background(self) -> None:
        ok, message = self.services.start_background()
        if not ok:
            self.notify("Proteccion", message, "warning")
        self.refresh_tray_state()
        self._refresh_status()
        try:
            self.dashboard_page.refresh()
        except Exception:
            log.exception("Error refrescando panel inicial")

    def _startup_visibility(self) -> None:
        if "--background" in sys.argv or self.services.settings.get_bool("start_minimized", False):
            if self.tray.isVisible():
                self.hide()
                if not self._tray_hint_shown:
                    self.tray.showMessage(
                        "NEXUS ANTIVIRUS",
                        "NEXUS sigue activo en la bandeja del sistema.",
                        QSystemTrayIcon.Information,
                        4000,
                    )
                    self._tray_hint_shown = True

    def show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for button in self.nav_group.buttons():
            if button.property("page_key") == key:
                button.setChecked(True)
                break
        refresh = getattr(page, "refresh", None)
        if callable(refresh) and key != "dashboard":
            try:
                refresh()
            except Exception:
                log.exception("Error refrescando pagina %s", key)

    def start_scan(self, scan_type: str, roots: list[str] | None = None) -> None:
        self.show_from_tray()
        self.show_page("scan")
        self.scan_page.start_scan(scan_type, roots)

    def set_realtime_enabled(self, enabled: bool) -> None:
        if enabled:
            ok, message = self.services.realtime.start()
            if not ok:
                QMessageBox.warning(self, "Proteccion en tiempo real", message)
                enabled = False
        else:
            self.services.realtime.stop()
            message = "Proteccion en tiempo real desactivada."
        self.notify(
            "Proteccion en tiempo real",
            message,
            "info" if enabled else "warning",
        )
        self.protection_page.refresh()
        self.dashboard_page.sync_realtime()
        self.refresh_dashboard()
        self.refresh_tray_state()
        self._refresh_status()

    def refresh_dashboard(self) -> None:
        try:
            self.dashboard_page.refresh()
        except Exception:
            log.exception("Error refrescando panel")

    def refresh_tray_state(self) -> None:
        active = self.services.realtime.running
        self._syncing_tray = True
        self.tray_realtime.setChecked(active)
        self._syncing_tray = False
        self.tray.setToolTip(
            "NEXUS ANTIVIRUS\nProteccion en tiempo real: " + ("ACTIVA" if active else "INACTIVA")
        )

    def _refresh_status(self) -> None:
        info = self.services.engine_info()
        sig_count = self.services.signatures.count
        yara_ok = self.services.yara.ready
        if sig_count and yara_ok:
            self.engine_badge.set_state("ok", f"MOTORES: {sig_count} FIRMAS / {self.services.yara.rule_count} YARA")
        else:
            self.engine_badge.set_state("warning", "MOTORES: REVISAR")
        active = self.services.realtime.running
        self.realtime_badge.set_state("ok" if active else "warning", "TIEMPO REAL: ACTIVA" if active else "TIEMPO REAL: INACTIVA")
        self.side_realtime.setText("PROTECCION: ACTIVA" if active else "PROTECCION: INACTIVA")
        self.side_realtime.setStyleSheet(f"color: {GREEN if active else YELLOW};")
        clam = "ClamAV OK" if self.services.clamav.available else "ClamAV opcional"
        self.side_engines.setText(f"{sig_count} firmas / {self.services.yara.rule_count} YARA\n{clam}")
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            admin = False
        self.admin_badge.set_state("ok" if admin else "muted", "ADMIN" if admin else "USUARIO")

    def notify(self, title: str, message: str, level: str = "info") -> None:
        color = {
            "info": ACCENT_2,
            "success": GREEN,
            "warning": YELLOW,
            "error": RED,
            "critical": RED,
        }.get(level, MUTED)
        self.status_message.setText(message)
        self.status_message.setStyleSheet(f"color: {color};")
        if self.services.settings.get_bool("notifications_enabled", True) and self.tray.isVisible():
            icon = {
                "warning": QSystemTrayIcon.Warning,
                "error": QSystemTrayIcon.Critical,
                "critical": QSystemTrayIcon.Critical,
            }.get(level, QSystemTrayIcon.Information)
            self.tray.showMessage(title, message, icon, 5000)

    def _detection_ui(self, detection: Detection) -> None:
        action = "aislado en cuarentena" if detection.action == "quarantined" else "requiere revision"
        self.notify(
            "Deteccion: " + detection.name,
            f"{detection.path} — {detection.verdict}, {action}.",
            "critical" if detection.verdict == "malware" else "warning",
        )
        self.refresh_dashboard()
        try:
            self.quarantine_page.refresh()
        except Exception:
            log.exception("Error refrescando cuarentena tras deteccion")
        if self.stack.currentWidget() is self.threats_page:
            try:
                self.threats_page.refresh()
            except Exception:
                log.exception("Error refrescando amenazas tras deteccion")

    def _ransomware_ui(self, alert: RansomAlert) -> None:
        processes = "\n".join(
            f"- PID {item.get('pid')} {item.get('name')} ({item.get('io_mb', 0)} MB I/O)"
            for item in alert.candidate_processes[:8]
        )
        detail = (
            f"{alert.reason}\n\nArchivos modificados: {alert.files_in_window} en "
            f"{alert.window_seconds} s\nSeveridad: {alert.severity}\n\n"
            f"Procesos candidatos:\n{processes or 'Sin candidatos correlacionados.'}"
        )
        self.services.db.add_event("critical", "ransomware", alert.reason, {"paths": alert.sample_paths})
        self.notify("Alerta antiransomware", alert.reason, "critical")
        self.refresh_dashboard()
        QMessageBox.critical(
            self,
            "Alerta de ransomware",
            detail
            + "\n\nNEXUS no modifico ni suspendio procesos automaticamente. "
            "Revise la pagina SISTEMA para inspeccionar los procesos.",
        )

    def _usb_ui(self, drive: str) -> None:
        self.notify(
            "Unidad removible",
            f"Unidad {drive} detectada. Abra Herramientas para analizarla.",
            "info",
        )
        try:
            self.tools_page.refresh_drives()
        except Exception:
            pass

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        self._shutdown_done = True
        try:
            self.services.shutdown()
        except Exception:
            log.exception("Error cerrando servicios")
        self.tray.hide()
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._shutdown_done:
            event.accept()
            return
        if (
            self.services.settings.get_bool("close_to_tray", False)
            and self.tray.isVisible()
        ):
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self.tray.showMessage(
                    "NEXUS ANTIVIRUS",
                    "NEXUS sigue protegiendo el equipo en segundo plano.",
                    QSystemTrayIcon.Information,
                    4000,
                )
                self._tray_hint_shown = True
            return
        self._shutdown_done = True
        try:
            self.services.shutdown()
        except Exception:
            log.exception("Error cerrando servicios")
        self.tray.hide()
        event.accept()
        QApplication.quit()

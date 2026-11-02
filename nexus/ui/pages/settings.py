from __future__ import annotations

import ctypes
import logging
import os

from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ... import paths
from ...util import format_bytes
from ..theme import ACCENT_2, GREEN, MUTED, TEXT, YELLOW
from ..widgets import Badge, Card, Page, PageHeader

log = logging.getLogger(__name__)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class SettingsPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services

        header = PageHeader(
            "CONFIGURACION",
            "Preferencias de interfaz, comportamiento y almacenamiento local.",
        )
        self.add(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        behavior = Card(accent=True)
        behavior_layout = QVBoxLayout(behavior)
        behavior_layout.setContentsMargins(20, 17, 20, 17)
        title = QLabel("COMPORTAMIENTO")
        title.setObjectName("SectionTitle")
        behavior_layout.addWidget(title)
        self.notifications = QCheckBox("Mostrar notificaciones y mensajes de bandeja")
        self.start_minimized = QCheckBox("Iniciar minimizado en la bandeja del sistema")
        self.close_to_tray = QCheckBox("Mantener NEXUS en la bandeja al cerrar la ventana")
        self.usb_auto = QCheckBox("Detectar unidades removibles al conectarlas")
        for checkbox in (self.notifications, self.start_minimized, self.close_to_tray, self.usb_auto):
            behavior_layout.addWidget(checkbox)
        save_behavior = QPushButton("Guardar preferencias")
        save_behavior.setObjectName("Primary")
        save_behavior.clicked.connect(self.save_behavior)
        behavior_layout.addWidget(save_behavior, 0)
        behavior_layout.addStretch(1)
        grid.addWidget(behavior, 0, 0)

        engines = Card()
        engines_layout = QVBoxLayout(engines)
        engines_layout.setContentsMargins(20, 17, 20, 17)
        engine_title = QLabel("MOTORES Y LIMITES")
        engine_title.setObjectName("SectionTitle")
        engines_layout.addWidget(engine_title)
        self.heuristics = QCheckBox("Activar heuristicas conservadoras")
        self.yara = QCheckBox("Activar reglas YARA")
        self.clamav = QCheckBox("Activar ClamAV cuando este disponible")
        for checkbox in (self.heuristics, self.yara, self.clamav):
            engines_layout.addWidget(checkbox)
        limit_row = QHBoxLayout()
        limit_row.addWidget(QLabel("Tamano maximo por archivo"))
        self.max_size = QSpinBox()
        self.max_size.setRange(1, 4096)
        self.max_size.setSuffix(" MB")
        limit_row.addWidget(self.max_size)
        limit_row.addStretch(1)
        engines_layout.addLayout(limit_row)
        save_engines = QPushButton("Guardar motores")
        save_engines.setObjectName("Primary")
        save_engines.clicked.connect(self.save_engines)
        engines_layout.addWidget(save_engines, 0)
        engines_layout.addStretch(1)
        grid.addWidget(engines, 0, 1)

        storage = Card()
        storage_layout = QVBoxLayout(storage)
        storage_layout.setContentsMargins(20, 17, 20, 17)
        storage_title = QLabel("ALMACENAMIENTO")
        storage_title.setObjectName("SectionTitle")
        storage_layout.addWidget(storage_title)
        self.data_label = QLabel()
        self.data_label.setObjectName("Muted")
        self.data_label.setWordWrap(True)
        storage_layout.addWidget(self.data_label)
        buttons = QHBoxLayout()
        open_data = QPushButton("Datos")
        open_data.setObjectName("Ghost")
        open_data.clicked.connect(lambda: self.open_path(paths.data_dir()))
        open_logs = QPushButton("Registros")
        open_logs.setObjectName("Ghost")
        open_logs.clicked.connect(lambda: self.open_path(paths.logs_dir()))
        open_quarantine = QPushButton("Cuarentena")
        open_quarantine.setObjectName("Ghost")
        open_quarantine.clicked.connect(lambda: self.open_path(paths.quarantine_dir()))
        buttons.addWidget(open_data)
        buttons.addWidget(open_logs)
        buttons.addWidget(open_quarantine)
        buttons.addStretch(1)
        storage_layout.addLayout(buttons)
        self.cleanup_logs = QPushButton("Limpiar registros antiguos")
        self.cleanup_logs.setObjectName("Ghost")
        self.cleanup_logs.clicked.connect(self.cleanup_logs_clicked)
        storage_layout.addWidget(self.cleanup_logs, 0)
        storage_layout.addStretch(1)
        grid.addWidget(storage, 1, 0)

        about = Card()
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(20, 17, 20, 17)
        about_title = QLabel("ACERCA DE NEXUS")
        about_title.setObjectName("SectionTitle")
        about_layout.addWidget(about_title)
        self.admin_badge = Badge("USUARIO ESTANDAR", "warning")
        about_layout.addWidget(self.admin_badge, 0)
        about_text = QLabel(
            "NEXUS ANTIVIRUS 1.0.0\n"
            "Proteccion de endpoints para Windows 10/11.\n\n"
            "Motores: firmas SHA-256, YARA, ClamAV opcional y heuristicas PE/scripts. "
            "La cuarentena usa AES-256-CTR con HMAC-SHA256 y clave protegida por DPAPI.\n\n"
            "NEXUS no desactiva Windows Defender ni el firewall. Las heuristicas generan "
            "alertas de revision, no veredictos definitivos."
        )
        about_text.setObjectName("Muted")
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        about_layout.addStretch(1)
        grid.addWidget(about, 1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        wrapper = QWidget()
        wrapper.setLayout(grid)
        self.add(wrapper)
        self.root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        settings = self.services.settings
        self.notifications.setChecked(settings.get_bool("notifications_enabled", True))
        self.start_minimized.setChecked(settings.get_bool("start_minimized", False))
        self.close_to_tray.setChecked(settings.get_bool("close_to_tray", False))
        self.usb_auto.setChecked(settings.get_bool("usb_scan_enabled", True))
        self.heuristics.setChecked(settings.get_bool("heuristics_enabled", True))
        self.yara.setChecked(settings.get_bool("yara_enabled", True))
        self.clamav.setChecked(settings.get_bool("clamav_enabled", True))
        self.max_size.setValue(settings.get_int("max_file_size_mb", 256))
        try:
            db_size = paths.database_path().stat().st_size
        except OSError:
            db_size = 0
        self.data_label.setText(
            f"Carpeta de datos:\n{paths.data_dir()}\n\n"
            f"Base de datos: {format_bytes(db_size)}\n"
            f"Cuarentena: {paths.quarantine_dir()}\n"
            f"Registros: {paths.logs_dir()}"
        )
        admin = _is_admin()
        self.admin_badge.set_state("ok" if admin else "warning", "ADMINISTRADOR" if admin else "USUARIO ESTANDAR")
        self.clamav.setEnabled(self.services.clamav.available)

    def save_behavior(self) -> None:
        settings = self.services.settings
        settings.set_bool("notifications_enabled", self.notifications.isChecked())
        settings.set_bool("start_minimized", self.start_minimized.isChecked())
        settings.set_bool("close_to_tray", self.close_to_tray.isChecked())
        settings.set_bool("usb_scan_enabled", self.usb_auto.isChecked())
        self.window.notify("Configuracion", "Preferencias guardadas.", "info")

    def save_engines(self) -> None:
        settings = self.services.settings
        settings.set_bool("heuristics_enabled", self.heuristics.isChecked())
        settings.set_bool("yara_enabled", self.yara.isChecked())
        settings.set_bool("clamav_enabled", self.clamav.isChecked())
        settings.set("max_file_size_mb", self.max_size.value())
        self.services.reload_engines(False)
        self.window.notify("Configuracion", "Motores y limites actualizados.", "info")
        self.window.refresh_dashboard()

    def cleanup_logs_clicked(self) -> None:
        logs = sorted(paths.logs_dir().glob("nexus.log.*"), key=lambda item: item.stat().st_mtime)
        if not logs:
            QMessageBox.information(self, "Registros", "No hay registros rotados antiguos.")
            return
        reply = QMessageBox.question(
            self,
            "Limpiar registros",
            f"¿Eliminar {len(logs)} archivo(s) de registro rotados?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        removed = 0
        for path in logs:
            try:
                path.unlink()
                removed += 1
            except OSError:
                log.exception("No se pudo eliminar %s", path)
        self.window.notify("Registros", f"{removed} archivo(s) eliminados.", "info")

    def open_path(self, path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
            os.startfile(str(path))
        except OSError as exc:
            QMessageBox.warning(self, "Abrir carpeta", str(exc))

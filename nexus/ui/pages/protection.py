from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...engine.clamav import ClamAVEngine
from ...security import autostart
from ..theme import ACCENT_2, GREEN, MUTED, RED, TEXT, YELLOW
from ..widgets import Badge, Card, Page, PageHeader, Switch, elide
from ..workers import launch_task

log = logging.getLogger(__name__)


class ProtectionPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._syncing = False

        header = PageHeader(
            "PROTECCION",
            "Supervision en tiempo real, inicio con Windows y defensa contra ransomware.",
        )
        self.status_badge = Badge("INACTIVA", "muted")
        header.add_action(self.status_badge)
        self.add(header)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        realtime_card = Card(accent=True)
        rt_layout = QVBoxLayout(realtime_card)
        rt_layout.setContentsMargins(20, 17, 20, 17)
        rt_top = QHBoxLayout()
        title = QLabel("PROTECCION EN TIEMPO REAL")
        title.setObjectName("SectionTitle")
        self.realtime_switch = Switch()
        self.realtime_switch.toggled.connect(self._toggle_realtime)
        rt_top.addWidget(title)
        rt_top.addStretch(1)
        rt_top.addWidget(self.realtime_switch)
        rt_layout.addLayout(rt_top)
        self.realtime_detail = QLabel("Supervisa carpetas y analiza archivos nuevos o modificados.")
        self.realtime_detail.setObjectName("Muted")
        self.realtime_detail.setWordWrap(True)
        rt_layout.addWidget(self.realtime_detail)
        self.watch_list = QListWidget()
        self.watch_list.setMaximumHeight(120)
        rt_layout.addWidget(self.watch_list)
        watch_buttons = QHBoxLayout()
        add_watch = QPushButton("Anadir carpeta")
        add_watch.setObjectName("Ghost")
        add_watch.clicked.connect(self.add_watch)
        remove_watch = QPushButton("Quitar")
        remove_watch.setObjectName("Ghost")
        remove_watch.clicked.connect(self.remove_watch)
        watch_buttons.addWidget(add_watch)
        watch_buttons.addWidget(remove_watch)
        watch_buttons.addStretch(1)
        rt_layout.addLayout(watch_buttons)

        auto_row = QHBoxLayout()
        self.auto_quarantine = Switch()
        self.auto_quarantine.toggled.connect(self._auto_quarantine_changed)
        auto_row.addWidget(self.auto_quarantine)
        auto_label = QLabel("Cuarentena automatica de malware confirmado")
        auto_label.setObjectName("Muted")
        auto_row.addWidget(auto_label)
        auto_row.addStretch(1)
        rt_layout.addLayout(auto_row)
        grid.addWidget(realtime_card, 0, 0)

        startup_card = Card()
        startup_layout = QVBoxLayout(startup_card)
        startup_layout.setContentsMargins(20, 17, 20, 17)
        startup_top = QHBoxLayout()
        startup_title = QLabel("INICIO CON WINDOWS")
        startup_title.setObjectName("SectionTitle")
        self.autostart_switch = Switch()
        self.autostart_switch.toggled.connect(self._toggle_autostart)
        startup_top.addWidget(startup_title)
        startup_top.addStretch(1)
        startup_top.addWidget(self.autostart_switch)
        startup_layout.addLayout(startup_top)
        self.autostart_detail = QLabel(
            "Registra NEXUS en HKCU\\...\\Run para el usuario actual. No requiere administrador."
        )
        self.autostart_detail.setObjectName("Muted")
        self.autostart_detail.setWordWrap(True)
        startup_layout.addWidget(self.autostart_detail)
        startup_layout.addStretch(1)
        self.startup_command = QLabel()
        self.startup_command.setObjectName("Muted")
        self.startup_command.setWordWrap(True)
        startup_layout.addWidget(self.startup_command)
        grid.addWidget(startup_card, 0, 1)

        ransom_card = Card()
        ransom_layout = QVBoxLayout(ransom_card)
        ransom_layout.setContentsMargins(20, 17, 20, 17)
        ransom_top = QHBoxLayout()
        ransom_title = QLabel("ESCUDO ANTIRANSOMWARE")
        ransom_title.setObjectName("SectionTitle")
        self.ransom_switch = Switch()
        ransom_top.addWidget(ransom_title)
        ransom_top.addStretch(1)
        ransom_top.addWidget(self.ransom_switch)
        ransom_layout.addLayout(ransom_top)
        ransom_note = QLabel(
            "Detecta rafagas de modificaciones y notas de rescate. Genera alertas y correlaciona procesos por "
            "escrituras, pero nunca cifra, elimina ni modifica archivos personales."
        )
        ransom_note.setObjectName("Muted")
        ransom_note.setWordWrap(True)
        ransom_layout.addWidget(ransom_note)
        settings_row = QHBoxLayout()
        settings_row.addWidget(QLabel("Ventana (segundos)"))
        self.ransom_window = QSpinBox()
        self.ransom_window.setRange(2, 300)
        settings_row.addWidget(self.ransom_window)
        settings_row.addSpacing(14)
        settings_row.addWidget(QLabel("Umbral de archivos"))
        self.ransom_threshold = QSpinBox()
        self.ransom_threshold.setRange(5, 2000)
        settings_row.addWidget(self.ransom_threshold)
        settings_row.addStretch(1)
        ransom_layout.addLayout(settings_row)
        save_ransom = QPushButton("Guardar parametros")
        save_ransom.setObjectName("Ghost")
        save_ransom.clicked.connect(self.save_ransom_settings)
        ransom_layout.addWidget(save_ransom, 0)
        grid.addWidget(ransom_card, 1, 0, 1, 2)

        engine_card = Card()
        engine_layout = QVBoxLayout(engine_card)
        engine_layout.setContentsMargins(20, 17, 20, 17)
        engine_title = QLabel("MOTORES DE DETECCION")
        engine_title.setObjectName("SectionTitle")
        engine_layout.addWidget(engine_title)
        self.engine_labels: dict[str, QLabel] = {}
        for key in ("Firmas SHA-256", "YARA", "ClamAV", "Heuristica"):
            row = QHBoxLayout()
            label = QLabel(key.upper())
            label.setObjectName("CardLabel")
            value = QLabel("—")
            value.setObjectName("Muted")
            value.setWordWrap(True)
            row.addWidget(label, 0)
            row.addSpacing(12)
            row.addWidget(value, 1)
            engine_layout.addLayout(row)
            self.engine_labels[key] = value
        clam_row = QHBoxLayout()
        self.clam_path = QLineEdit()
        self.clam_path.setPlaceholderText("Ruta de clamscan.exe (opcional)")
        browse = QPushButton("Examinar")
        browse.setObjectName("Ghost")
        browse.clicked.connect(self.browse_clam)
        test = QPushButton("Comprobar")
        test.setObjectName("Ghost")
        test.clicked.connect(self.check_clam)
        clam_row.addWidget(self.clam_path, 1)
        clam_row.addWidget(browse)
        clam_row.addWidget(test)
        engine_layout.addLayout(clam_row)
        self.clam_status = QLabel()
        self.clam_status.setObjectName("Muted")
        self.clam_status.setWordWrap(True)
        engine_layout.addWidget(self.clam_status)
        engine_layout.addStretch(1)
        grid.addWidget(engine_card, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)
        self.add_widget(grid)

        exclusions = Card()
        ex_layout = QVBoxLayout(exclusions)
        ex_layout.setContentsMargins(20, 17, 20, 17)
        ex_top = QHBoxLayout()
        ex_title = QLabel("EXCLUSIONES")
        ex_title.setObjectName("SectionTitle")
        ex_top.addWidget(ex_title)
        ex_top.addStretch(1)
        add_ex = QPushButton("Anadir")
        add_ex.setObjectName("Ghost")
        add_ex.clicked.connect(self.add_exclusion)
        remove_ex = QPushButton("Quitar")
        remove_ex.setObjectName("Ghost")
        remove_ex.clicked.connect(self.remove_exclusion)
        ex_top.addWidget(add_ex)
        ex_top.addWidget(remove_ex)
        ex_layout.addLayout(ex_top)
        ex_note = QLabel("Las rutas excluidas no se analizan ni se supervisan. No excluya carpetas de riesgo.")
        ex_note.setObjectName("Muted")
        ex_note.setWordWrap(True)
        ex_layout.addWidget(ex_note)
        self.exclusion_list = QListWidget()
        self.exclusion_list.setMaximumHeight(125)
        ex_layout.addWidget(self.exclusion_list)
        self.add(exclusions)
        self.root.addStretch(1)
        self.refresh()

    def add_widget(self, layout) -> None:
        wrapper = QWidget()
        wrapper.setLayout(layout)
        self.add(wrapper)

    def refresh(self) -> None:
        self._syncing = True
        try:
            self.realtime_switch.setChecked(self.services.realtime.running)
            self.autostart_switch.setChecked(autostart.is_enabled())
            self.auto_quarantine.setChecked(self.services.settings.get_bool("auto_quarantine", False))
            self.ransom_switch.setChecked(self.services.settings.get_bool("ransomware_enabled", True))
            self.ransom_window.setValue(self.services.settings.ransomware_window)
            self.ransom_threshold.setValue(self.services.settings.ransomware_threshold)
            self.clam_path.setText(self.services.settings.get("clamav_path", ""))
            self.watch_list.clear()
            self.watch_list.addItems(self.services.settings.watch_folders)
            self.exclusion_list.clear()
            self.exclusion_list.addItems(self.services.settings.excluded_paths)
            self._update_status()
            info = self.services.engine_info()
            for key, label in self.engine_labels.items():
                label.setText(info.get(key, "—"))
            self.startup_command.setText(
                "Comando registrado: " + elide(autostart.registered_command() or "ninguno", 130)
            )
            if self.services.clamav.available:
                self.clam_status.setText(f"ClamAV detectado: {self.services.clamav.scan_binary}")
                self.clam_status.setStyleSheet(f"color: {GREEN};")
            else:
                self.clam_status.setText(
                    "ClamAV no disponible. Instale ClamAV y configure la ruta, o deje el motor desactivado."
                )
                self.clam_status.setStyleSheet(f"color: {YELLOW};")
        finally:
            self._syncing = False

    def _update_status(self) -> None:
        active = self.services.realtime.running
        self.status_badge.set_state("ok" if active else "warning", "ACTIVA" if active else "INACTIVA")
        self.realtime_detail.setText(
            "Supervisando cambios en "
            + str(len(self.services.realtime.watched_folders()))
            + " carpeta(s). Los archivos nuevos o modificados se analizan en segundo plano."
            if active
            else "Supervisa carpetas y analiza archivos nuevos o modificados."
        )

    def _toggle_realtime(self, enabled: bool) -> None:
        if self._syncing:
            return
        if enabled:
            ok, message = self.services.realtime.start()
            if not ok:
                QMessageBox.warning(self, "Proteccion en tiempo real", message)
                self._syncing = True
                self.realtime_switch.setChecked(False)
                self._syncing = False
            else:
                self.window.notify("Proteccion activa", message, "info")
        else:
            self.services.realtime.stop()
            self.window.notify("Proteccion desactivada", "La supervision en tiempo real se detuvo.", "warning")
        self._update_status()
        self.window.refresh_dashboard()
        self.window.refresh_tray_state()

    def _toggle_autostart(self, enabled: bool) -> None:
        if self._syncing:
            return
        ok, message = autostart.enable() if enabled else autostart.disable()
        self.services.settings.set_bool("autostart_enabled", enabled and ok)
        if not ok:
            QMessageBox.warning(self, "Inicio con Windows", message)
            self._syncing = True
            self.autostart_switch.setChecked(not enabled)
            self._syncing = False
        else:
            self.window.notify("Inicio con Windows", message, "info")
        self.startup_command.setText(
            "Comando registrado: " + elide(autostart.registered_command() or "ninguno", 130)
        )

    def _auto_quarantine_changed(self, enabled: bool) -> None:
        if self._syncing:
            return
        self.services.settings.set_bool("auto_quarantine", enabled)

    def save_ransom_settings(self) -> None:
        self.services.settings.set_bool("ransomware_enabled", self.ransom_switch.isChecked())
        self.services.settings.set("ransomware_window_seconds", self.ransom_window.value())
        self.services.settings.set("ransomware_file_threshold", self.ransom_threshold.value())
        self.services.ransomware.clear()
        self.window.notify("Antiransomware", "Parametros guardados.", "info")

    def add_watch(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Carpeta a supervisar")
        if not folder:
            return
        items = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        if folder not in items:
            self.watch_list.addItem(folder)
            self._save_watch()

    def remove_watch(self) -> None:
        row = self.watch_list.currentRow()
        if row >= 0:
            self.watch_list.takeItem(row)
            self._save_watch()

    def _save_watch(self) -> None:
        folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        self.services.settings.set_list("watch_folders", folders)
        if self.services.realtime.running:
            ok, message = self.services.realtime.restart()
            if not ok:
                QMessageBox.warning(self, "Proteccion en tiempo real", message)

    def add_exclusion(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Ruta a excluir")
        if not folder:
            return
        items = [self.exclusion_list.item(i).text() for i in range(self.exclusion_list.count())]
        if folder not in items:
            self.exclusion_list.addItem(folder)
            self._save_exclusions()

    def remove_exclusion(self) -> None:
        row = self.exclusion_list.currentRow()
        if row >= 0:
            self.exclusion_list.takeItem(row)
            self._save_exclusions()

    def _save_exclusions(self) -> None:
        values = [self.exclusion_list.item(i).text() for i in range(self.exclusion_list.count())]
        self.services.settings.set_list("excluded_paths", values)
        self.window.notify("Exclusiones", "Configuracion guardada.", "info")

    def browse_clam(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar clamscan.exe", "", "Ejecutable (*.exe);;Todos (*)"
        )
        if path:
            self.clam_path.setText(path)

    def check_clam(self) -> None:
        path = self.clam_path.text().strip()
        engine = ClamAVEngine(path)
        if engine.available:
            self.services.settings.set("clamav_path", path)
            self.services.clamav = engine
            self.services.scanner.clamav = engine
            self.clam_status.setText(f"ClamAV detectado: {engine.scan_binary} / {engine.version}")
            self.clam_status.setStyleSheet(f"color: {GREEN};")
            self.window.notify("ClamAV", "Motor disponible y configurado.", "info")
        else:
            self.clam_status.setText("No se encontro clamscan.exe en la ruta indicada ni en el PATH.")
            self.clam_status.setStyleSheet(f"color: {RED};")
        self.refresh()

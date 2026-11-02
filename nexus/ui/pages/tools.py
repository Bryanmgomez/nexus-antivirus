from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...security.shredder import secure_delete
from ...security.url_analysis import analyze_url, check_virustotal
from ...paths import backups_dir
from ...system.backup import create_backup, list_backups, restore_backup
from ...usb import removable_drives
from ...util import format_bytes
from ..theme import GREEN, RED, TEXT, YELLOW
from ..widgets import Card, Page, PageHeader
from ..workers import launch_task

log = logging.getLogger(__name__)


class ToolsPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._backups: list[dict] = []

        header = PageHeader(
            "HERRAMIENTAS",
            "Analisis de enlaces, destruccion segura, unidades removibles y copias de seguridad.",
        )
        self.add(header)

        url_card = Card(accent=True)
        url_layout = QVBoxLayout(url_card)
        url_layout.setContentsMargins(20, 17, 20, 17)
        title = QLabel("ANALISIS DE URL / PHISHING")
        title.setObjectName("SectionTitle")
        url_layout.addWidget(title)
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://ejemplo.com/inicio")
        self.url_input.returnPressed.connect(self.analyze_url_clicked)
        analyze = QPushButton("ANALIZAR")
        analyze.setObjectName("Primary")
        analyze.clicked.connect(self.analyze_url_clicked)
        url_row.addWidget(self.url_input, 1)
        url_row.addWidget(analyze)
        url_layout.addLayout(url_row)
        self.url_result = QLabel(
            "El analisis offline evalua esquema, host, IP directa, acortadores, TLD de riesgo, "
            "marcas y ejecutables. No abre el enlace."
        )
        self.url_result.setObjectName("Muted")
        self.url_result.setWordWrap(True)
        self.url_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        url_layout.addWidget(self.url_result)
        vt_row = QHBoxLayout()
        self.vt_key = QLineEdit()
        self.vt_key.setEchoMode(QLineEdit.Password)
        self.vt_key.setPlaceholderText("Clave API de VirusTotal (opcional)")
        self.vt_consent = QCheckBox("Autorizo enviar esta URL a VirusTotal")
        query = QPushButton("Consultar VirusTotal")
        query.setObjectName("Ghost")
        query.clicked.connect(self.virustotal_clicked)
        vt_row.addWidget(self.vt_key, 1)
        vt_row.addWidget(self.vt_consent)
        vt_row.addWidget(query)
        url_layout.addLayout(vt_row)
        self.vt_status = QLabel()
        self.vt_status.setObjectName("Muted")
        self.vt_status.setWordWrap(True)
        url_layout.addWidget(self.vt_status)
        self.add(url_card)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        shred_card = Card()
        shred_layout = QVBoxLayout(shred_card)
        shred_layout.setContentsMargins(20, 17, 20, 17)
        shred_title = QLabel("DESTRUCTOR SEGURO")
        shred_title.setObjectName("SectionTitle")
        shred_layout.addWidget(shred_title)
        shred_note = QLabel(
            "Sobrescribe el archivo con datos aleatorios, sincroniza a disco y lo elimina. "
            "No garantiza borrado fisico en SSD con wear leveling ni en copias del sistema."
        )
        shred_note.setObjectName("Muted")
        shred_note.setWordWrap(True)
        shred_layout.addWidget(shred_note)
        self.shred_path = QLineEdit()
        self.shred_path.setPlaceholderText("Archivo a destruir")
        shred_browse = QPushButton("Elegir archivo")
        shred_browse.setObjectName("Ghost")
        shred_browse.clicked.connect(self.choose_shred_file)
        shred_row = QHBoxLayout()
        shred_row.addWidget(self.shred_path, 1)
        shred_row.addWidget(shred_browse)
        shred_layout.addLayout(shred_row)
        passes_row = QHBoxLayout()
        passes_row.addWidget(QLabel("Pasadas (1-7)"))
        self.shred_passes = QComboBox()
        self.shred_passes.addItems([str(value) for value in range(1, 8)])
        self.shred_passes.setCurrentText("3")
        passes_row.addWidget(self.shred_passes)
        passes_row.addStretch(1)
        destroy = QPushButton("DESTRUIR")
        destroy.setObjectName("Danger")
        destroy.clicked.connect(self.shred_clicked)
        passes_row.addWidget(destroy)
        shred_layout.addLayout(passes_row)
        grid.addWidget(shred_card, 0, 0)

        usb_card = Card()
        usb_layout = QVBoxLayout(usb_card)
        usb_layout.setContentsMargins(20, 17, 20, 17)
        usb_title = QLabel("UNIDADES REMOVIBLES")
        usb_title.setObjectName("SectionTitle")
        usb_layout.addWidget(usb_title)
        usb_note = QLabel(
            "Analiza una unidad USB con el motor completo. La deteccion automatica al insertar "
            "esta controlada por la configuracion de proteccion."
        )
        usb_note.setObjectName("Muted")
        usb_note.setWordWrap(True)
        usb_layout.addWidget(usb_note)
        self.drive_combo = QComboBox()
        usb_layout.addWidget(self.drive_combo)
        usb_row = QHBoxLayout()
        refresh_drives = QPushButton("Buscar unidades")
        refresh_drives.setObjectName("Ghost")
        refresh_drives.clicked.connect(self.refresh_drives)
        scan_usb = QPushButton("ANALIZAR UNIDAD")
        scan_usb.setObjectName("Primary")
        scan_usb.clicked.connect(self.scan_usb)
        usb_row.addWidget(refresh_drives)
        usb_row.addStretch(1)
        usb_row.addWidget(scan_usb)
        usb_layout.addLayout(usb_row)
        usb_layout.addStretch(1)
        grid.addWidget(usb_card, 0, 1)

        backup_card = Card()
        backup_layout = QVBoxLayout(backup_card)
        backup_layout.setContentsMargins(20, 17, 20, 17)
        backup_title = QLabel("COPIAS DE SEGURIDAD")
        backup_title.setObjectName("SectionTitle")
        backup_layout.addWidget(backup_title)
        backup_note = QLabel(
            "Crea un ZIP de una carpeta antes de una limpieza. Las copias se guardan solo en el "
            "almacen local de NEXUS; no se suben a Internet."
        )
        backup_note.setObjectName("Muted")
        backup_note.setWordWrap(True)
        backup_layout.addWidget(backup_note)
        self.backup_list = QListWidget()
        self.backup_list.setMaximumHeight(125)
        backup_layout.addWidget(self.backup_list)
        backup_buttons = QHBoxLayout()
        create = QPushButton("CREAR COPIA")
        create.setObjectName("Primary")
        create.clicked.connect(self.create_backup_clicked)
        restore = QPushButton("RESTAURAR")
        restore.setObjectName("Ghost")
        restore.clicked.connect(self.restore_backup_clicked)
        open_folder = QPushButton("Abrir carpeta")
        open_folder.setObjectName("Ghost")
        open_folder.clicked.connect(self.open_backups)
        backup_buttons.addWidget(create)
        backup_buttons.addWidget(restore)
        backup_buttons.addWidget(open_folder)
        backup_buttons.addStretch(1)
        backup_layout.addLayout(backup_buttons)
        grid.addWidget(backup_card, 1, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        wrapper = QWidget()
        wrapper.setLayout(grid)
        self.add(wrapper)
        self.root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        self.vt_key.setText(self.services.settings.get("virustotal_api_key", ""))
        self.refresh_backups()
        self.refresh_drives()

    def analyze_url_clicked(self) -> None:
        url = self.url_input.text().strip()
        if not url:
            return
        result = analyze_url(url)
        color = GREEN if result.verdict == "clean" else RED if result.verdict in {"malicious", "invalid"} else YELLOW
        reason_text = "\n".join(f"  - {reason}" for reason in result.reasons) or "  - Sin indicadores offline."
        self.url_result.setStyleSheet(f"color: {TEXT};")
        self.url_result.setText(
            f"Host: {result.hostname or '—'}   Veredicto: {result.verdict.upper()}   "
            f"Riesgo: {result.score}/100\n{reason_text}"
        )
        self.url_result.setStyleSheet(f"color: {color};")
        self.services.db.add_event(
            "warning" if result.score >= 40 else "info",
            "url",
            f"Analisis URL {result.verdict}: {url}",
            {"score": result.score, "reasons": result.reasons},
        )

    def virustotal_clicked(self) -> None:
        url = self.url_input.text().strip()
        if not url:
            return
        api_key = self.vt_key.text().strip()
        if not self.vt_consent.isChecked():
            QMessageBox.warning(
                self,
                "Consentimiento requerido",
                "Debe autorizar explicitamente el envio de la URL a VirusTotal.",
            )
            return
        if not api_key:
            QMessageBox.warning(self, "VirusTotal", "Introduzca una clave de API.")
            return
        self.services.settings.set("virustotal_api_key", api_key)
        self.vt_status.setText("Consultando VirusTotal...")
        launch_task(
            self,
            check_virustotal,
            url,
            api_key,
            True,
            on_result=self._vt_result,
            on_error=lambda message: self._vt_error(message),
        )

    def _vt_result(self, result: dict) -> None:
        stats = result.get("stats", {})
        summary = ", ".join(f"{key}: {value}" for key, value in sorted(stats.items())) or "sin estadisticas aun"
        self.vt_status.setText(f"VirusTotal ({result.get('status', '')}): {summary}")
        self.vt_status.setStyleSheet(f"color: {TEXT};")
        self.services.db.add_event("info", "url", f"Consulta VirusTotal: {result.get('analysis_id', '')}", result)

    def _vt_error(self, message: str) -> None:
        self.vt_status.setText(f"VirusTotal no disponible: {message}")
        self.vt_status.setStyleSheet(f"color: {RED};")

    def choose_shred_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Archivo a destruir")
        if path:
            self.shred_path.setText(path)

    def shred_clicked(self) -> None:
        path = self.shred_path.text().strip()
        if not path:
            return
        text, ok = QInputDialog.getText(
            self,
            "Confirmacion de destruccion",
            f"Esta accion es irreversible:\n{path}\n\nEscriba DESTRUIR para continuar:",
        )
        if not ok or text.strip().upper() != "DESTRUIR":
            return
        passes = int(self.shred_passes.currentText())
        self.window.notify("Destructor seguro", f"Sobrescribiendo con {passes} pasadas...", "warning")
        launch_task(
            self,
            secure_delete,
            path,
            passes,
            on_result=lambda _result: self._shred_done(path),
            on_error=lambda message: QMessageBox.critical(self, "Destructor seguro", message),
        )

    def _shred_done(self, path: str) -> None:
        self.shred_path.clear()
        self.services.db.add_event("warning", "shredder", f"Archivo destruido: {path}")
        self.window.notify("Destructor seguro", "Archivo destruido y eliminado.", "info")

    def refresh_drives(self) -> None:
        self.drive_combo.clear()
        drives = removable_drives()
        self.drive_combo.setEnabled(bool(drives))
        if drives:
            self.drive_combo.addItems(drives)
        else:
            self.drive_combo.addItem("No hay unidades removibles")

    def scan_usb(self) -> None:
        drive = self.drive_combo.currentText()
        if not self.drive_combo.isEnabled() or not drive or drive == "No hay unidades removibles":
            return
        self.window.start_scan("custom", [drive])

    def refresh_backups(self) -> None:
        try:
            self._backups = list_backups()
        except Exception:
            log.exception("Error listando copias de seguridad")
            self._backups = []
        self.backup_list.clear()
        for entry in self._backups:
            self.backup_list.addItem(
                f"{entry['name']}  |  {format_bytes(entry['size'])}  |  "
                f"{entry['files']} archivos  |  {entry['created_at']}"
            )

    def create_backup_clicked(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Carpeta a respaldar")
        if not folder:
            return
        self.window.notify("Copias de seguridad", f"Creando copia de {folder}...", "info")
        launch_task(
            self,
            create_backup,
            folder,
            on_result=self._backup_created,
            on_error=lambda message: QMessageBox.critical(self, "Copia de seguridad", message),
        )

    def _backup_created(self, path: Path) -> None:
        self.services.db.add_event("info", "backup", f"Copia creada: {path}")
        self.window.notify("Copia creada", str(path), "info")
        self.refresh_backups()

    def restore_backup_clicked(self) -> None:
        row = self.backup_list.currentRow()
        if row < 0 or row >= len(self._backups):
            QMessageBox.information(self, "Restaurar copia", "Seleccione una copia de seguridad.")
            return
        entry = self._backups[row]
        destination = QFileDialog.getExistingDirectory(self, "Carpeta de destino para restaurar")
        if not destination:
            return
        reply = QMessageBox.question(
            self,
            "Restaurar copia",
            f"Se extraeran los archivos en:\n{destination}\n\nLos archivos existentes no se sobrescriben. "
            "¿Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        launch_task(
            self,
            restore_backup,
            entry["path"],
            destination,
            on_result=lambda count: self._backup_restored(destination, count),
            on_error=lambda message: QMessageBox.critical(self, "Restaurar copia", message),
        )

    def _backup_restored(self, destination: str, count: int) -> None:
        self.window.notify("Copia restaurada", f"{count} archivos en {destination}", "info")
        self.services.db.add_event("info", "backup", f"Copia restaurada en {destination}: {count} archivos")

    def open_backups(self) -> None:
        try:
            os.startfile(str(backups_dir()))
        except OSError as exc:
            QMessageBox.warning(self, "Copias de seguridad", str(exc))

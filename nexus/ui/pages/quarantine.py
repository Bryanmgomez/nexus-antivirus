from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...models import QuarantineEntry
from ...util import format_bytes, local_now_display
from ..theme import ACCENT_2, MUTED, RED, TEXT
from ..widgets import Badge, Card, Page, PageHeader, elide, item, make_table

log = logging.getLogger(__name__)


class QuarantinePage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._entries: dict[int, QuarantineEntry] = {}

        header = PageHeader(
            "CUARENTENA",
            "Archivos aislados con cifrado AES-256-CTR, HMAC-SHA256 y clave protegida por DPAPI.",
        )
        self.usage_badge = Badge("0 ARCHIVOS", "muted")
        self.open_button = QPushButton("Abrir almacen")
        self.open_button.setObjectName("Ghost")
        self.open_button.clicked.connect(self.open_storage)
        header.add_action(self.usage_badge)
        header.add_action(self.open_button)
        self.add(header)

        self.tabs = QTabWidget()
        self.add(self.tabs)

        active = QWidget()
        active_layout = QVBoxLayout(active)
        active_layout.setContentsMargins(14, 14, 14, 14)
        active_top = QHBoxLayout()
        title = QLabel("ARCHIVOS AISLADOS")
        title.setObjectName("SectionTitle")
        active_top.addWidget(title)
        active_top.addStretch(1)
        refresh = QPushButton("Actualizar")
        refresh.setObjectName("Ghost")
        refresh.clicked.connect(self.refresh)
        details = QPushButton("Detalles")
        details.setObjectName("Ghost")
        details.clicked.connect(self.show_details)
        restore = QPushButton("RESTAURAR")
        restore.setObjectName("Primary")
        restore.clicked.connect(self.restore_selected)
        delete = QPushButton("ELIMINAR DEFINITIVAMENTE")
        delete.setObjectName("Danger")
        delete.clicked.connect(self.delete_selected)
        for button in (refresh, details, restore, delete):
            active_top.addWidget(button)
        active_layout.addLayout(active_top)
        self.table = make_table(
            ["ID", "FECHA", "DETECCION", "RUTA ORIGINAL", "TAMANO", "SHA-256"], stretch_column=3
        )
        self.table.setMinimumHeight(380)
        self.table.itemDoubleClicked.connect(lambda _item: self.show_details())
        active_layout.addWidget(self.table)
        note = QLabel(
            "La restauracion verifica el HMAC y el SHA-256 antes de escribir. "
            "Nunca se sobrescribe un archivo existente: se usa un nombre unico."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        active_layout.addWidget(note)
        self.tabs.addTab(active, "AISLADOS")

        history = QWidget()
        history_layout = QVBoxLayout(history)
        history_layout.setContentsMargins(14, 14, 14, 14)
        history_top = QHBoxLayout()
        history_title = QLabel("HISTORIAL DE CUARENTENA")
        history_title.setObjectName("SectionTitle")
        history_top.addWidget(history_title)
        history_top.addStretch(1)
        history_refresh = QPushButton("Actualizar")
        history_refresh.setObjectName("Ghost")
        history_refresh.clicked.connect(self.refresh)
        history_top.addWidget(history_refresh)
        history_layout.addLayout(history_top)
        self.history_table = make_table(
            ["FECHA", "DETECCION", "RUTA ORIGINAL", "MOTOR", "ESTADO"], stretch_column=2
        )
        self.history_table.setMinimumHeight(380)
        history_layout.addWidget(self.history_table)
        self.tabs.addTab(history, "HISTORIAL")

        self.refresh()

    def refresh(self) -> None:
        try:
            entries = self.services.quarantine.list_entries()
            self._entries = {entry.id: entry for entry in entries}
            self.table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                self.table.setItem(row, 0, item(str(entry.id), MUTED))
                self.table.setItem(row, 1, item(local_now_display(entry.created_at), MUTED))
                self.table.setItem(row, 2, item(entry.detection_name, RED))
                self.table.setItem(row, 3, item(elide(entry.original_path, 78), TEXT, entry.original_path))
                self.table.setItem(row, 4, item(format_bytes(entry.size), MUTED))
                self.table.setItem(row, 5, item(entry.sha256[:16] + "...", MUTED, entry.sha256))
            total = sum(entry.size for entry in entries)
            self.usage_badge.set_state("ok" if entries else "muted", f"{len(entries)} ARCHIVOS / {format_bytes(total)}")
            history = self.services.db.list_quarantine_history(500)
            self.history_table.setRowCount(len(history))
            for row, entry in enumerate(history):
                self.history_table.setItem(row, 0, item(local_now_display(str(entry.get("created_at", ""))), MUTED))
                self.history_table.setItem(row, 1, item(str(entry.get("detection_name", "")), RED))
                path = str(entry.get("original_path", ""))
                self.history_table.setItem(row, 2, item(elide(path, 78), TEXT, path))
                self.history_table.setItem(row, 3, item(str(entry.get("engine", "")), ACCENT_2))
                status = str(entry.get("status", ""))
                color = {"quarantined": ACCENT_2, "restored": "#3ee6a5", "deleted": RED}.get(status, MUTED)
                self.history_table.setItem(row, 4, item(status, color))
        except Exception:
            log.exception("Error actualizando cuarentena")

    def _selected(self) -> QuarantineEntry | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        try:
            entry_id = int(self.table.item(row, 0).text())
        except (AttributeError, ValueError):
            return None
        return self._entries.get(entry_id)

    def show_details(self) -> None:
        entry = self._selected()
        if entry is None:
            return
        QMessageBox.information(
            self,
            "Entrada de cuarentena",
            f"ID: {entry.id}\n"
            f"Deteccion: {entry.detection_name}\n"
            f"Motor: {entry.engine}\n"
            f"Ruta original: {entry.original_path}\n"
            f"Tamano: {format_bytes(entry.size)}\n"
            f"SHA-256: {entry.sha256}\n"
            f"Fecha: {local_now_display(entry.created_at)}\n"
            f"Estado: {entry.status}\n\n{entry.details}",
        )

    def restore_selected(self) -> None:
        entry = self._selected()
        if entry is None:
            QMessageBox.information(self, "Cuarentena", "Seleccione un archivo aislado.")
            return
        target = Path(entry.original_path)
        warning = ""
        if target.exists():
            warning = "\n\nLa ruta original ya existe; se restaurara con un nombre unico."
        reply = QMessageBox.question(
            self,
            "Restaurar archivo",
            f"¿Restaurar?\n\n{entry.original_path}\n\nDeteccion: {entry.detection_name}{warning}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            restored = self.services.quarantine.restore(entry.id)
            self.services.db.add_event("info", "quarantine", f"Restaurado: {restored}")
            QMessageBox.information(self, "Restaurado", f"Archivo restaurado en:\n{restored}")
        except Exception as exc:
            log.exception("Error restaurando de cuarentena")
            QMessageBox.critical(self, "Error al restaurar", str(exc))
        finally:
            QGuiApplication.restoreOverrideCursor()
            self.refresh()
            self.window.refresh_dashboard()

    def delete_selected(self) -> None:
        entry = self._selected()
        if entry is None:
            QMessageBox.information(self, "Cuarentena", "Seleccione un archivo aislado.")
            return
        reply = QMessageBox.warning(
            self,
            "Eliminacion definitiva",
            f"Esta accion eliminara permanentemente el archivo cifrado y no se puede deshacer.\n\n"
            f"{entry.original_path}\n\n¿Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        text, ok = QInputDialog.getText(
            self,
            "Confirmacion requerida",
            "Escriba ELIMINAR para confirmar:",
        )
        if not ok or text.strip().upper() != "ELIMINAR":
            return
        try:
            self.services.quarantine.delete_forever(entry.id)
            self.window.notify("Cuarentena", "Entrada eliminada definitivamente.", "info")
        except Exception as exc:
            log.exception("Error eliminando de cuarentena")
            QMessageBox.critical(self, "Error", str(exc))
        self.refresh()
        self.window.refresh_dashboard()

    def open_storage(self) -> None:
        try:
            os.startfile(str(self.services.quarantine.storage_dir))
        except OSError as exc:
            QMessageBox.warning(self, "Abrir almacen", str(exc))

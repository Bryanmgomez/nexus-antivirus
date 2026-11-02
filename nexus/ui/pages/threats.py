from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...models import Detection
from ...util import local_now_display
from ..theme import ACCENT_2, MUTED, RED, TEXT, YELLOW
from ..widgets import Badge, Card, Page, PageHeader, elide, item, make_table, severity_color, verdict_color

log = logging.getLogger(__name__)


class ThreatsPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._threats: list[dict] = []
        self._visible: list[dict] = []

        header = PageHeader(
            "HISTORIAL DE AMENAZAS",
            "Registro persistente de detecciones, motores, acciones y hashes SHA-256.",
        )
        self.count_badge = Badge("0 REGISTROS", "muted")
        header.add_action(self.count_badge)
        self.add(header)

        filters = Card()
        filters_layout = QHBoxLayout(filters)
        filters_layout.setContentsMargins(16, 12, 16, 12)
        filters_layout.setSpacing(10)
        label = QLabel("FILTRAR")
        label.setObjectName("CardLabel")
        filters_layout.addWidget(label)
        self.verdict_filter = QComboBox()
        self.verdict_filter.addItems(["Todos", "Malware", "Sospechoso"])
        self.verdict_filter.currentIndexChanged.connect(self.apply_filter)
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas", "Critica", "Alta", "Media", "Baja", "Test"])
        self.severity_filter.currentIndexChanged.connect(self.apply_filter)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar ruta, nombre o SHA-256...")
        self.search.textChanged.connect(self.apply_filter)
        filters_layout.addWidget(self.verdict_filter)
        filters_layout.addWidget(self.severity_filter)
        filters_layout.addWidget(self.search, 1)
        self.add(filters)

        card = Card()
        card_layout = QHBoxLayout()
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(8)
        top = QHBoxLayout()
        title = QLabel("DETECCIONES REGISTRADAS")
        title.setObjectName("SectionTitle")
        top.addWidget(title)
        top.addStretch(1)
        refresh = QPushButton("Actualizar")
        refresh.setObjectName("Ghost")
        refresh.clicked.connect(self.refresh)
        details = QPushButton("Detalles")
        details.setObjectName("Ghost")
        details.clicked.connect(self.show_details)
        resolve = QPushButton("RESOLVER")
        quarantine.setObjectName("Primary")
        resolve.clicked.connect(self.resolve_selected)
        dismiss = QPushButton("Descartar")
        dismiss.setObjectName("Ghost")
        dismiss.clicked.connect(self.dismiss_selected)
        export = QPushButton("Exportar")
        export.setObjectName("Ghost")
        export.clicked.connect(self.export)
        resolve_all = QPushButton("RESOLVER TODAS")
        resolve_all.setObjectName("Primary")
        resolve_all.clicked.connect(self.resolve_all)
        top.addWidget(resolve_all)
        for widget in (refresh, details, quarantine, dismiss, export):
            top.addWidget(widget)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.addLayout(top)
        self.table = make_table(
            ["FECHA", "NOMBRE", "VEREDICTO", "SEVERIDAD", "MOTOR", "RUTA", "ACCION"], stretch_column=5
        )
        self.table.setMinimumHeight(420)
        self.table.itemDoubleClicked.connect(lambda _item: self.show_details())
        layout.addWidget(self.table)
        self.add(card)
        self.root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        try:
            self._threats = self.services.db.list_threats(1000)
            self.apply_filter()
        except Exception:
            log.exception("Error cargando amenazas")

    def apply_filter(self) -> None:
        verdict_map = {0: None, 1: "malware", 2: "suspicious"}
        severity_map = {
            0: None,
            1: "critical",
            2: "high",
            3: "medium",
            4: "low",
            5: "test",
        }
        verdict = verdict_map.get(self.verdict_filter.currentIndex())
        severity = severity_map.get(self.severity_filter.currentIndex())
        query = self.search.text().strip().lower()
        rows: list[dict] = []
        for threat in self._threats:
            if verdict and str(threat.get("verdict", "")).lower() != verdict:
                continue
            if severity and str(threat.get("severity", "")).lower() != severity:
                continue
            haystack = " ".join(
                str(threat.get(key, "")) for key in ("path", "name", "sha256", "engine")
            ).lower()
            if query and query not in haystack:
                continue
            rows.append(threat)
        self._visible = rows
        self.table.setRowCount(len(rows))
        for index, threat in enumerate(rows):
            self.table.setItem(index, 0, item(local_now_display(str(threat.get("discovered_at", ""))), MUTED))
            self.table.setItem(index, 1, item(str(threat.get("name", "")), TEXT))
            self.table.setItem(
                index, 2, item(str(threat.get("verdict", "")).upper(), verdict_color(str(threat.get("verdict", ""))))
            )
            self.table.setItem(
                index, 3, item(str(threat.get("severity", "")).upper(), severity_color(str(threat.get("severity", ""))))
            )
            self.table.setItem(index, 4, item(str(threat.get("engine", "")), ACCENT_2))
            path = str(threat.get("path", ""))
            self.table.setItem(index, 5, item(elide(path, 90), MUTED, path))
            action = str(threat.get("action", ""))
            self.table.setItem(index, 6, item(action, ACCENT_2 if action == "quarantined" else MUTED))
        self.count_badge.set_state("danger" if rows else "muted", f"{len(rows)} REGISTROS")

    def _selected(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._visible):
            return None
        return self._visible[row]

    def show_details(self) -> None:
        threat = self._selected()
        if not threat:
            return
        QMessageBox.information(
            self,
            "Detalle de amenaza",
            f"Nombre: {threat.get('name')}\n"
            f"Veredicto: {threat.get('verdict')}\n"
            f"Severidad: {threat.get('severity')}\n"
            f"Motor: {threat.get('engine')}\n"
            f"Fecha: {threat.get('discovered_at')}\n"
            f"Ruta: {threat.get('path')}\n"
            f"SHA-256: {threat.get('sha256') or 'no disponible'}\n"
            f"Accion: {threat.get('action')}\n\n{threat.get('details') or ''}",
        )

    def resolve_selected(self) -> None:
        threat = self._selected()
        if not threat:
            return
        path = str(threat.get("path", ""))
        action = str(threat.get("action", ""))
        if action == "quarantined":
            reply = QMessageBox.question(
                self,
                "Eliminar definitivamente",
                f"La amenaza ya esta en cuarentena.\n\n{path}\n\nEliminar definitivamente?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            try:
                entries = self.services.quarantine.list_entries()
                entry = next((e for e in entries if e.original_path == path), None)
                if entry is not None:
                    self.services.quarantine.delete_forever(entry.id)
                self.services.db.update_threat_action(int(threat["id"]), "deleted")
                self.window.notify("Amenaza resuelta", "Archivo eliminado definitivamente.", "info")
            except Exception as exc:
                log.exception("Error eliminando amenaza")
                QMessageBox.critical(self, "Resolver", str(exc))
            self.refresh()
            self.window.quarantine_page.refresh()
            self.window.refresh_dashboard()
            return
        if not Path(path).is_file():
            reply = QMessageBox.question(
                self,
                "Marcar como resuelta",
                f"El archivo ya no existe en disco.\n\n{path}\n\n�Marcar la amenaza como resuelta?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            self.services.db.update_threat_action(int(threat["id"]), "dismissed")
            self.services.db.add_event("info", "threats", f"Amenaza resuelta (archivo ausente): {threat.get('name')}", {"path": path})
            self.window.notify("Amenaza resuelta", "Marcada como resuelta.", "info")
            self.refresh()
            self.window.refresh_dashboard()
            return
        reply = QMessageBox.question(
            self,
            "Resolver amenaza",
            f"�Poner en cuarentena este archivo?\n\n{path}\n\nPodra restaurarse desde la cuarentena.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            self.services.quarantine.quarantine_file(
                path,
                str(threat.get("name", "Deteccion")),
                str(threat.get("engine", "")),
                str(threat.get("sha256", "")),
                str(threat.get("details", "")),
            )
            self.services.db.update_threat_action(int(threat["id"]), "quarantined")
            self.window.notify("Amenaza resuelta", "Archivo aislado en cuarentena.", "info")
        except Exception as exc:
            log.exception("Error resolviendo amenaza")
            QMessageBox.critical(self, "Resolver", str(exc))
        self.refresh()
        self.window.quarantine_page.refresh()
        self.window.refresh_dashboard()

    def dismiss_selected(self) -> None:
        threat = self._selected()
        if not threat:
            return
        reply = QMessageBox.question(
            self,
            "Descartar deteccion",
            "Se marcara como descartada en el historial. No se modifica ni elimina el archivo.\n\n¿Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.services.db.update_threat_action(int(threat["id"]), "dismissed")
            self.services.db.add_event(
                "info", "threats", f"Deteccion descartada: {threat.get('name')}", {"path": threat.get("path")}
            )
            self.refresh()
            self.window.refresh_dashboard()

    def resolve_all(self) -> None:
        pending = [
            threat
            for threat in self._threats
            if str(threat.get("action", "")) not in {"quarantined", "deleted", "dismissed"}
            and Path(str(threat.get("path", ""))).is_file()
        ]
        if not pending:
            QMessageBox.information(self, "Resolver amenazas", "No hay amenazas pendientes con archivo disponible.")
            return
        reply = QMessageBox.question(
            self,
            "Resolver todas las amenazas",
            f"Se pondran en cuarentena {len(pending)} archivo(s) detectado(s).\n\n¿Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.window.notify("Resolviendo amenazas", f"Procesando {len(pending)} archivo(s)...", "warning")
        from ..workers import launch_task

        launch_task(
            self,
            self._resolve_all_worker,
            pending,
            on_result=self._resolve_all_done,
            on_error=lambda message: QMessageBox.critical(self, "Resolver amenazas", message),
        )

    def _resolve_all_worker(self, pending: list[dict]) -> dict:
        resolved = 0
        failed = 0
        for threat in pending:
            path = str(threat.get("path", ""))
            try:
                self.services.quarantine.quarantine_file(
                    path,
                    str(threat.get("name", "Deteccion")),
                    str(threat.get("engine", "")),
                    str(threat.get("sha256", "")),
                    str(threat.get("details", "")),
                )
                self.services.db.update_threat_action(int(threat["id"]), "quarantined")
                resolved += 1
            except Exception as exc:
                failed += 1
                log.exception("No se pudo resolver %s: %s", path, exc)
        return {"resolved": resolved, "failed": failed, "total": len(pending)}

    def _resolve_all_done(self, result: dict) -> None:
        self.refresh()
        self.window.quarantine_page.refresh()
        self.window.refresh_dashboard()
        self.window.notify(
            "Amenazas resueltas",
            f"{result['resolved']} de {result['total']} resueltas. Fallos: {result['failed']}.",
            "info" if result["failed"] == 0 else "warning",
        )

    def export(self) -> None:
        if not self._visible:
            QMessageBox.information(self, "Exportar", "No hay registros visibles para exportar.")
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Exportar historial",
            str(Path.home() / "nexus_historial.csv"),
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".json") or "JSON" in selected:
                Path(path).write_text(
                    json.dumps(self._visible, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            else:
                with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(self._visible[0].keys()))
                    writer.writeheader()
                    writer.writerows(self._visible)
            self.window.notify("Historial exportado", path, "info")
        except OSError as exc:
            QMessageBox.critical(self, "Exportar", str(exc))

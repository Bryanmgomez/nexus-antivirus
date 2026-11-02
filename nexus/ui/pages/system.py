from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...models import Detection, SystemCheck
from ...system import (
    build_security_report,
    compare_baseline,
    create_baseline,
    extract_command_target,
    integrity_status,
    list_network_connections,
    list_processes,
    list_scheduled_tasks,
    list_services,
    list_startup_entries,
    resume_process,
    service_suspicion,
    suspend_process,
    system_checks,
)
from ..theme import ACCENT_2, GREEN, MUTED, RED, TEXT, YELLOW
from ..widgets import Badge, Card, Page, PageHeader, elide, item, make_table, severity_color
from ..workers import launch_task

log = logging.getLogger(__name__)


def _suspicion_color(value: str) -> str:
    return YELLOW if value else GREEN


def _build_report(db, settings, engine_info) -> str:
    return build_security_report(db, settings, engine_info, system_checks())


class SystemPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._processes = []
        self._startup = []
        self._tasks = []
        self._loading: set[str] = set()
        self._loaded: set[str] = set()

        header = PageHeader(
            "CENTRO DEL SISTEMA",
            "Procesos, persistencia, red, servicios y verificacion de integridad en tiempo real.",
        )
        self.load_badge = Badge("LISTO", "muted")
        header.add_action(self.load_badge)
        refresh = QPushButton("Actualizar pestana")
        refresh.setObjectName("Ghost")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        self.add(header)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._tab_changed)
        self.add(self.tabs)

        self.tabs.addTab(self._build_processes(), "PROCESOS")
        self.tabs.addTab(self._build_startup(), "INICIO")
        self.tabs.addTab(self._build_network(), "RED")
        self.tabs.addTab(self._build_services(), "SERVICIOS")
        self.tabs.addTab(self._build_tasks(), "TAREAS")
        self.tabs.addTab(self._build_security(), "INTEGRIDAD")

        self.timer = QTimer(self)
        self.timer.setInterval(12000)
        self.timer.timeout.connect(self._auto_refresh)
        self.timer.start()
        self._refresh_processes()

    @staticmethod
    def _tab_widget(layout_owner) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        layout_owner._active_layout = layout
        return widget

    def _toolbar(self, *buttons) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addStretch(1)
        for button in buttons:
            row.addWidget(button)
        return row

    def _button(self, text: str, slot, object_name: str = "Ghost") -> QPushButton:
        button = QPushButton(text)
        button.setObjectName(object_name)
        button.clicked.connect(slot)
        return button

    def _build_processes(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.process_count = QLabel("Cargando procesos...")
        self.process_count.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.process_count)
        row.addStretch(1)
        self.auto_refresh = QCheckBox("Actualizar cada 12 s")
        self.auto_refresh.setChecked(True)
        row.addWidget(self.auto_refresh)
        row.addWidget(self._button("Detalles", self.process_details))
        row.addWidget(self._button("Suspender", self.suspend_selected))
        row.addWidget(self._button("Reanudar", self.resume_selected))
        row.addWidget(self._button("Analizar ejecutable", self.analyze_process, "Primary"))
        layout.addLayout(row)
        self.process_table = make_table(
            ["PID", "PROCESO", "USUARIO", "CPU", "RAM", "CONEX.", "ESTADO", "RUTA", "INDICADOR"],
            stretch_column=7,
        )
        self.process_table.itemDoubleClicked.connect(lambda _item: self.process_details())
        layout.addWidget(self.process_table)
        note = QLabel(
            "Suspender un proceso puede congelar aplicaciones o el sistema. Uselo solo tras identificar "
            "actividad sospechosa. Reanudar restaura la ejecucion."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        return widget

    def _build_startup(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.startup_count = QLabel()
        self.startup_count.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.startup_count)
        row.addStretch(1)
        row.addWidget(self._button("Detalles", self.startup_details))
        row.addWidget(self._button("Analizar destino", self.analyze_startup, "Primary"))
        layout.addLayout(row)
        self.startup_table = make_table(
            ["ORIGEN", "NOMBRE", "COMANDO", "UBICACION", "USUARIO", "INDICADOR"], stretch_column=2
        )
        layout.addWidget(self.startup_table)
        note = QLabel(
            "Entradas de inicio del usuario y del sistema. NEXUS solo muestra y analiza; no desactiva "
            "automaticamente elementos de inicio."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        return widget

    def _build_network(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.network_count = QLabel()
        self.network_count.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.network_count)
        row.addStretch(1)
        row.addWidget(self._button("Detalles", self.network_details))
        layout.addLayout(row)
        self.network_table = make_table(
            ["PID", "PROCESO", "LOCAL", "REMOTA", "ESTADO", "FAMILIA", "INDICADOR"], stretch_column=3
        )
        self.network_table.itemDoubleClicked.connect(lambda _item: self.network_details())
        layout.addWidget(self.network_table)
        return widget

    def _build_services(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.service_count = QLabel()
        self.service_count.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.service_count)
        row.addStretch(1)
        row.addWidget(self._button("Detalles", self.service_details))
        layout.addLayout(row)
        self.service_table = make_table(
            ["SERVICIO", "NOMBRE VISIBLE", "ESTADO", "INICIO", "BINARIO", "INDICADOR"], stretch_column=4
        )
        self.service_table.itemDoubleClicked.connect(lambda _item: self.service_details())
        layout.addWidget(self.service_table)
        return widget

    def _build_tasks(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.task_count = QLabel()
        self.task_count.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.task_count)
        row.addStretch(1)
        row.addWidget(self._button("Detalles", self.task_details))
        row.addWidget(self._button("Analizar destino", self.analyze_task, "Primary"))
        layout.addLayout(row)
        self.task_table = make_table(
            ["TAREA", "RUTA", "ESTADO", "ACCION", "DISPARADOR", "INDICADOR"], stretch_column=3
        )
        self.task_table.itemDoubleClicked.connect(lambda _item: self.task_details())
        layout.addWidget(self.task_table)
        return widget

    def _build_security(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        self.security_summary = QLabel()
        self.security_summary.setObjectName("Muted")
        row = QHBoxLayout()
        row.addWidget(self.security_summary)
        row.addStretch(1)
        row.addWidget(self._button("Crear linea base", self.create_baseline_clicked))
        row.addWidget(self._button("Comparar", self.compare_clicked))
        row.addWidget(self._button("Generar informe", self.report_clicked, "Primary"))
        layout.addLayout(row)
        self.security_table = make_table(["CONTROL", "ESTADO", "SEVERIDAD", "DETALLE"], stretch_column=3)
        layout.addWidget(self.security_table)
        note = QLabel(
            "La linea base registra hashes de archivos criticos, inicio y servicios. Comparar no modifica "
            "nada: solo informa diferencias. El informe HTML se guarda en la ubicacion elegida."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        return widget

    def refresh(self) -> None:
        index = self.tabs.currentIndex()
        {
            0: self._refresh_processes,
            1: self._refresh_startup,
            2: self._refresh_network,
            3: self._refresh_services,
            4: self._refresh_tasks,
            5: self._refresh_security,
        }.get(index, self._refresh_processes)()

    def _tab_changed(self, index: int) -> None:
        key = ("processes", "startup", "network", "services", "tasks", "security")[index]
        if key not in self._loaded:
            self.refresh()

    def _auto_refresh(self) -> None:
        if (
            self.auto_refresh.isChecked()
            and self.isVisible()
            and self.tabs.currentIndex() == 0
            and "processes" not in self._loading
        ):
            self._refresh_processes()

    def _load(self, key: str, fn, populate) -> None:
        if key in self._loading:
            return
        self._loading.add(key)
        self.load_badge.set_state("warning", "CARGANDO")
        launch_task(
            self,
            fn,
            on_result=lambda data, k=key, p=populate: self._finish(k, p, data),
            on_error=lambda message, k=key: self._failed(k, message),
        )

    def _finish(self, key: str, populate, data) -> None:
        self._loading.discard(key)
        self._loaded.add(key)
        self.load_badge.set_state("ok", "LISTO")
        try:
            populate(data)
        except Exception:
            log.exception("Error mostrando datos del sistema")
            self.window.notify("Sistema", "No se pudieron mostrar los datos.", "error")

    def _failed(self, key: str, message: str) -> None:
        self._loading.discard(key)
        self.load_badge.set_state("danger", "ERROR")
        log.error("Consulta del sistema fallida (%s): %s", key, message)
        self.window.notify("Sistema", f"No se pudo consultar {key}: {message}", "error")

    def _refresh_processes(self) -> None:
        self._load("processes", list_processes, self._populate_processes)

    def _refresh_startup(self) -> None:
        self._load("startup", list_startup_entries, self._populate_startup)

    def _refresh_network(self) -> None:
        self._load("network", list_network_connections, self._populate_network)

    def _refresh_services(self) -> None:
        self._load("services", list_services, self._populate_services)

    def _refresh_tasks(self) -> None:
        self._load("tasks", list_scheduled_tasks, self._populate_tasks)

    def _refresh_security(self) -> None:
        self._load("security", integrity_status, self._populate_security)

    def _populate_processes(self, processes) -> None:
        self._processes = processes
        self.process_table.setRowCount(len(processes))
        suspicious = 0
        for row, process in enumerate(processes):
            suspicious += bool(process.suspicion)
            self.process_table.setItem(row, 0, item(str(process.pid), MUTED))
            self.process_table.setItem(row, 1, item(process.name, TEXT))
            self.process_table.setItem(row, 2, item(process.username, MUTED))
            self.process_table.setItem(row, 3, item(f"{process.cpu_percent:.1f} %", ACCENT_2))
            self.process_table.setItem(row, 4, item(f"{process.memory_mb:.1f} MB", MUTED))
            self.process_table.setItem(row, 5, item(str(process.connections), MUTED))
            self.process_table.setItem(row, 6, item(process.status, MUTED))
            self.process_table.setItem(row, 7, item(elide(process.exe or process.cmdline, 85), MUTED, process.exe))
            self.process_table.setItem(row, 8, item(process.suspicion or "Normal", _suspicion_color(process.suspicion)))
        self.process_count.setText(
            f"{len(processes)} procesos / {suspicious} con indicadores heuristicos"
        )
        if suspicious:
            self.load_badge.set_state("warning", f"{suspicious} INDICADORES")

    def _selected_process(self):
        row = self.process_table.currentRow()
        if 0 <= row < len(self._processes):
            return self._processes[row]
        return None

    def process_details(self) -> None:
        process = self._selected_process()
        if not process:
            return
        QMessageBox.information(
            self,
            f"Proceso {process.pid}",
            f"Nombre: {process.name}\n"
            f"PID: {process.pid}\n"
            f"Usuario: {process.username}\n"
            f"Estado: {process.status}\n"
            f"CPU: {process.cpu_percent:.2f}%\n"
            f"RAM: {process.memory_mb:.1f} MB\n"
            f"Conexiones: {process.connections}\n"
            f"Ejecutable: {process.exe}\n"
            f"Linea de comandos: {process.cmdline}\n\n"
            f"Indicador: {process.suspicion or 'Sin indicadores heuristicos'}",
        )

    def suspend_selected(self) -> None:
        process = self._selected_process()
        if not process:
            return
        reply = QMessageBox.warning(
            self,
            "Suspender proceso",
            f"¿Suspender {process.name} (PID {process.pid})?\n\n"
            "El proceso quedara congelado. Si es una aplicacion critica, el sistema podria dejar de responder.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        ok, message = suspend_process(process.pid)
        self.window.notify("Procesos", message, "info" if ok else "error")
        if ok:
            self._refresh_processes()

    def resume_selected(self) -> None:
        process = self._selected_process()
        if not process:
            return
        ok, message = resume_process(process.pid)
        self.window.notify("Procesos", message, "info" if ok else "error")
        if ok:
            self._refresh_processes()

    def analyze_process(self) -> None:
        process = self._selected_process()
        if not process:
            return
        if not process.exe or not Path(process.exe).is_file():
            QMessageBox.warning(self, "Analizar", "El proceso no expone un ejecutable accesible.")
            return
        self._analyze_file(process.exe, f"proceso {process.name}")

    def _populate_startup(self, entries) -> None:
        self._startup = entries
        self.startup_table.setRowCount(len(entries))
        suspicious = 0
        for row, entry in enumerate(entries):
            suspicious += bool(entry.suspicion)
            self.startup_table.setItem(row, 0, item(entry.source, ACCENT_2))
            self.startup_table.setItem(row, 1, item(entry.name, TEXT))
            self.startup_table.setItem(row, 2, item(elide(entry.command, 95), MUTED, entry.command))
            self.startup_table.setItem(row, 3, item(elide(entry.location, 65), MUTED, entry.location))
            self.startup_table.setItem(row, 4, item(entry.user or "—", MUTED))
            self.startup_table.setItem(row, 5, item(entry.suspicion or "Normal", _suspicion_color(entry.suspicion)))
        self.startup_count.setText(f"{len(entries)} entradas / {suspicious} con indicadores")

    def _selected_startup(self):
        row = self.startup_table.currentRow()
        if 0 <= row < len(self._startup):
            return self._startup[row]
        return None

    def startup_details(self) -> None:
        entry = self._selected_startup()
        if not entry:
            return
        QMessageBox.information(
            self,
            "Entrada de inicio",
            f"Origen: {entry.source}\nNombre: {entry.name}\nComando: {entry.command}\n"
            f"Ubicacion: {entry.location}\nUsuario: {entry.user or '—'}\n\n"
            f"Indicador: {entry.suspicion or 'Sin indicadores heuristicos'}",
        )

    def analyze_startup(self) -> None:
        entry = self._selected_startup()
        if not entry:
            return
        target = extract_command_target(entry.command)
        if not target:
            QMessageBox.warning(self, "Analizar destino", "No se encontro un ejecutable local en el comando.")
            return
        self._analyze_file(target, f"inicio {entry.name}")

    def _populate_network(self, connections) -> None:
        self.network_table.setRowCount(len(connections))
        suspicious = 0
        for row, connection in enumerate(connections):
            suspicious += bool(connection.suspicion)
            self.network_table.setItem(row, 0, item(str(connection.pid), MUTED))
            self.network_table.setItem(row, 1, item(connection.process, TEXT))
            self.network_table.setItem(row, 2, item(connection.local, MUTED))
            self.network_table.setItem(row, 3, item(connection.remote, ACCENT_2))
            self.network_table.setItem(row, 4, item(connection.status, MUTED))
            self.network_table.setItem(row, 5, item(connection.family, MUTED))
            self.network_table.setItem(row, 6, item(connection.suspicion or "Normal", _suspicion_color(connection.suspicion)))
        self.network_count.setText(f"{len(connections)} conexiones / {suspicious} con indicadores")

    def network_details(self) -> None:
        row = self.network_table.currentRow()
        if row < 0:
            return
        values = [self.network_table.item(row, col).text() for col in range(7)]
        QMessageBox.information(
            self,
            "Conexion de red",
            f"PID: {values[0]}\nProceso: {values[1]}\nLocal: {values[2]}\nRemota: {values[3]}\n"
            f"Estado: {values[4]}\nFamilia: {values[5]}\nIndicador: {values[6]}",
        )

    def _populate_services(self, services) -> None:
        self.service_table.setRowCount(len(services))
        suspicious = 0
        for row, service in enumerate(services):
            indicator = service_suspicion(service.binary_path)
            suspicious += bool(indicator)
            self.service_table.setItem(row, 0, item(service.name, TEXT))
            self.service_table.setItem(row, 1, item(service.display_name, MUTED))
            color = GREEN if service.status.lower() == "running" else MUTED
            self.service_table.setItem(row, 2, item(service.status, color))
            self.service_table.setItem(row, 3, item(service.start_type, MUTED))
            self.service_table.setItem(row, 4, item(elide(service.binary_path, 90), MUTED, service.binary_path))
            self.service_table.setItem(row, 5, item(indicator or "Normal", _suspicion_color(indicator)))
        self.service_count.setText(f"{len(services)} servicios / {suspicious} con indicadores")

    def service_details(self) -> None:
        row = self.service_table.currentRow()
        if row < 0:
            return
        values = [self.service_table.item(row, col).text() for col in range(6)]
        QMessageBox.information(
            self,
            "Servicio de Windows",
            f"Servicio: {values[0]}\nNombre visible: {values[1]}\nEstado: {values[2]}\n"
            f"Inicio: {values[3]}\nBinario: {values[4]}\nIndicador: {values[5]}",
        )

    def _populate_tasks(self, tasks) -> None:
        self._tasks = tasks
        self.task_table.setRowCount(len(tasks))
        suspicious = 0
        for row, task in enumerate(tasks):
            suspicious += bool(task.suspicion)
            self.task_table.setItem(row, 0, item(task.name, TEXT))
            self.task_table.setItem(row, 1, item(elide(task.path, 70), MUTED, task.path))
            self.task_table.setItem(row, 2, item(task.state, MUTED))
            self.task_table.setItem(row, 3, item(elide(task.action, 90), MUTED, task.action))
            self.task_table.setItem(row, 4, item(task.trigger, MUTED))
            self.task_table.setItem(row, 5, item(task.suspicion or "Normal", _suspicion_color(task.suspicion)))
        self.task_count.setText(f"{len(tasks)} tareas / {suspicious} con indicadores")

    def _selected_task(self):
        row = self.task_table.currentRow()
        if 0 <= row < len(self._tasks):
            return self._tasks[row]
        return None

    def task_details(self) -> None:
        task = self._selected_task()
        if not task:
            return
        QMessageBox.information(
            self,
            "Tarea programada",
            f"Tarea: {task.name}\nRuta: {task.path}\nEstado: {task.state}\n"
            f"Accion: {task.action}\nDisparador: {task.trigger}\n\n"
            f"Indicador: {task.suspicion or 'Sin indicadores heuristicos'}",
        )

    def analyze_task(self) -> None:
        task = self._selected_task()
        if not task:
            return
        target = extract_command_target(task.action)
        if not target:
            QMessageBox.warning(self, "Analizar destino", "No se encontro un ejecutable local en la tarea.")
            return
        self._analyze_file(target, f"tarea {task.name}")

    def _analyze_file(self, path: str, source: str) -> None:
        self.window.notify("Analisis", f"Analizando {source}...", "info")
        launch_task(
            self,
            self.services.scanner.scan_single_file,
            path,
            on_result=lambda detections: self._analysis_result(path, source, detections),
            on_error=lambda message: self.window.notify("Analisis", f"Error: {message}", "error"),
        )

    def _analysis_result(self, path: str, source: str, detections: list[Detection]) -> None:
        if not detections:
            QMessageBox.information(
                self, "Analisis completado", f"Sin detecciones para:\n{path}\n\nOrigen: {source}"
            )
            return
        threat_ids: list[int] = []
        lines: list[str] = []
        for detection in detections:
            threat_ids.append(self.services.db.add_threat(detection))
            lines.append(
                f"- {detection.name} [{detection.verdict}/{detection.severity}] "
                f"({detection.engine})"
            )
        self.window.refresh_dashboard()
        reply = QMessageBox.warning(
            self,
            "Detecciones encontradas",
            f"Archivo: {path}\nOrigen: {source}\n\n" + "\n".join(lines) + "\n\n¿Poner el archivo en cuarentena?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            detection = detections[0]
            self.services.quarantine.quarantine_file(
                path,
                detection.name,
                detection.engine,
                detection.sha256,
                detection.details,
            )
            for threat_id in threat_ids:
                self.services.db.update_threat_action(threat_id, "quarantined")
            self.window.notify("Cuarentena", "Archivo aislado correctamente.", "info")
            self.window.quarantine_page.refresh()
            self.window.refresh_dashboard()
        except Exception as exc:
            log.exception("Error poniendo archivo en cuarentena")
            QMessageBox.critical(self, "Cuarentena", str(exc))

    def _populate_security(self, checks) -> None:
        self.security_table.setRowCount(len(checks))
        bad = 0
        for row, check in enumerate(checks):
            bad += check.status.lower() in {"warning", "fail", "error", "unknown"}
            self.security_table.setItem(row, 0, item(check.title, TEXT))
            color = {
                "ok": GREEN,
                "warning": YELLOW,
                "fail": RED,
                "error": RED,
                "unknown": MUTED,
            }.get(check.status.lower(), MUTED)
            self.security_table.setItem(row, 1, item(check.status.upper(), color))
            self.security_table.setItem(row, 2, item(check.severity.upper(), severity_color(check.severity)))
            self.security_table.setItem(row, 3, item(check.detail, MUTED))
        self.security_summary.setText(f"{len(checks)} controles / {bad} requieren atencion")

    def create_baseline_clicked(self) -> None:
        reply = QMessageBox.question(
            self,
            "Crear linea base",
            "Se guardara el estado actual de archivos criticos, inicio y servicios.\n\n¿Continuar?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        launch_task(
            self,
            create_baseline,
            on_result=lambda path: self._baseline_created(path),
            on_error=lambda message: QMessageBox.critical(self, "Linea base", message),
        )

    def _baseline_created(self, path) -> None:
        self.window.notify("Linea base", f"Creada en {path}", "info")
        self._refresh_security()

    def compare_clicked(self) -> None:
        launch_task(
            self,
            compare_baseline,
            on_result=self._compare_result,
            on_error=lambda message: QMessageBox.critical(self, "Integridad", message),
        )

    def _compare_result(self, diff) -> None:
        rows = list(diff.checks)
        for label, values in (
            ("Archivo modificado", diff.changed_files),
            ("Inicio anadido", diff.added_startup),
            ("Inicio eliminado", diff.removed_startup),
            ("Servicio cambiado", diff.changed_services),
        ):
            for value in values:
                rows.append(
                    SystemCheck(
                        key=label,
                        title=label,
                        status="warning",
                        detail=str(value),
                        severity="medium",
                    )
                )
        if not rows:
            QMessageBox.information(self, "Integridad", "No se detectaron diferencias respecto a la linea base.")
            return
        self.security_table.setRowCount(len(rows))
        for row, check in enumerate(rows):
            self.security_table.setItem(row, 0, item(check.title, TEXT))
            color = GREEN if check.status == "ok" else YELLOW if check.status == "warning" else RED
            self.security_table.setItem(row, 1, item(check.status.upper(), color))
            self.security_table.setItem(row, 2, item(check.severity.upper(), severity_color(check.severity)))
            self.security_table.setItem(row, 3, item(check.detail, MUTED))
        self.security_summary.setText("Comparacion de integridad completada")
        self.window.notify("Integridad", "Comparacion completada.", "info")

    def report_clicked(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar informe de seguridad",
            str(Path.home() / "NEXUS_informe_seguridad.html"),
            "HTML (*.html)",
        )
        if not path:
            return
        launch_task(
            self,
            _build_report,
            self.services.db,
            self.services.settings,
            self.services.engine_info(),
            on_result=lambda html: self._report_ready(path, html),
            on_error=lambda message: QMessageBox.critical(self, "Informe", message),
        )

    def _report_ready(self, path: str, html: str) -> None:
        try:
            Path(path).write_text(html, encoding="utf-8")
            self.window.notify("Informe generado", path, "info")
            os.startfile(path)
        except OSError as exc:
            QMessageBox.critical(self, "Informe", str(exc))

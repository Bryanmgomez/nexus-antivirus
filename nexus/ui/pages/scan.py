from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...models import Detection, ScanOptions, ScanProgress, ScanSummary
from ...usb import removable_drives
from ...util import format_duration, local_now_display
from ..theme import ACCENT_2, MUTED, RED, TEXT, YELLOW
from ..widgets import (
    Badge,
    Card,
    Page,
    PageHeader,
    Switch,
    elide,
    item,
    make_table,
    severity_color,
    verdict_color,
)
from ..workers import ScanWorker, launch_task

log = logging.getLogger(__name__)


class ScanPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._memory_thread = None
        self._running = False
        self._row_detections: dict[int, Detection] = {}
        self._seen_rows: set[tuple[str, str, str]] = set()

        header = PageHeader(
            "MOTOR DE ANALISIS",
            "Analisis de archivos, memoria, persistencia y unidades externas con motores reales.",
        )
        self.cancel_button = QPushButton("CANCELAR")
        self.cancel_button.setObjectName("Danger")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        header.add_action(self.cancel_button)
        self.add(header)

        tiles_card = Card()
        tiles_layout = QGridLayout(tiles_card)
        tiles_layout.setContentsMargins(16, 16, 16, 16)
        tiles_layout.setSpacing(10)
        scan_types = [
            ("RAPIDO", "Descargas, escritorio, documentos, inicio y tareas.", "quick"),
            ("COMPLETO", "Todas las unidades fijas accesibles.", "full"),
            ("PERSONALIZADO", "Rutas y archivos seleccionados manualmente.", "custom"),
            ("PROFUNDO", "Sistema completo mas persistencia e integridad.", "deep"),
            ("MEMORIA", "Procesos activos e imagenes en ejecucion.", "memory"),
            ("USB", "Unidad removible conectada.", "usb"),
        ]
        for index, (title, description, scan_type) in enumerate(scan_types):
            button = QPushButton(f"{title}\n{description}")
            button.setObjectName("ScanTile")
            button.setMinimumHeight(84)
            button.clicked.connect(lambda checked=False, kind=scan_type: self.start_scan(kind))
            tiles_layout.addWidget(button, index // 3, index % 3)
        self.add(tiles_card)

        custom_card = Card()
        custom_layout = QVBoxLayout(custom_card)
        custom_layout.setContentsMargins(18, 14, 18, 14)
        title = QLabel("RUTAS DEL ANALISIS PERSONALIZADO")
        title.setObjectName("SectionTitle")
        custom_layout.addWidget(title)
        self.roots_list = QListWidget()
        self.roots_list.setMaximumHeight(92)
        custom_layout.addWidget(self.roots_list)
        buttons = QHBoxLayout()
        add_folder = QPushButton("Anadir carpeta")
        add_folder.setObjectName("Ghost")
        add_folder.clicked.connect(self.add_folder)
        add_file = QPushButton("Anadir archivo")
        add_file.setObjectName("Ghost")
        add_file.clicked.connect(self.add_file)
        remove = QPushButton("Quitar")
        remove.setObjectName("Ghost")
        remove.clicked.connect(self.remove_root)
        buttons.addWidget(add_folder)
        buttons.addWidget(add_file)
        buttons.addWidget(remove)
        buttons.addStretch(1)
        custom_layout.addLayout(buttons)
        self.add(custom_card)

        options_card = Card()
        options_layout = QHBoxLayout(options_card)
        options_layout.setContentsMargins(18, 13, 18, 13)
        options_layout.setSpacing(16)
        self.auto_quarantine = Switch()
        self.auto_quarantine.setChecked(self.services.settings.get_bool("auto_quarantine", False))
        options_layout.addWidget(self.auto_quarantine)
        auto_text = QVBoxLayout()
        auto_title = QLabel("CUARENTENA AUTOMATICA DE MALWARE CONFIRMADO")
        auto_title.setObjectName("CardLabel")
        auto_hint = QLabel("Solo se mueven detecciones de firmas, YARA o ClamAV. Las sospechas heuristicas requieren revision.")
        auto_hint.setObjectName("Muted")
        auto_hint.setWordWrap(True)
        auto_text.addWidget(auto_title)
        auto_text.addWidget(auto_hint)
        options_layout.addLayout(auto_text, 1)
        self.clamav_check = QCheckBox("Usar ClamAV")
        self.clamav_check.setChecked(
            self.services.settings.get_bool("clamav_enabled", True) and self.services.clamav.available
        )
        self.clamav_check.setEnabled(self.services.clamav.available)
        if not self.services.clamav.available:
            self.clamav_check.setToolTip("ClamAV no esta instalado o no se encontro. Es opcional.")
        self.yara_check = QCheckBox("Usar YARA")
        self.yara_check.setChecked(self.services.yara.ready)
        self.yara_check.setEnabled(self.services.yara.ready)
        options_layout.addWidget(self.clamav_check)
        options_layout.addWidget(self.yara_check)
        self.auto_quarantine.toggled.connect(
            lambda checked: self.services.settings.set_bool("auto_quarantine", checked)
        )
        self.add(options_card)

        progress_card = Card(accent=True)
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(18, 15, 18, 15)
        progress_top = QHBoxLayout()
        self.phase_badge = Badge("LISTO", "muted")
        self.status_label = QLabel("Seleccione un tipo de analisis.")
        self.status_label.setObjectName("SectionTitle")
        progress_top.addWidget(self.phase_badge)
        progress_top.addWidget(self.status_label)
        progress_top.addStretch(1)
        self.elapsed_label = QLabel("00:00")
        self.elapsed_label.setObjectName("Muted")
        progress_top.addWidget(self.elapsed_label)
        progress_layout.addLayout(progress_top)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        progress_layout.addWidget(self.progress)
        stats_row = QHBoxLayout()
        self.files_label = QLabel("Archivos: 0")
        self.threats_label = QLabel("Detecciones: 0")
        self.current_label = QLabel("")
        self.current_label.setObjectName("Muted")
        for label in (self.files_label, self.threats_label):
            label.setObjectName("Muted")
            stats_row.addWidget(label)
        stats_row.addSpacing(20)
        stats_row.addWidget(self.current_label, 1)
        progress_layout.addLayout(stats_row)
        self.add(progress_card)

        results_card = Card()
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(18, 14, 18, 14)
        results_top = QHBoxLayout()
        results_title = QLabel("RESULTADOS")
        results_title.setObjectName("SectionTitle")
        self.results_badge = Badge("0 HALLAZGOS", "muted")
        results_top.addWidget(results_title)
        results_top.addWidget(self.results_badge)
        results_top.addStretch(1)
        self.quarantine_button = QPushButton("PONER EN CUARENTENA")
        self.quarantine_button.setObjectName("Primary")
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self.quarantine_selected)
        details_button = QPushButton("Ver detalles")
        details_button.setObjectName("Ghost")
        details_button.clicked.connect(self.show_details)
        results_top.addWidget(details_button)
        results_top.addWidget(self.quarantine_button)
        results_layout.addLayout(results_top)
        self.results_table = make_table(
            ["SEVERIDAD", "VEREDICTO", "NOMBRE", "RUTA", "MOTOR", "ACCION"], stretch_column=3
        )
        self.results_table.setMinimumHeight(240)
        self.results_table.itemSelectionChanged.connect(self._selection_changed)
        self.results_table.itemDoubleClicked.connect(lambda _item: self.show_details())
        results_layout.addWidget(self.results_table)
        self.add(results_card)
        self.root.addStretch(1)

        self._load_saved_options()

    def _load_saved_options(self) -> None:
        if not self.services.clamav.available:
            self.clamav_check.setChecked(False)

    def add_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta para analizar")
        if folder:
            self._add_root(folder)

    def add_file(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Seleccionar archivos para analizar")
        for path in files:
            self._add_root(path)

    def _add_root(self, path: str) -> None:
        existing = {self.roots_list.item(index).text() for index in range(self.roots_list.count())}
        if path not in existing:
            self.roots_list.addItem(path)
        self.window.show_page("scan")

    def remove_root(self) -> None:
        row = self.roots_list.currentRow()
        if row >= 0:
            self.roots_list.takeItem(row)

    def start_scan(self, scan_type: str, roots: list[str] | None = None) -> None:
        if self._running:
            self.window.notify("Analisis en curso", "Espere o cancele el analisis actual.", "warning")
            return
        if roots is None:
            roots = [self.roots_list.item(i).text() for i in range(self.roots_list.count())]
        if scan_type == "custom" and not roots:
            self.add_folder()
            roots = [self.roots_list.item(i).text() for i in range(self.roots_list.count())]
            if not roots:
                return
        if scan_type == "usb":
            drives = removable_drives()
            if not drives:
                QMessageBox.information(self, "Sin unidades", "No se detectaron unidades removibles conectadas.")
                return
            drive, ok = QInputDialog.getItem(self, "Analizar USB", "Unidad removible:", drives, 0, False)
            if not ok or not drive:
                return
            roots = [drive]
        if scan_type == "deep":
            reply = QMessageBox.question(
                self,
                "Analisis profundo",
                "El analisis profundo recorre todas las unidades accesibles y audita persistencia e integridad. "
                "Puede tardar bastante. ¿Continuar?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
        self._reset_results()
        self.window.show_page("scan")
        if scan_type == "memory":
            self._start_memory_scan()
            return
        options = ScanOptions(
            scan_type=scan_type,
            roots=roots,
            auto_quarantine=self.auto_quarantine.isChecked(),
            use_clamav=self.clamav_check.isChecked(),
            use_yara=self.yara_check.isChecked(),
            use_heuristics=self.services.settings.get_bool("heuristics_enabled", True),
            max_file_size=self.services.settings.max_file_size,
        )
        self._set_running(True)
        self.phase_badge.set_state("warning", "INICIANDO")
        self.status_label.setText("Preparando analisis...")
        self.progress.setValue(0)
        thread = QThread(self)
        worker = ScanWorker(self.services.scanner, options)
        worker.moveToThread(thread)
        self._thread, self._worker = thread, worker
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.detection.connect(self._on_detection)
        worker.result.connect(self._on_result)
        worker.error.connect(self._on_error)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._thread_finished)
        thread.start()

    def _start_memory_scan(self) -> None:
        self._set_running(True)
        self.phase_badge.set_state("warning", "MEMORIA")
        self.status_label.setText("Analizando procesos activos...")
        self.progress.setRange(0, 0)
        self._memory_thread, _task = launch_task(
            self,
            self.services.scan_memory,
            on_result=self._memory_result,
            on_error=self._memory_error,
            on_progress=self._memory_progress,
            with_progress=True,
        )

    def _memory_progress(self, payload) -> None:
        try:
            scanned, total, name = payload
        except (TypeError, ValueError):
            return
        self.files_label.setText(f"Procesos: {scanned}/{total}")
        self.current_label.setText(elide(str(name), 100))

    def _memory_result(self, summary: ScanSummary) -> None:
        self._set_running(False)
        self.progress.setRange(0, 1000)
        self.progress.setValue(1000)
        for detection in summary.detections:
            self._add_detection_row(detection)
        self._after_scan(summary)

    def _memory_error(self, message: str) -> None:
        self._set_running(False)
        self.progress.setRange(0, 1000)
        self._on_error(message)

    def _thread_finished(self) -> None:
        self._thread = None
        self._worker = None
        self._set_running(False)

    def _set_running(self, running: bool) -> None:
        self._running = running
        self.cancel_button.setEnabled(running)
        if not running:
            self.progress.setRange(0, 1000)

    def cancel_scan(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status_label.setText("Cancelando...")
            self.cancel_button.setEnabled(False)

    def _on_progress(self, progress: ScanProgress) -> None:
        self.progress.setValue(int(progress.percent * 10))
        phase_labels = {
            "enumerating": "ENUMERANDO",
            "ready": "PREPARADO",
            "clamav": "CLAMAV",
            "scanning": "ANALIZANDO",
            "deep_audit": "AUDITORIA",
            "finished": "FINALIZADO",
        }
        self.phase_badge.set_state("warning" if progress.phase != "finished" else "ok", phase_labels.get(progress.phase, progress.phase.upper()))
        if progress.message:
            self.status_label.setText(progress.message)
        if progress.total_files:
            self.files_label.setText(
                f"Archivos: {progress.files_scanned:,}/{progress.total_files:,}".replace(",", ".")
            )
        self.threats_label.setText(f"Detecciones: {progress.threats_found}")
        self.elapsed_label.setText(format_duration(progress.elapsed_seconds))
        if progress.current_path:
            self.current_label.setText(elide(progress.current_path, 120))
            self.current_label.setToolTip(progress.current_path)

    def _on_detection(self, detection: Detection) -> None:
        self._add_detection_row(detection)
        self.threats_label.setText(f"Detecciones: {self.results_table.rowCount()}")
        self.window.refresh_dashboard()
        self.window.quarantine_page.refresh()

    def _add_detection_row(self, detection: Detection) -> None:
        key = (detection.path, detection.engine, detection.name)
        if key in self._seen_rows:
            return
        self._seen_rows.add(key)
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, item(detection.severity.upper(), severity_color(detection.severity)))
        self.results_table.setItem(row, 1, item(detection.verdict.upper(), verdict_color(detection.verdict)))
        self.results_table.setItem(row, 2, item(detection.name, TEXT))
        self.results_table.setItem(row, 3, item(elide(detection.path, 90), MUTED, detection.path))
        self.results_table.setItem(row, 4, item(detection.engine, ACCENT_2))
        self.results_table.setItem(row, 5, item(detection.action, MUTED))
        self._row_detections[row] = detection
        count = self.results_table.rowCount()
        self.results_badge.set_state("danger" if count else "muted", f"{count} HALLAZGOS")
        self.quarantine_button.setEnabled(bool(self._selected_detection()))

    def _on_result(self, summary: ScanSummary) -> None:
        self.progress.setValue(1000)
        self._after_scan(summary)

    def _after_scan(self, summary: ScanSummary) -> None:
        self.files_label.setText(f"Archivos: {summary.files_scanned:,}".replace(",", "."))
        self.threats_label.setText(f"Detecciones: {summary.threats_found}")
        status = "cancelado" if summary.cancelled else "completado"
        self.phase_badge.set_state("ok" if not summary.cancelled else "warning", status.upper())
        self.status_label.setText(
            f"Analisis {status}: {summary.files_scanned} archivos, {summary.threats_found} detecciones, "
            f"{summary.errors} errores."
        )
        self.window.refresh_dashboard()
        self.window.quarantine_page.refresh()
        if summary.threats_found:
            self.window.notify(
                "Analisis completado",
                f"{summary.threats_found} hallazgo(s) requieren revision.",
                "warning",
            )
        self.window.refresh_tray_state()

    def _on_error(self, message: str) -> None:
        self.phase_badge.set_state("danger", "ERROR")
        self.status_label.setText("El analisis fallo. Revise el registro.")
        log.error("Error de analisis: %s", message)
        QMessageBox.critical(self, "Error de analisis", message)
        self._set_running(False)

    def _reset_results(self) -> None:
        self.results_table.setRowCount(0)
        self._row_detections.clear()
        self._seen_rows.clear()
        self.results_badge.set_state("muted", "0 HALLAZGOS")
        self.quarantine_button.setEnabled(False)
        self.files_label.setText("Archivos: 0")
        self.threats_label.setText("Detecciones: 0")
        self.elapsed_label.setText("00:00")
        self.current_label.clear()

    def _selected_detection(self) -> Detection | None:
        row = self.results_table.currentRow()
        return self._row_detections.get(row)

    def _selection_changed(self) -> None:
        detection = self._selected_detection()
        self.quarantine_button.setEnabled(
            bool(detection and Path(detection.path).is_file() and detection.action != "quarantined")
        )

    def show_details(self) -> None:
        detection = self._selected_detection()
        if detection is None:
            return
        QMessageBox.information(
            self,
            "Detalle de deteccion",
            f"Nombre: {detection.name}\n"
            f"Veredicto: {detection.verdict}\n"
            f"Severidad: {detection.severity}\n"
            f"Motor: {detection.engine}\n"
            f"Ruta: {detection.path}\n"
            f"SHA-256: {detection.sha256 or 'no calculado'}\n"
            f"Accion: {detection.action}\n\n{detection.details}",
        )

    def quarantine_selected(self) -> None:
        detection = self._selected_detection()
        if detection is None:
            return
        if not Path(detection.path).is_file():
            QMessageBox.warning(self, "Archivo no disponible", "El archivo ya no existe en esa ruta.")
            return
        extra = (
            "\n\nATENCION: es una deteccion heuristica (sospecha), no malware confirmado."
            if detection.verdict != "malware"
            else ""
        )
        reply = QMessageBox.question(
            self,
            "Poner en cuarentena",
            f"¿Aislar este archivo?\n\n{detection.path}\n\nSe movera a la cuarentena cifrada y podra restaurarse.{extra}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            self.services.quarantine.quarantine_file(
                detection.path,
                detection.name,
                detection.engine,
                detection.sha256,
                detection.details,
            )
            if detection.id:
                self.services.db.update_threat_action(detection.id, "quarantined")
            detection.action = "quarantined"
            row = self.results_table.currentRow()
            self.results_table.setItem(row, 5, item("quarantined", ACCENT_2))
            self._selection_changed()
            self.window.quarantine_page.refresh()
            self.window.refresh_dashboard()
            self.window.notify("Cuarentena", "Archivo aislado correctamente.", "info")
        except Exception as exc:
            log.exception("Error moviendo a cuarentena")
            QMessageBox.critical(self, "Cuarentena", str(exc))

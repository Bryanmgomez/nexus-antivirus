from __future__ import annotations

import logging
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ... import paths
from ...util import format_bytes, local_now_display
from ..theme import ACCENT_2, GREEN, MUTED, RED, TEXT, YELLOW
from ..widgets import Badge, Card, Page, PageHeader, item, make_table
from ..workers import launch_task

log = logging.getLogger(__name__)


class UpdatesPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._info = None

        header = PageHeader(
            "ACTUALIZACIONES",
            "Definiciones firmadas con Ed25519 y actualizacion opcional de ClamAV.",
        )
        self.badge = Badge("SIN CAMBIOS", "muted")
        header.add_action(self.badge)
        refresh = QPushButton("Actualizar vista")
        refresh.setObjectName("Ghost")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        self.add(header)

        version_card = Card(accent=True)
        version_layout = QHBoxLayout(version_card)
        version_layout.setContentsMargins(20, 17, 20, 17)
        left = QVBoxLayout()
        title = QLabel("DEFINICIONES NEXUS")
        title.setObjectName("SectionTitle")
        left.addWidget(title)
        self.version_label = QLabel()
        self.version_label.setObjectName("HeroValue")
        left.addWidget(self.version_label)
        self.engine_detail = QLabel()
        self.engine_detail.setObjectName("Muted")
        self.engine_detail.setWordWrap(True)
        left.addWidget(self.engine_detail)
        version_layout.addLayout(left, 1)
        right = QVBoxLayout()
        self.last_update = QLabel()
        self.last_update.setObjectName("Muted")
        self.last_update.setAlignment(Qt.AlignRight | Qt.AlignTop)
        right.addWidget(self.last_update)
        open_defs = QPushButton("Abrir carpeta de definiciones")
        open_defs.setObjectName("Ghost")
        open_defs.clicked.connect(self.open_definitions)
        right.addWidget(open_defs)
        version_layout.addLayout(right)
        self.add(version_card)

        config_card = Card()
        config_layout = QVBoxLayout(config_card)
        config_layout.setContentsMargins(20, 17, 20, 17)
        config_title = QLabel("REPOSITORIO FIRMADO")
        config_title.setObjectName("SectionTitle")
        config_layout.addWidget(config_title)
        config_note = QLabel(
            "Solo se aceptan manifiestos y paquetes firmados. NEXUS verifica firma Ed25519, SHA-256, "
            "tamano y contenido antes de instalar. Las actualizaciones sin firma se rechazan."
        )
        config_note.setObjectName("Muted")
        config_note.setWordWrap(True)
        config_layout.addWidget(config_note)
        url_row = QHBoxLayout()
        url_row.addWidget(QLabel("URL del manifiesto"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://servidor/nexus/manifest.json")
        url_row.addWidget(self.url_input, 1)
        local = QPushButton("Elegir local")
        local.setObjectName("Ghost")
        local.clicked.connect(self.choose_local_manifest)
        url_row.addWidget(local)
        config_layout.addLayout(url_row)
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Clave publica Ed25519"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Ruta a public_key.pem")
        key_row.addWidget(self.key_input, 1)
        browse_key = QPushButton("Examinar")
        browse_key.setObjectName("Ghost")
        browse_key.clicked.connect(self.choose_public_key)
        key_row.addWidget(browse_key)
        config_layout.addLayout(key_row)
        actions = QHBoxLayout()
        save = QPushButton("Guardar configuracion")
        save.setObjectName("Ghost")
        save.clicked.connect(self.save_config)
        self.check_button = QPushButton("BUSCAR ACTUALIZACION")
        self.check_button.setObjectName("Primary")
        self.check_button.clicked.connect(self.check_updates)
        self.install_button = QPushButton("INSTALAR")
        self.install_button.setObjectName("Primary")
        self.install_button.setEnabled(False)
        self.install_button.clicked.connect(self.install_update)
        actions.addWidget(save)
        actions.addStretch(1)
        actions.addWidget(self.check_button)
        actions.addWidget(self.install_button)
        config_layout.addLayout(actions)
        self.result_label = QLabel()
        self.result_label.setObjectName("Muted")
        self.result_label.setWordWrap(True)
        config_layout.addWidget(self.result_label)
        self.add(config_card)

        clam_card = Card()
        clam_layout = QHBoxLayout(clam_card)
        clam_layout.setContentsMargins(20, 17, 20, 17)
        clam_left = QVBoxLayout()
        clam_title = QLabel("DEFINICIONES CLAMAV (OPCIONAL)")
        clam_title.setObjectName("SectionTitle")
        clam_left.addWidget(clam_title)
        self.clam_label = QLabel()
        self.clam_label.setObjectName("Muted")
        self.clam_label.setWordWrap(True)
        clam_left.addWidget(self.clam_label)
        clam_layout.addLayout(clam_left, 1)
        self.clam_button = QPushButton("ACTUALIZAR CLAMAV")
        self.clam_button.setObjectName("Ghost")
        self.clam_button.clicked.connect(self.update_clamav)
        clam_layout.addWidget(self.clam_button)
        self.add(clam_card)

        history_card = Card()
        history_layout = QVBoxLayout(history_card)
        history_layout.setContentsMargins(20, 17, 20, 17)
        history_title = QLabel("HISTORIAL DE ACTUALIZACIONES")
        history_title.setObjectName("SectionTitle")
        history_layout.addWidget(history_title)
        self.history_table = make_table(["FECHA", "VERSION", "ORIGEN", "ESTADO", "MENSAJE"], stretch_column=4)
        self.history_table.setMinimumHeight(150)
        history_layout.addWidget(self.history_table)
        self.add(history_card)
        self.root.addStretch(1)
        self.refresh()

    def refresh(self) -> None:
        signatures = self.services.signatures
        self.version_label.setText(f"v{signatures.version}")
        self.engine_detail.setText(
            f"{signatures.count} firmas SHA-256 / {self.services.yara.rule_count} reglas YARA / "
            f"ClamAV: {'disponible' if self.services.clamav.available else 'no disponible'}"
        )
        self.last_update.setText(
            "Ultima actualizacion de firmas:\n" + (signatures.updated_at or "desconocida")
        )
        self.url_input.setText(self.services.settings.get("update_url", ""))
        self.key_input.setText(self.services.settings.get("update_public_key", ""))
        if self.services.clamav.available:
            self.clam_label.setText(
                f"Motor: {self.services.clamav.version}\nUbicacion: {self.services.clamav.scan_binary}"
            )
            self.clam_button.setEnabled(bool(self.services.clamav.update_binary))
        else:
            self.clam_label.setText(
                "ClamAV no esta instalado. Configure la ruta en Proteccion para habilitar este motor."
            )
            self.clam_button.setEnabled(False)
        records = self.services.db.list_updates(100)
        self.history_table.setRowCount(len(records))
        for row, record in enumerate(records):
            self.history_table.setItem(row, 0, item(local_now_display(str(record.get("created_at", ""))), MUTED))
            self.history_table.setItem(row, 1, item(str(record.get("version", "")), ACCENT_2))
            self.history_table.setItem(row, 2, item(str(record.get("source", "")), MUTED))
            status = str(record.get("status", ""))
            color = GREEN if status == "success" else RED if status == "error" else YELLOW
            self.history_table.setItem(row, 3, item(status.upper(), color))
            self.history_table.setItem(row, 4, item(str(record.get("message", "")), MUTED))

    def save_config(self) -> None:
        self.services.settings.set("update_url", self.url_input.text().strip())
        self.services.settings.set("update_public_key", self.key_input.text().strip())
        self.window.notify("Actualizaciones", "Configuracion guardada.", "info")
        self.refresh()

    def choose_local_manifest(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Manifiesto de actualizacion", "", "Manifiesto (*.json);;Todos (*)"
        )
        if path:
            self.url_input.setText(Path(path).as_uri())

    def choose_public_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Clave publica Ed25519", "", "Clave PEM (*.pem);;Todos (*)"
        )
        if path:
            self.key_input.setText(path)

    def check_updates(self) -> None:
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Actualizaciones", "Configure la URL del repositorio.")
            return
        self.services.settings.set("update_url", url)
        self.services.settings.set("update_public_key", self.key_input.text().strip())
        self.badge.set_state("warning", "COMPROBANDO")
        self.result_label.setText("Descargando y verificando manifiesto firmado...")
        self.check_button.setEnabled(False)
        launch_task(
            self,
            self.services.update_manager.check,
            url,
            on_result=self._check_result,
            on_error=self._check_error,
        )

    def _check_result(self, info) -> None:
        self._info = info
        self.check_button.setEnabled(True)
        self.badge.set_state("warning", f"v{info.version} DISPONIBLE")
        self.result_label.setText(
            f"Version firmada disponible: {info.version}\n"
            f"Publicada: {info.published_at or 'sin fecha'}\n"
            f"Paquete: {format_bytes(info.archive_size)}\n"
            f"Notas: {info.notes or 'sin notas'}"
        )
        self.install_button.setEnabled(True)

    def _check_error(self, message: str) -> None:
        self._info = None
        self.check_button.setEnabled(True)
        self.install_button.setEnabled(False)
        self.badge.set_state("danger", "ERROR")
        self.result_label.setText(message)
        log.warning("Comprobacion de actualizaciones fallida: %s", message)

    def install_update(self) -> None:
        info = self._info
        if info is None:
            return
        reply = QMessageBox.question(
            self,
            "Instalar actualizacion",
            f"¿Instalar definiciones v{info.version}?\n\n"
            "Se verificaran firma, hash y reglas antes de reemplazar las actuales.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.install_button.setEnabled(False)
        self.badge.set_state("warning", "INSTALANDO")
        launch_task(
            self,
            self.services.update_manager.download_and_apply,
            info,
            on_result=self._installed,
            on_error=self._install_error,
        )

    def _installed(self, version: str) -> None:
        self.services.reload_engines(True)
        self.services.db.add_event("info", "updates", f"Definiciones actualizadas a {version}")
        self.badge.set_state("ok", "ACTUALIZADO")
        self.result_label.setText(f"Definiciones v{version} instaladas y motores recargados.")
        self.window.notify("Actualizaciones", f"Definiciones v{version} instaladas.", "info")
        self.refresh()
        self.window.protection_page.refresh()
        self.window.refresh_dashboard()

    def _install_error(self, message: str) -> None:
        self.badge.set_state("danger", "ERROR")
        self.result_label.setText(f"No se pudo instalar: {message}")
        self.services.db.add_update_record("", "firmado", "error", message[:2000])
        self.window.notify("Actualizaciones", message, "error")
        self.refresh()

    def update_clamav(self) -> None:
        self.clam_button.setEnabled(False)
        self.clam_label.setText("Actualizando definiciones de ClamAV. Puede tardar varios minutos...")
        launch_task(
            self,
            self.services.clamav.update_definitions,
            on_result=self._clam_result,
            on_error=self._clam_error,
        )

    def _clam_result(self, result) -> None:
        ok, message = result
        self.clam_label.setText(message)
        self.clam_button.setEnabled(True)
        self.services.db.add_event("info" if ok else "error", "clamav", message)
        if ok:
            self.services.reload_engines(True)
        self.refresh()

    def _clam_error(self, message: str) -> None:
        self.clam_label.setText(f"Error actualizando ClamAV: {message}")
        self.clam_button.setEnabled(True)

    def open_definitions(self) -> None:
        try:
            paths.definitions_dir().mkdir(parents=True, exist_ok=True)
            os.startfile(str(paths.definitions_dir()))
        except OSError as exc:
            QMessageBox.warning(self, "Definiciones", str(exc))

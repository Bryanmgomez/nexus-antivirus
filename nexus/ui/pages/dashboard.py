from __future__ import annotations

import logging

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from ...system.inventory import list_processes
from ...util import local_now_display
from ..theme import ACCENT_2, GREEN, MUTED, RED, TEXT, YELLOW
from ..widgets import (
    ActivityChart,
    Badge,
    Card,
    Page,
    PageHeader,
    StatCard,
    StatusRing,
    Switch,
    elide,
    item,
    make_table,
)
from ..workers import launch_task

log = logging.getLogger(__name__)


class DashboardPage(Page):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.services = window.services
        self._process_check_running = False

        header = PageHeader(
            "PANEL DE CONTROL",
            "Estado de seguridad del equipo, motores activos y actividad reciente.",
        )
        quick = QPushButton("ANALISIS RAPIDO")
        quick.setObjectName("Ghost")
        quick.clicked.connect(lambda: self.window.start_scan("quick"))
        full = QPushButton("ANALISIS COMPLETO")
        full.setObjectName("Primary")
        full.clicked.connect(lambda: self.window.start_scan("full"))
        header.add_action(quick)
        header.add_action(full)
        self.add(header)

        hero = Card(accent=True)
        hero.setObjectName("HeroCard")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(24, 18, 28, 18)
        hero_layout.setSpacing(28)
        self.ring = StatusRing()
        self.ring.setFixedSize(230, 230)
        hero_layout.addWidget(self.ring)
        info = QVBoxLayout()
        info.setSpacing(9)
        top_badge = QHBoxLayout()
        self.badge = Badge("EVALUANDO", "muted")
        top_badge.addWidget(self.badge)
        top_badge.addStretch(1)
        info.addLayout(top_badge)
        title = QLabel("Proteccion del equipo")
        title.setObjectName("PageTitle")
        title.setStyleSheet("font-size: 22px;")
        info.addWidget(title)
        self.hero_text = QLabel("Comprobando el estado de los motores y la proteccion en tiempo real.")
        self.hero_text.setObjectName("Muted")
        self.hero_text.setWordWrap(True)
        info.addWidget(self.hero_text)
        switch_row = QHBoxLayout()
        switch_row.setSpacing(10)
        realtime_label = QLabel("PROTECCION EN TIEMPO REAL")
        realtime_label.setObjectName("CardLabel")
        self.realtime_switch = Switch()
        self.realtime_switch.toggled.connect(self.window.set_realtime_enabled)
        switch_row.addWidget(realtime_label)
        switch_row.addWidget(self.realtime_switch)
        switch_row.addStretch(1)
        info.addLayout(switch_row)
        self.engine_label = QLabel()
        self.engine_label.setObjectName("Muted")
        self.engine_label.setWordWrap(True)
        info.addWidget(self.engine_label)
        info.addStretch(1)
        last_row = QHBoxLayout()
        self.last_scan_label = QLabel("Ultimo analisis: Nunca")
        self.last_scan_label.setObjectName("Muted")
        self.last_update_label = QLabel("Definiciones: sin datos")
        self.last_update_label.setObjectName("Muted")
        last_row.addWidget(self.last_scan_label)
        last_row.addSpacing(18)
        last_row.addWidget(self.last_update_label)
        last_row.addStretch(1)
        info.addLayout(last_row)
        hero_layout.addLayout(info, 1)
        self.add(hero)

        cards = QGridLayout()
        cards.setHorizontalSpacing(12)
        cards.setVerticalSpacing(12)
        self.threat_card = StatCard("Amenazas abiertas", "0", "Detecciones sin resolver", RED)
        self.quarantine_card = StatCard("Cuarentena", "0", "Archivos aislados", ACCENT_2)
        self.files_card = StatCard("Archivos analizados", "0", "Total historico", GREEN)
        self.process_card = StatCard("Procesos sospechosos", "—", "Indicadores de linea de comandos", YELLOW)
        for index, card in enumerate(
            (self.threat_card, self.quarantine_card, self.files_card, self.process_card)
        ):
            cards.addWidget(card, 0, index)
        self.add_layout(cards)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        activity = Card()
        activity_layout = QVBoxLayout(activity)
        activity_layout.setContentsMargins(18, 15, 18, 12)
        activity_title = QLabel("ACTIVIDAD DE ANALISIS / 7 DIAS")
        activity_title.setObjectName("SectionTitle")
        activity_layout.addWidget(activity_title)
        self.chart = ActivityChart()
        activity_layout.addWidget(self.chart)
        lower.addWidget(activity, 3)

        recent = Card()
        recent_layout = QVBoxLayout(recent)
        recent_layout.setContentsMargins(18, 15, 18, 12)
        recent_title = QLabel("ACTIVIDAD RECIENTE")
        recent_title.setObjectName("SectionTitle")
        recent_layout.addWidget(recent_title)
        self.events_table = make_table(["HORA", "MODULO", "EVENTO"])
        self.events_table.horizontalHeader().setStretchLastSection(True)
        self.events_table.setMinimumHeight(220)
        recent_layout.addWidget(self.events_table)
        lower.addWidget(recent, 4)
        self.add_layout(lower)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(15000)

    def add_layout(self, layout) -> None:
        wrapper = QWidget()
        wrapper.setLayout(layout)
        self.root.addWidget(wrapper)

    def refresh(self) -> None:
        try:
            stats = self.services.db.statistics()
            self.threat_card.set_value(str(stats["threats"]), color=RED if stats["threats"] else GREEN)
            self.quarantine_card.set_value(str(stats["quarantine"]))
            self.files_card.set_value(f"{stats['files_scanned']:,}".replace(",", "."))
            self.chart.set_data(self.services.db.daily_stats(7))
            self._refresh_events()
            settings = self.services.settings
            self.last_scan_label.setText(
                "Ultimo analisis: " + local_now_display(settings.get("last_scan", ""))
            )
            last_update = settings.get("last_update", "")
            self.last_update_label.setText(
                "Definiciones: " + local_now_display(last_update)
                if last_update
                else f"Definiciones: v{self.services.signatures.version}"
            )
            info = self.services.engine_info()
            self.engine_label.setText(
                "Firmas: {firmas}  |  YARA: {yara}  |  ClamAV: {clam}".format(
                    firmas=info.get("Firmas SHA-256", ""),
                    yara=info.get("YARA", ""),
                    clam=info.get("ClamAV", ""),
                )
            )
            self.sync_realtime()
            self._update_ring(stats)
            self._refresh_process_count()
        except Exception:
            log.exception("Error actualizando panel")

    def _refresh_events(self) -> None:
        events = self.services.db.list_events(12)
        self.events_table.setRowCount(len(events))
        for row, event in enumerate(events):
            timestamp = str(event.get("created_at", ""))
            display = timestamp[11:16] if len(timestamp) > 16 else timestamp
            level = str(event.get("level", ""))
            color = {"critical": RED, "error": RED, "warning": YELLOW}.get(level, TEXT)
            self.events_table.setItem(row, 0, item(display, MUTED))
            self.events_table.setItem(row, 1, item(str(event.get("module", "")), ACCENT_2))
            self.events_table.setItem(
                row,
                2,
                item(elide(str(event.get("message", "")), 95), color, str(event.get("message", ""))),
            )

    def _update_ring(self, stats: dict) -> None:
        realtime = self.services.realtime.running
        engines = self.services.signatures.count > 0 and self.services.yara.ready
        score = 45
        if realtime:
            score += 30
        if engines:
            score += 15
        if stats["threats"] == 0:
            score += 10
        else:
            score -= min(35, stats["threats"] * 8)
        score = max(0, min(100, score))
        if realtime and stats["threats"] == 0:
            caption, color, badge_state, badge_text = "PROTEGIDO", GREEN, "ok", "PROTEGIDO"
            message = "La proteccion en tiempo real esta activa y no hay amenazas abiertas."
        elif stats["threats"] > 0:
            caption, color, badge_state, badge_text = "ATENCION", RED, "danger", "AMENAZAS"
            message = f"Hay {stats['threats']} deteccion(es) sin resolver. Revise el historial y la cuarentena."
        else:
            caption, color, badge_state, badge_text = "ATENCION", YELLOW, "warning", "REVISAR"
            message = "Active la proteccion en tiempo real para reducir la exposicion del equipo."
        self.ring.set_score(score, caption, color)
        self.badge.set_state(badge_state, badge_text)
        self.hero_text.setText(message)

    def sync_realtime(self) -> None:
        enabled = self.services.realtime.running
        if self.realtime_switch.isChecked() != enabled:
            self.realtime_switch.blockSignals(True)
            self.realtime_switch.setChecked(enabled)
            self.realtime_switch.blockSignals(False)

    def _refresh_process_count(self) -> None:
        if self._process_check_running:
            return
        self._process_check_running = True

        def done(processes):
            self._process_check_running = False
            suspicious = sum(1 for process in processes if process.suspicion)
            self.process_card.set_value(
                str(suspicious),
                "Sin indicadores" if suspicious == 0 else "Requieren revision",
                YELLOW if suspicious else GREEN,
            )

        def failed(message):
            self._process_check_running = False
            self.process_card.set_value("—", "No se pudo enumerar", YELLOW)

        launch_task(self, list_processes, on_result=done, on_error=failed)

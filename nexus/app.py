from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from .logging_setup import configure_logging
from .paths import ensure_directories
from .ui.theme import apply_theme, app_icon

log = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    ensure_directories()
    configure_logging(verbose="--verbose" in (argv or sys.argv))
    app = QApplication(sys.argv if argv is None else argv)
    app.setApplicationName("NEXUS ANTIVIRUS")
    app.setOrganizationName("NEXUS Security")
    app.setApplicationVersion("1.0.0")
    app.setWindowIcon(app_icon())
    apply_theme(app)
    try:
        from .ui.main_window import MainWindow

        window = MainWindow()
    except Exception as exc:
        log.exception("No se pudo iniciar la interfaz")
        QMessageBox.critical(
            None,
            "NEXUS ANTIVIRUS",
            f"No se pudo iniciar la aplicacion:\n\n{exc}\n\nConsulte los registros en "
            "%LOCALAPPDATA%\\NexusAntivirus\\logs\\nexus.log",
        )
        return 1
    argv_list = sys.argv if argv is None else argv
    if "--background" not in (argv_list or []):
        window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

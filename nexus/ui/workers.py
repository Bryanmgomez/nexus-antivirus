from __future__ import annotations

import logging
import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..engine.scanner import AntivirusScanner
from ..models import ScanOptions, ScanProgress, Detection, ScanSummary

log = logging.getLogger(__name__)


class ScanWorker(QObject):
    progress = Signal(object)
    detection = Signal(object)
    result = Signal(object)
    error = Signal(str)
    finished = Signal()

    def __init__(self, scanner: AntivirusScanner, options: ScanOptions):
        super().__init__()
        self.scanner = scanner
        self.options = options

    @Slot()
    def run(self) -> None:
        try:
            summary: ScanSummary = self.scanner.scan(
                self.options,
                progress_cb=self.progress.emit,
                detection_cb=self.detection.emit,
            )
            self.result.emit(summary)
        except Exception as exc:
            log.exception("Fallo el analisis")
            self.error.emit(f"{exc}\n{traceback.format_exc(limit=3)}")
        finally:
            self.finished.emit()

    def cancel(self) -> None:
        self.scanner.cancel()


class BackgroundTask(QObject):
    result = Signal(object)
    progress = Signal(object)
    error = Signal(str)
    finished = Signal()

    def __init__(
        self,
        fn: Callable[..., Any],
        *args: Any,
        with_progress: bool = False,
        **kwargs: Any,
    ):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.with_progress = with_progress

    @Slot()
    def run(self) -> None:
        try:
            if self.with_progress:
                value = self.fn(*self.args, progress_cb=self.progress.emit, **self.kwargs)
            else:
                value = self.fn(*self.args, **self.kwargs)
            self.result.emit(value)
        except Exception as exc:
            log.exception("Tarea en segundo plano fallida")
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


def launch_task(
    owner: QObject,
    fn: Callable[..., Any],
    *args: Any,
    on_result: Callable[[Any], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_progress: Callable[[Any], None] | None = None,
    with_progress: bool = False,
    **kwargs: Any,
) -> tuple[QThread, BackgroundTask]:
    thread = QThread(owner)
    task = BackgroundTask(fn, *args, with_progress=with_progress, **kwargs)
    task.moveToThread(thread)
    refs: list = getattr(owner, "_background_refs", [])
    if not hasattr(owner, "_background_refs"):
        owner._background_refs = refs
    refs.append((thread, task))
    if on_result:
        task.result.connect(on_result)
    if on_error:
        task.error.connect(on_error)
    if on_progress:
        task.progress.connect(on_progress)
    thread.started.connect(task.run)
    task.finished.connect(thread.quit)
    task.finished.connect(task.deleteLater)
    thread.finished.connect(thread.deleteLater)

    def cleanup() -> None:
        try:
            refs.remove((thread, task))
        except ValueError:
            pass

    thread.finished.connect(cleanup)
    thread.start()
    return thread, task

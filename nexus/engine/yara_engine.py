from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .. import paths

log = logging.getLogger(__name__)

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover - depende del entorno
    yara = None


@dataclass(slots=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, str]
    severity: str
    name: str
    details: str


class YaraEngine:
    def __init__(self, rules_path: Path | str | None = None):
        self.rules_path = Path(rules_path) if rules_path else paths.active_yara_file()
        self._rules = None
        self.available = yara is not None
        self.last_error = ""
        self.rule_count = 0
        if self.available:
            self.compile()
        else:
            self.last_error = "yara-python no esta instalado"

    def compile(self) -> None:
        self.last_error = ""
        self._rules = None
        self.rule_count = 0
        if not self.available:
            return
        try:
            if not self.rules_path.is_file():
                raise FileNotFoundError(str(self.rules_path))
            self._rules = yara.compile(filepath=str(self.rules_path))
            # yara-python no expone un conteo directo; se cuenta por nombres de reglas.
            source = self.rules_path.read_text(encoding="utf-8", errors="replace")
            self.rule_count = source.count("\nrule ") + (1 if source.lstrip().startswith("rule ") else 0)
            log.info("Reglas YARA compiladas desde %s", self.rules_path)
        except Exception as exc:  # yara.YaraError no siempre existe como atributo
            self.last_error = f"Error compilando YARA: {exc}"
            self._rules = None
            log.exception("No se pudieron compilar las reglas YARA")

    @property
    def ready(self) -> bool:
        return self.available and self._rules is not None

    def scan_file(self, path: str) -> list[YaraMatch]:
        if not self.ready or self._rules is None:
            return []
        try:
            matches = self._rules.match(path, timeout=10)
        except Exception as exc:
            log.warning("YARA no pudo analizar %s: %s", path, exc)
            return []
        results: list[YaraMatch] = []
        for match in matches:
            meta = {str(k): str(v) for k, v in (match.meta or {}).items()}
            severity = meta.get("severity", "medium").lower()
            name = meta.get("name") or f"YARA.{match.rule}"
            description = meta.get("description", "")
            results.append(
                YaraMatch(
                    rule=str(match.rule),
                    namespace=str(match.namespace),
                    tags=[str(tag) for tag in match.tags],
                    meta=meta,
                    severity=severity,
                    name=name,
                    details=description or f"Regla YARA: {match.rule}",
                )
            )
        return results

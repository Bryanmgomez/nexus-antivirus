from __future__ import annotations

import argparse
import json
import sys
import uuid

from .logging_setup import configure_logging
from .models import ScanOptions
from .paths import APP_NAME, APP_VERSION
from .services import NexusServices
from .util import utc_now


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nexus-antivirus", description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--scan", choices=["quick", "full", "deep", "memory", "custom", "usb"], default="quick")
    parser.add_argument("paths", nargs="*", help="Rutas para el analisis personalizado")
    parser.add_argument("--quarantine", action="store_true", help="Aislar automaticamente malware confirmado")
    parser.add_argument("--no-clamav", action="store_true", help="No usar ClamAV en este analisis")
    parser.add_argument("--no-yara", action="store_true", help="No usar reglas YARA")
    parser.add_argument("--json", action="store_true", help="Salida JSON")
    parser.add_argument("--verbose", action="store_true")
    return parser


def _print_summary(data: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    print(f"\n{APP_NAME} / RESULTADO")
    print(f"Tipo: {data.get('scan_type')}")
    print(f"Archivos: {data.get('files_scanned')}")
    print(f"Detecciones: {data.get('threats_found')}")
    print(f"Errores: {data.get('errors')}")
    print(f"Estado: {data.get('status')}")
    for detection in data.get("detections", []):
        print(
            f"  [{detection['verdict'].upper()}] {detection['name']} | {detection['engine']} | "
            f"{detection['path']}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    services = NexusServices()
    try:
        if args.scan == "memory":
            detections = services.memory.scan()
            scan_id = uuid.uuid4().hex
            now = utc_now()
            services.db.create_scan(scan_id, "memory", [], now)
            for detection in detections:
                services.db.add_threat(detection, scan_id)
            services.db.finish_scan(
                scan_id, utc_now(), 0, 0, len(detections), 0, "completed"
            )
            payload = {
                "scan_type": "memory",
                "files_scanned": 0,
                "threats_found": len(detections),
                "errors": 0,
                "status": "completed",
                "detections": [detection.to_dict() for detection in detections],
            }
            _print_summary(payload, args.json)
            return 1 if detections else 0
        if args.scan in {"custom", "usb"} and not args.paths:
            parser.error("El analisis personalizado/USB requiere al menos una ruta.")
        options = ScanOptions(
            scan_type=args.scan,
            roots=args.paths,
            auto_quarantine=args.quarantine,
            use_clamav=not args.no_clamav,
            use_yara=not args.no_yara,
        )
        summary = services.scanner.scan(options)
        payload = {
            "scan_type": summary.scan_type,
            "scan_id": summary.scan_id,
            "files_scanned": summary.files_scanned,
            "bytes_scanned": summary.bytes_scanned,
            "threats_found": summary.threats_found,
            "errors": summary.errors,
            "status": summary.status,
            "cancelled": summary.cancelled,
            "detections": [detection.to_dict() for detection in summary.detections],
        }
        _print_summary(payload, args.json)
        return 1 if summary.detections else 0
    finally:
        services.shutdown()


if __name__ == "__main__":
    sys.exit(main())

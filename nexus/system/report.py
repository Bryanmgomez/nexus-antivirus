from __future__ import annotations

import html
from typing import Any

from ..config import Settings
from ..database import Database
from ..models import SystemCheck
from ..util import local_now_display, utc_now


def build_security_report(
    db: Database,
    settings: Settings,
    engine_info: dict[str, Any],
    checks: list[SystemCheck],
) -> str:
    stats = db.statistics()
    scans = db.list_scans(5)
    threats = db.list_threats(30)
    quarantine = db.list_quarantine()
    updates = db.list_updates(5)
    rows_threats = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('discovered_at', '')))}</td>"
        f"<td>{html.escape(str(item.get('name', '')))}</td>"
        f"<td>{html.escape(str(item.get('verdict', '')))}</td>"
        f"<td>{html.escape(str(item.get('severity', '')))}</td>"
        f"<td class='path'>{html.escape(str(item.get('path', '')))}</td>"
        f"<td>{html.escape(str(item.get('engine', '')))}</td>"
        "</tr>"
        for item in threats
    ) or "<tr><td colspan='6'>Sin amenazas registradas.</td></tr>"
    rows_checks = "".join(
        "<tr>"
        f"<td>{html.escape(item.title)}</td>"
        f"<td class='{html.escape(item.status)}'>{html.escape(item.status.upper())}</td>"
        f"<td>{html.escape(item.detail)}</td>"
        "</tr>"
        for item in checks
    ) or "<tr><td colspan='3'>Sin comprobaciones disponibles.</td></tr>"
    rows_scans = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('scan_type', '')))}</td>"
        f"<td>{html.escape(local_now_display(str(item.get('started_at', ''))))}</td>"
        f"<td>{int(item.get('files_scanned', 0))}</td>"
        f"<td>{int(item.get('threats_found', 0))}</td>"
        f"<td>{html.escape(str(item.get('status', '')))}</td>"
        "</tr>"
        for item in scans
    ) or "<tr><td colspan='5'>Sin analisis registrados.</td></tr>"
    rows_updates = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('created_at', '')))}</td>"
        f"<td>{html.escape(str(item.get('version', '')))}</td>"
        f"<td>{html.escape(str(item.get('status', '')))}</td>"
        f"<td>{html.escape(str(item.get('message', '') or ''))}</td>"
        "</tr>"
        for item in updates
    ) or "<tr><td colspan='4'>Sin actualizaciones registradas.</td></tr>"
    engine_rows = "".join(
        f"<li><strong>{html.escape(str(name))}:</strong> {html.escape(str(value))}</li>"
        for name, value in engine_info.items()
    )
    generated = utc_now()
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>NEXUS ANTIVIRUS - Informe de seguridad</title>
<style>
body {{ background:#070b12; color:#d8e6f3; font-family:'Segoe UI',sans-serif; margin:0; padding:40px; }}
h1,h2 {{ color:#39b8ff; letter-spacing:1px; }}
h1 {{ border-bottom:1px solid #17324a; padding-bottom:16px; }}
.cards {{ display:flex; gap:14px; flex-wrap:wrap; margin:20px 0; }}
.card {{ background:#0d1622; border:1px solid #17324a; border-radius:10px; padding:16px 22px; min-width:150px; }}
.card .value {{ font-size:28px; color:#66d9ff; font-weight:600; }}
table {{ width:100%; border-collapse:collapse; margin:10px 0 30px; font-size:13px; }}
th,td {{ border-bottom:1px solid #15283a; padding:8px; text-align:left; vertical-align:top; }}
th {{ color:#6fb9df; text-transform:uppercase; font-size:11px; letter-spacing:1px; }}
.path {{ word-break:break-all; color:#9bb7cd; }}
.ok {{ color:#46e6a0; }} .warning {{ color:#ffbd4a; }} .unknown {{ color:#8da2b5; }}
.footer {{ color:#547089; font-size:12px; margin-top:30px; }}
</style>
</head>
<body>
<h1>NEXUS ANTIVIRUS / INFORME DE SEGURIDAD</h1>
<p>Generado: {html.escape(generated)}</p>
<div class="cards">
<div class="card"><div class="value">{stats['threats']}</div>Amenazas abiertas</div>
<div class="card"><div class="value">{stats['quarantine']}</div>En cuarentena</div>
<div class="card"><div class="value">{stats['files_scanned']}</div>Archivos analizados</div>
<div class="card"><div class="value">{stats['scans']}</div>Analisis realizados</div>
</div>
<h2>Motores</h2><ul>{engine_rows}</ul>
<h2>Estado de seguridad</h2>
<table><thead><tr><th>Comprobacion</th><th>Estado</th><th>Detalle</th></tr></thead><tbody>{rows_checks}</tbody></table>
<h2>Analisis recientes</h2>
<table><thead><tr><th>Tipo</th><th>Inicio</th><th>Archivos</th><th>Detecciones</th><th>Estado</th></tr></thead><tbody>{rows_scans}</tbody></table>
<h2>Amenazas recientes</h2>
<table><thead><tr><th>Fecha</th><th>Nombre</th><th>Veredicto</th><th>Severidad</th><th>Ruta</th><th>Motor</th></tr></thead><tbody>{rows_threats}</tbody></table>
<h2>Cuarentena actual</h2>
<p>{len(quarantine)} archivo(s) aislado(s).</p>
<h2>Actualizaciones</h2>
<table><thead><tr><th>Fecha</th><th>Version</th><th>Estado</th><th>Mensaje</th></tr></thead><tbody>{rows_updates}</tbody></table>
<p class="footer">Este informe se genera a partir de datos reales almacenados por NEXUS. Las detecciones heuristicas son sospechas y requieren revision. NEXUS no sustituye a Windows Defender ni a una solucion EDR corporativa.</p>
</body></html>"""

# NEXUS ANTIVIRUS

Aplicacion de proteccion de endpoints para Windows 10/11 con interfaz PySide6 y CLI.

## Ejecucion

```powershell
.\.venv\Scripts\python.exe -m nexus
```

CLI:

```powershell
.\.venv\Scripts\python.exe -m nexus.cli --scan quick
```

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Notas

- ClamAV es opcional.
- La cuarentena cifra archivos con AES-256-CTR + HMAC-SHA256 y clave protegida por DPAPI.
- Las heuristicas generan hallazgos de revision, no veredictos definitivos.

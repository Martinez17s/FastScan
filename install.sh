#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  FastScan CLI v3 — Installer
#  Compatible: Kali Linux, Parrot OS, Ubuntu, Debian
# ─────────────────────────────────────────────────────────────

set -e

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Config ───────────────────────────────────────────────────
INSTALL_DIR="/opt/fastscan"
BIN_LINK="/usr/local/bin/fastscan"
REPO_RAW="https://raw.githubusercontent.com/Martinez17s/FastScan/main/fastscan.py"
# Si no tenés repo, el installer usa el archivo local si existe
LOCAL_SCRIPT="$(dirname "$0")/fastscan.py"

# ─────────────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    echo "  ███████╗ █████╗ ███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗"
    echo "  ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║"
    echo "  █████╗  ███████║███████╗   ██║   ███████╗██║     ███████║██╔██╗ ██║"
    echo "  ██╔══╝  ██╔══██║╚════██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║"
    echo "  ██║     ██║  ██║███████║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║"
    echo "  ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "  ${BOLD}FastScan CLI v3 — Installer${NC}"
    echo -e "  ${YELLOW}Kali / Parrot / Ubuntu / Debian${NC}"
    echo ""
}

log_ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
log_info() { echo -e "  ${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "  ${RED}[✗]${NC} $1"; }

# ─────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "Este installer necesita permisos root."
        echo -e "  Corré: ${BOLD}sudo bash install.sh${NC}"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_ID="$ID"
    else
        OS_NAME="Unknown"
        OS_ID="unknown"
    fi
    log_info "Sistema detectado: ${BOLD}$OS_NAME${NC}"
}

check_python() {
    log_info "Verificando Python 3..."
    if ! command -v python3 &>/dev/null; then
        log_warn "Python 3 no encontrado. Instalando..."
        apt-get install -y python3 python3-pip &>/dev/null
    fi
    PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    log_ok "Python $PY_VER"
}

install_system_deps() {
    log_info "Actualizando lista de paquetes..."
    apt-get update -qq

    PKGS=("nmap" "python3-pip" "libnotify-bin" "curl" "wget")

    # Proxychains (nombre varía según distro)
    if apt-cache show proxychains4 &>/dev/null 2>&1; then
        PKGS+=("proxychains4")
    else
        PKGS+=("proxychains")
    fi

    for pkg in "${PKGS[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            log_ok "$pkg ya instalado"
        else
            log_info "Instalando $pkg..."
            if apt-get install -y "$pkg" &>/dev/null; then
                log_ok "$pkg instalado"
            else
                log_warn "$pkg no se pudo instalar (no es crítico)"
            fi
        fi
    done
}

install_python_deps() {
    log_info "Instalando dependencias Python..."

    PYDEPS=("python-nmap" "rich")

    for dep in "${PYDEPS[@]}"; do
        log_info "pip install $dep..."
        if pip3 install "$dep" --break-system-packages -q 2>/dev/null || \
           pip3 install "$dep" -q 2>/dev/null; then
            log_ok "$dep instalado"
        else
            log_err "No se pudo instalar $dep"
            echo -e "  Intentá manualmente: ${BOLD}pip3 install $dep --break-system-packages${NC}"
            exit 1
        fi
    done
}

install_fastscan() {
    log_info "Instalando FastScan en $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"

    # Obtener fastscan.py: primero local, luego repo
    if [[ -f "$LOCAL_SCRIPT" ]]; then
        cp "$LOCAL_SCRIPT" "$INSTALL_DIR/fastscan.py"
        log_ok "fastscan.py copiado desde archivo local"
    else
        log_info "Descargando fastscan.py desde repositorio..."
        if curl -fsSL "$REPO_RAW" -o "$INSTALL_DIR/fastscan.py" 2>/dev/null; then
            log_ok "fastscan.py descargado"
        else
            log_err "No se pudo descargar fastscan.py"
            log_warn "Copiá fastscan.py manualmente a $INSTALL_DIR/"
            exit 1
        fi
    fi

    chmod 755 "$INSTALL_DIR/fastscan.py"

    # Crear wrapper en /usr/local/bin para correr con sudo automático
    cat > "$BIN_LINK" << 'EOF'
#!/usr/bin/env bash
# FastScan CLI — wrapper con sudo automático
SCRIPT="/opt/fastscan/fastscan.py"

if [[ $EUID -ne 0 ]]; then
    exec sudo DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" python3 "$SCRIPT" "$@"
else
    exec python3 "$SCRIPT" "$@"
fi
EOF

    chmod +x "$BIN_LINK"
    log_ok "Comando global creado: ${BOLD}fastscan${NC}"
}

set_nmap_capabilities() {
    log_info "Configurando capabilities en nmap (evitar sudo en SYN scans)..."
    NMAP_BIN=$(which nmap)
    if setcap cap_net_raw,cap_net_admin+eip "$NMAP_BIN" 2>/dev/null; then
        log_ok "Capabilities aplicadas a nmap — ya no necesitás sudo para SYN scans"
    else
        log_warn "No se pudieron aplicar capabilities. Nmap seguirá requiriendo sudo."
    fi
}

verify_install() {
    echo ""
    log_info "Verificando instalación..."
    echo ""

    CHECKS_OK=0
    CHECKS_FAIL=0

    check_item() {
        local label="$1"
        local cmd="$2"
        if eval "$cmd" &>/dev/null; then
            log_ok "$label"
            ((CHECKS_OK++))
        else
            log_warn "$label — NO disponible"
            ((CHECKS_FAIL++))
        fi
    }

    check_item "nmap"              "command -v nmap"
    check_item "python3"           "command -v python3"
    check_item "python-nmap"       "python3 -c 'import nmap'"
    check_item "rich"              "python3 -c 'import rich'"
    check_item "notify-send"       "command -v notify-send"
    check_item "proxychains"       "command -v proxychains4 || command -v proxychains"
    check_item "fastscan (global)" "command -v fastscan"

    echo ""
    if [[ $CHECKS_FAIL -eq 0 ]]; then
        log_ok "${BOLD}Todos los checks pasaron ($CHECKS_OK/$((CHECKS_OK+CHECKS_FAIL)))${NC}"
    else
        log_warn "$CHECKS_OK ok / $CHECKS_FAIL con advertencias"
    fi
}

print_usage() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}${GREEN}¡Instalación completada!${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Uso:"
    echo -e "    ${BOLD}fastscan${NC}                         → Menú interactivo"
    echo -e "    ${BOLD}fastscan 192.168.1.1 --fast${NC}      → Reconocimiento rápido"
    echo -e "    ${BOLD}fastscan 192.168.1.1 --deep -v${NC}   → Escaneo completo verbose"
    echo -e "    ${BOLD}fastscan 192.168.1.0/24 --recon${NC}  → Descubrimiento de hosts"
    echo -e "    ${BOLD}fastscan 10.0.0.5 --vuln --export${NC} → Auditoría + reporte MD"
    echo -e "    ${BOLD}fastscan 10.0.0.5 --evade --proxychains${NC} → Evasión con proxy"
    echo ""
    echo -e "  Archivos:"
    echo -e "    Script:  ${BOLD}/opt/fastscan/fastscan.py${NC}"
    echo -e "    Comando: ${BOLD}/usr/local/bin/fastscan${NC}"
    echo ""
}

uninstall() {
    echo -e "${YELLOW}[!] Desinstalando FastScan...${NC}"
    rm -rf "$INSTALL_DIR"
    rm -f  "$BIN_LINK"
    log_ok "FastScan eliminado."
    exit 0
}

# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
if [[ "$1" == "--uninstall" ]]; then
    check_root
    uninstall
fi

banner
check_root
detect_os

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Paso 1/5 — Verificando Python${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
check_python

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Paso 2/5 — Dependencias del sistema${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
install_system_deps

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Paso 3/5 — Dependencias Python${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
install_python_deps

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Paso 4/5 — Instalando FastScan${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
install_fastscan
set_nmap_capabilities

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Paso 5/5 — Verificación final${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
verify_install

print_usage

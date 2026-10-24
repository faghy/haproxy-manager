#!/bin/bash
# =============================================
# client/install-launcher.sh
# Installa sul PC dell'utente il lanciatore di haproxy-manager: lo script
# haproxy-manager-open, l'alias SSH "hamgr" (tunnel verso il master) e
# l'icona nel menu delle applicazioni.
#
#   git clone https://github.com/faghy/haproxy-manager.git
#   haproxy-manager/client/install-launcher.sh [opzioni]
#
# Opzioni:
#   --host IP        master HAProxy (predefinito 10.0.0.200, raggiungibile via WireGuard)
#   --user NOME      utente SSH sul master (predefinito root)
#   --key FILE       chiave SSH da usare (predefinita: quelle standard di ssh)
#   --port N         porta locale del tunnel (predefinita 8888)
#   --desktop        mette l'icona anche sulla scrivania (Linux)
#   --uninstall      toglie script, icone e alias hamgr
#
# Linux: un solo file .desktop (standard freedesktop) vale per GNOME, KDE
# Plasma, XFCE, Cinnamon, MATE, LXQt, Budgie; con --desktop l'icona sulla
# scrivania viene marcata come fidata dove serve (GNOME/Nautilus, XFCE).
# macOS: crea "~/Applications/HAProxy Manager.app".
# Non tocca un alias "hamgr" già presente in ~/.ssh/config.
# =============================================
set -euo pipefail

HOST=10.0.0.200 USER_SSH=root KEY="" PORT=8888 DESKTOP=0 UNINSTALL=0
# Impronta della chiave host ED25519 del master (per la verifica al primo accesso)
FINGERPRINT="SHA256:gngRfkOU3NYJ1qd6XFraueZbo72RtEuEC7QTrZvDI3w"

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --user) USER_SSH="$2"; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --desktop) DESKTOP=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Opzione sconosciuta: $1" >&2; exit 2 ;;
    esac
done
[[ "$PORT" =~ ^[0-9]{2,5}$ ]] || { echo "Porta non valida: $PORT" >&2; exit 2; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/haproxy-manager-open"
BIN_DIR="$HOME/.local/bin"
BIN="$BIN_DIR/haproxy-manager-open"
SSH_CFG="$HOME/.ssh/config"
OS="$(uname -s)"
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="$APPS_DIR/haproxy-manager.desktop"
MAC_APP="$HOME/Applications/HAProxy Manager.app"

desktop_dir() {
    if command -v xdg-user-dir >/dev/null 2>&1; then xdg-user-dir DESKTOP; else echo "$HOME/Desktop"; fi
}

refresh_menus() {
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS_DIR" 2>/dev/null || true
    # KDE Plasma ricarica il menu da solo, ma così è immediato
    for k in kbuildsycoca6 kbuildsycoca5; do
        if command -v "$k" >/dev/null 2>&1; then "$k" >/dev/null 2>&1 || true; break; fi
    done
    return 0
}

# ---------- disinstallazione ----------
if [ "$UNINSTALL" = 1 ]; then
    "$BIN" stop 2>/dev/null || true
    rm -f "$BIN" "$DESKTOP_FILE" "$(desktop_dir)/haproxy-manager.desktop"
    rm -rf "$MAC_APP"
    if [ -f "$SSH_CFG" ] && grep -q "^# >>> haproxy-manager" "$SSH_CFG"; then
        cp -p "$SSH_CFG" "$SSH_CFG.bak-$(date +%Y%m%d-%H%M%S)"
        sed -i.tmp '/^# >>> haproxy-manager/,/^# <<< haproxy-manager/d' "$SSH_CFG" && rm -f "$SSH_CFG.tmp"
        echo "Alias hamgr tolto da $SSH_CFG (copia di sicurezza accanto)"
    fi
    [ "$OS" = Linux ] && refresh_menus
    echo "HAProxy Manager disinstallato."
    exit 0
fi

# ---------- prerequisiti ----------
command -v ssh >/dev/null 2>&1 || { echo "Manca il client ssh (openssh-client)." >&2; exit 1; }
[ -f "$SRC" ] || { echo "Non trovo $SRC: lancia lo script dalla cartella client della repo." >&2; exit 1; }

# ---------- script ----------
mkdir -p "$BIN_DIR"
install -m 0755 "$SRC" "$BIN"
if [ "$PORT" != 8888 ]; then
    sed -i.tmp "s/^PORT=.*/PORT=\"\${HAMGR_PORT:-$PORT}\"/" "$BIN" && rm -f "$BIN.tmp"
fi
echo "Script: $BIN"

# ---------- alias SSH ----------
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
touch "$SSH_CFG" && chmod 600 "$SSH_CFG"
if grep -qiE "^[[:space:]]*Host[[:space:]]+(.*[[:space:]])?hamgr([[:space:]]|$)" "$SSH_CFG"; then
    echo "Alias hamgr già presente in $SSH_CFG: lasciato com'è."
else
    cp -p "$SSH_CFG" "$SSH_CFG.bak-$(date +%Y%m%d-%H%M%S)"
    {
        echo ""
        echo "# >>> haproxy-manager (client/install-launcher.sh)"
        echo "Host hamgr"
        echo "    HostName $HOST"
        echo "    User $USER_SSH"
        [ -n "$KEY" ] && echo "    IdentityFile $KEY"
        echo "    LocalForward 127.0.0.1:$PORT 127.0.0.1:8081"
        echo "    ExitOnForwardFailure yes"
        echo "    ServerAliveInterval 30"
        echo "    ServerAliveCountMax 3"
        echo "# <<< haproxy-manager"
    } >> "$SSH_CFG"
    echo "Alias hamgr aggiunto a $SSH_CFG ($USER_SSH@$HOST, localhost:$PORT)"
fi

# ---------- lanciatore ----------
case "$OS" in
Linux)
    mkdir -p "$APPS_DIR"
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=HAProxy Manager
Comment=Domini HAProxy/Varnish (tunnel SSH su localhost:$PORT)
Exec=$BIN
Icon=network-server
Terminal=false
Categories=System;
Keywords=haproxy;varnish;domini;
StartupNotify=false
Actions=stop;

[Desktop Action stop]
Name=Chiudi tunnel
Exec=$BIN stop
EOF
    chmod 0755 "$DESKTOP_FILE"
    command -v desktop-file-validate >/dev/null 2>&1 && desktop-file-validate "$DESKTOP_FILE" || true
    refresh_menus
    echo "Menu applicazioni: $DESKTOP_FILE"

    if [ "$DESKTOP" = 1 ]; then
        DD="$(desktop_dir)"; mkdir -p "$DD"
        install -m 0755 "$DESKTOP_FILE" "$DD/haproxy-manager.desktop"
        # GNOME (estensione Desktop Icons/DING, Nautilus) e XFCE chiedono che il file sia "fidato"
        command -v gio >/dev/null 2>&1 && gio set "$DD/haproxy-manager.desktop" metadata::trusted true 2>/dev/null || true
        if command -v xfconf-query >/dev/null 2>&1 || [ "${XDG_CURRENT_DESKTOP:-}" = XFCE ]; then
            sum=$(sha256sum "$DD/haproxy-manager.desktop" | cut -d' ' -f1)
            gio set -t string "$DD/haproxy-manager.desktop" metadata::xfce-exe-checksum "$sum" 2>/dev/null || true
        fi
        echo "Scrivania: $DD/haproxy-manager.desktop"
        case "${XDG_CURRENT_DESKTOP:-}" in
            *GNOME*) echo "  GNOME mostra icone sulla scrivania solo con l'estensione \"Desktop Icons NG\"." ;;
        esac
    fi
    ;;
Darwin)
    command -v osacompile >/dev/null 2>&1 || { echo "osacompile non trovato" >&2; exit 1; }
    mkdir -p "$HOME/Applications"
    rm -rf "$MAC_APP"
    osacompile -o "$MAC_APP" -e "do shell script quoted form of \"$BIN\" & \" >/dev/null 2>&1\""
    echo "Applicazione: $MAC_APP (Launchpad/Spotlight: \"HAProxy Manager\")"
    echo "Per chiudere il tunnel: $BIN stop"
    ;;
*)
    echo "Sistema $OS non gestito: usa direttamente $BIN" ;;
esac

# ---------- primo accesso ----------
cat <<EOF

Fatto. Prima di usare l'icona:
  1. WireGuard attivo (il master $HOST si raggiunge solo dalla VPN).
  2. La tua chiave SSH pubblica deve essere in /root/.ssh/authorized_keys del master.
  3. Primo accesso da terminale per accettare la chiave host:
       ssh hamgr true
     L'impronta ED25519 deve essere esattamente:
       $FINGERPRINT
     Se è diversa, NON accettare.
EOF
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "  (Nota: $BIN_DIR non è nel PATH: l'icona funziona lo stesso.)";; esac

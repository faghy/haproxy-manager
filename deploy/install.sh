#!/bin/bash
# =============================================
# Installa/aggiorna haproxy-manager su un nodo HAProxy (da root, nella
# cartella della repo già compilata: /opt/haproxy-manager).
# Idempotente. Non riavvia il servizio: systemctl restart haproxy-manager
# =============================================
set -euo pipefail
cd "$(dirname "$0")/.."
APP=/opt/haproxy-manager
U=haproxy-manager

id "$U" >/dev/null 2>&1 ||
    useradd --system --home-dir /var/lib/haproxy-manager --no-create-home --shell /usr/sbin/nologin "$U"

install -m 0755 deploy/haproxy-manager-helper /usr/local/sbin/haproxy-manager-helper
install -D -m 0755 deploy/cf-certs.py /usr/local/lib/haproxy-manager/cf-certs.py
[ -f /root/.cloudflare.env ] ||
    echo "attenzione: /root/.cloudflare.env mancante, i certificati Cloudflare non si possono creare"
install -m 0644 deploy/tmpfiles.conf /etc/tmpfiles.d/haproxy-manager.conf
systemd-tmpfiles --create /etc/tmpfiles.d/haproxy-manager.conf
chown root:"$U" /run/lock/haproxy-maps.lock; chmod 0664 /run/lock/haproxy-maps.lock

visudo -cf deploy/sudoers >/dev/null
install -m 0440 deploy/sudoers /etc/sudoers.d/haproxy-manager

# Mappe: cartella del gruppo haproxy-manager (setgid: i file nuovi restano del gruppo)
chgrp "$U" /etc/haproxy/maps; chmod 2775 /etc/haproxy/maps
chgrp "$U" /etc/haproxy/maps/*.map; chmod 0664 /etc/haproxy/maps/*.map

touch /var/log/haproxy-manager.log; chown "$U":"$U" /var/log/haproxy-manager.log
install -d -o "$U" -g "$U" -m 0755 /var/lib/haproxy-manager
[ -f /var/lib/haproxy-manager/history.jsonl ] || install -o "$U" -g "$U" -m 0644 /dev/null /var/lib/haproxy-manager/history.jsonl

# .env: password come hash bcrypt invece che in chiaro
if [ -f "$APP/.env" ]; then
    if grep -q '^ADMIN_PASS=' "$APP/.env" && ! grep -q '^ADMIN_PASS_HASH=' "$APP/.env"; then
        P=$(sed -n 's/^ADMIN_PASS=//p' "$APP/.env" | head -1)
        P="${P%\"}"; P="${P#\"}"; P="${P%\'}"; P="${P#\'}"
        H=$(printf '%s\n' "$P" | "$APP/target/release/haproxy-manager" hash-password)
        unset P
        cp -a "$APP/.env" "$APP/.env.bak-$(date +%Y%m%d-%H%M%S)"
        chmod 600 "$APP"/.env.bak-*
        sed -i "s|^ADMIN_PASS=.*|ADMIN_PASS_HASH='$H'|" "$APP/.env"
        echo "ADMIN_PASS convertita in ADMIN_PASS_HASH"
    fi
    chown root:"$U" "$APP/.env"; chmod 0640 "$APP/.env"
fi

install -m 0644 deploy/haproxy-manager.service /etc/systemd/system/haproxy-manager.service
systemctl daemon-reload
echo "installato: systemctl restart haproxy-manager"

#!/usr/bin/env python3
# =============================================
# /usr/local/lib/haproxy-manager/cf-certs.py (root:root 0755)
# Certificati Cloudflare Origin CA per HAProxy. Lo chiama solo
# haproxy-manager-helper (root), che controlla, ricarica e sincronizza.
#
#   create <dominio>    crea .<nome>.pem.new in /etc/haproxy/certs e stampa
#                       "NEW <nome>.pem" (o "EXISTS <nome>.pem" se c'è già).
#                       <nome> = la zona se il dominio è la zona o un livello
#                       sotto (copre zona e *.zona), altrimenti il dominio
#   strict <dominio>    SSL/TLS Full (strict) sulla zona del dominio
#   used <file.pem>     domini delle mappe coperti solo da questo certificato
#   revoke <percorso>   revoca su Cloudflare il certificato uguale a quello del file
#                       (in /etc/haproxy/certs o nella copia in /var/backups/haproxy/certs)
#   list                "<file>|<scadenza>|<nome> <nome>…" per ogni certificato
#
# Segreti: /root/.cloudflare.env (CF_API_TOKEN, CF_ORIGIN_CA_KEY, come sui
# Plesk; scripts/rotate-cloudflare-env.sh nella repo di configurazione).
# Informazioni su stdout; errori su stderr con uscita 1.
# =============================================
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

CERT_DIR = "/etc/haproxy/certs"
DOMAINS_MAP = "/etc/haproxy/maps/domains.map"
ENV_FILE = "/root/.cloudflare.env"
API = "https://api.cloudflare.com/client/v4"
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
BACKUP_DIR = "/var/backups/haproxy/certs"
FILE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,250}\.pem$")


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def secrets():
    env = {}
    try:
        for line in open(ENV_FILE):
            m = re.match(r'^\s*(?:export\s+)?([A-Z_]+)=["\']?(.*?)["\']?\s*$', line)
            if m:
                env[m.group(1)] = m.group(2)
    except OSError:
        die(f"Credenziali Cloudflare mancanti: {ENV_FILE}")
    if not env.get("CF_API_TOKEN") or not env.get("CF_ORIGIN_CA_KEY"):
        die(f"CF_API_TOKEN o CF_ORIGIN_CA_KEY non impostati in {ENV_FILE}")
    return env


def call(method, path, *, token=None, service_key=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if service_key:
        headers["X-Auth-User-Service-Key"] = service_key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            res = json.load(e)
        except ValueError:
            die(f"Cloudflare: HTTP {e.code} su {method} {path}")
    except (urllib.error.URLError, TimeoutError) as e:
        die(f"Cloudflare non raggiungibile: {e}")
    if not res.get("success"):
        errs = "; ".join(f"{x.get('code')}: {x.get('message')}" for x in res.get("errors", []))
        die(f"Cloudflare: {errs or 'errore sconosciuto'}")
    return res


def normalize(domain):
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not DOMAIN_RE.match(d):
        die(f"Nome di dominio non valido: {domain}")
    return d


# Zona: il suffisso più lungo del dominio che esiste su Cloudflare
# (funziona anche con .co.uk, .com.br…)
def find_zone(domain, token):
    cand = domain
    while "." in cand:
        res = call("GET", "/zones?" + urllib.parse.urlencode({"name": cand}), token=token)
        if res.get("result"):
            return cand, res["result"][0]["id"]
        cand = cand.split(".", 1)[1]
    die(f"Nessuna zona Cloudflare per {domain}")


def cert_name(domain, zone):
    rest = domain[: -len(zone)].rstrip(".")
    return zone if not rest or "." not in rest else domain


def cert_names(path):
    out = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", path],
                         capture_output=True, text=True).stdout
    return [n.lower() for n in re.findall(r"DNS:([^,\s]+)", out)]


def cert_body(pem_text):
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_text, re.S)
    return re.sub(r"\s", "", m.group(1)) if m else ""


def covers(names, domain):
    parent = domain.split(".", 1)[1] if "." in domain else ""
    return any(n == domain or n == "*." + parent for n in names)


def pem_files():
    return sorted(f for f in os.listdir(CERT_DIR) if f.endswith(".pem") and not f.startswith("."))


def check_file(name):
    if not FILE_RE.match(name) or not os.path.isfile(os.path.join(CERT_DIR, name)):
        die(f"Certificato non trovato: {name}")
    return os.path.join(CERT_DIR, name)


def cmd_create(domain):
    env = secrets()
    domain = normalize(domain)
    zone, _ = find_zone(domain, env["CF_API_TOKEN"])
    name = cert_name(domain, zone)
    pem = f"{name}.pem"
    if os.path.exists(os.path.join(CERT_DIR, pem)):
        print(f"EXISTS {pem}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        key, csr = os.path.join(tmp, "key.pem"), os.path.join(tmp, "req.csr")
        r = subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", key, "-out", csr, "-subj", f"/CN=*.{name}",
                            "-addext", f"subjectAltName=DNS:{name},DNS:*.{name}"],
                           capture_output=True, text=True)
        if r.returncode:
            die(f"openssl: {r.stderr.strip()}")
        res = call("POST", "/certificates", service_key=env["CF_ORIGIN_CA_KEY"], body={
            "hostnames": [name, f"*.{name}"],
            "requested_validity": 5475,
            "request_type": "origin-rsa",
            "csr": open(csr).read(),
        })
        cert = res["result"]["certificate"]
        # PEM combinato per HAProxy: certificato e poi chiave
        new = os.path.join(CERT_DIR, f".{pem}.new")
        fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(cert.rstrip("\n") + "\n" + open(key).read())
    print(f"NEW {pem}")


def cmd_strict(domain):
    env = secrets()
    zone, zid = find_zone(normalize(domain), env["CF_API_TOKEN"])
    cur = call("GET", f"/zones/{zid}/settings/ssl", token=env["CF_API_TOKEN"])["result"]["value"]
    if cur != "strict":
        call("PATCH", f"/zones/{zid}/settings/ssl", token=env["CF_API_TOKEN"], body={"value": "strict"})
        print(f"SSL Full (strict) impostato su {zone} (era {cur})")


def cmd_used(name):
    path = check_file(name)
    mine = cert_names(path)
    others = [cert_names(os.path.join(CERT_DIR, f)) for f in pem_files() if f != name]
    domains = []
    for line in open(DOMAINS_MAP):
        parts = line.split()
        if parts and not parts[0].startswith("#"):
            domains.append(parts[0])
    for d in domains:
        if covers(mine, d) and not any(covers(o, d) for o in others):
            print(d)


def cmd_revoke(path):
    env = secrets()
    real = os.path.realpath(path)
    if os.path.dirname(real) not in (CERT_DIR, BACKUP_DIR) or not os.path.isfile(real):
        die(f"Certificato non trovato: {path}")
    name = os.path.basename(real)
    body = cert_body(open(path).read())
    names = [n for n in cert_names(path) if not n.startswith("*.")] or [n[2:] for n in cert_names(path)]
    if not names:
        die(f"{name}: nessun nome nel certificato")
    _, zid = find_zone(names[0], env["CF_API_TOKEN"])
    res = call("GET", "/certificates?" + urllib.parse.urlencode({"zone_id": zid}),
               service_key=env["CF_ORIGIN_CA_KEY"])
    for c in res.get("result", []):
        if cert_body(c.get("certificate", "")) == body:
            call("DELETE", f"/certificates/{c['id']}", service_key=env["CF_ORIGIN_CA_KEY"])
            print(f"revocato su Cloudflare ({c['id']})")
            return
    print("attenzione: certificato non trovato tra quelli Origin CA della zona, non revocato")


def cmd_list():
    for f in pem_files():
        path = os.path.join(CERT_DIR, f)
        end = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", path],
                             capture_output=True, text=True).stdout.strip().removeprefix("notAfter=")
        iso = subprocess.run(["date", "-u", "-d", end, "+%Y-%m-%d"], capture_output=True,
                             text=True).stdout.strip() if end else ""
        print(f"{f}|{iso}|{' '.join(cert_names(path))}")


if __name__ == "__main__":
    cmds = {"create": cmd_create, "strict": cmd_strict, "used": cmd_used, "revoke": cmd_revoke}
    if len(sys.argv) == 2 and sys.argv[1] == "list":
        cmd_list()
    elif len(sys.argv) == 3 and sys.argv[1] in cmds:
        cmds[sys.argv[1]](sys.argv[2])
    else:
        die("uso: cf-certs.py create|strict <dominio> | used <file.pem> | revoke <percorso> | list")

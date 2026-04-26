# HAProxy Manager

Lightweight web interface for managing HAProxy map files, written in Rust.

## Features

- Authentication with session tokens (UUID v4)
- CRUD operations for domains and backends
- Bulk update for multiple domains
- Dashboard with statistics
- Operation logging (ADD, UPDATE, DELETE, BULK, RELOAD)
- HAProxy configuration reload
- Dark theme responsive UI

## Quick Start

### Build
```bash
git clone https://github.com/faghy/haproxy-manager.git
cd haproxy-manager
cargo build --release
```
### Build
sudo mkdir -p /etc/haproxy/maps /opt/haproxy-manager/ui
sudo cp ui/index.html /opt/haproxy-manager/ui/
sudo touch /var/log/haproxy-manager.log

Configure HAProxy
Add to /etc/haproxy/haproxy.cfg:
map-file /etc/haproxy/maps/domains.map

frontend web
    bind *:80
    mode http
    use_backend %[req.hdr(host),lower,map_dom(/etc/haproxy/maps/domains.map, default-backend)]

backend default-backend
    server default 127.0.0.1:8081 check

### Run
sudo ./target/release/haproxy-manager


Open browser: http://localhost:8080

### API Endpoints
Method	  Endpoint	            Description
POST	  /auth/login	            Get session token
POST	  /auth/logout	          Invalidate session
GET	    /api/domains	          List all domains
POST	  /api/domains	          Add domain
PUT	    /api/domains/{domain}	  Update domain
DELETE	/api/domains/{domain}	  Delete domain
POST	  /api/domains/bulk	Bulk  update
GET	    /api/backends	List      backends
GET	    /api/haproxy/status	    HAProxy status
POST	  /api/haproxy/reload	    Reload HAProxy
GET	    /api/logs	              Get operation logs

## Systemd Service
[Unit]
Description=HAProxy Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/haproxy-manager
ExecStart=/opt/haproxy-manager/target/release/haproxy-manager
Restart=always

[Install]
WantedBy=multi-user.target

## Security Notes
    Change the default password in main.rs before production

    Run behind HTTPS (nginx, HAProxy, or Cloudflare Tunnel)

    Restrict access via firewall to internal/VPN network only

## License
MIT

## Author
** faghy **

# Interactive Fail2ban & Cowrie Honeypot Dashboard

An interactive, real-time threat intelligence dashboard featuring a live 3D globe (built with Globe.gl) and detailed connection metrics. It visualizes attempts against both the **Cowrie SSH Honeypot (Port 22)** and brute-force/port-scans on your **Administrative SSH port (Port 2222)** by tailing `/var/log/auth.log` and `/opt/cowrie/var/log/cowrie/cowrie.json`.

Built with FastAPI (Python) and Vanilla HTML5/CSS/JavaScript with HTTP Basic Authentication.

---

## Features
- **Live 3D Globe Visualization:** Renders inbound attacks as animated arcs firing from attacker GeoIP locations straight to your server.
- **Unified Event Feed:** Real-time log console showing timestamps, ports, IPs, country codes, usernames, and passwords (where logged).
- **Security-First Masking:** Automatically masks passwords for attempts made on your administrative port (2222) to avoid leaks, while displaying raw password attempts for the honeypot (22).
- **Session Analyzer & Replay:** Reconstruct and replay terminal sessions of honeypot attackers step-by-step.
- **Fail2ban Integration:** Displays active bans, jail counts, and metrics pulled directly from your local fail2ban instance.
- **Built-in Security:** Secured with HTTP Basic Authentication out-of-the-box.

---

## System Architecture

```mermaid
flowchart TD
    Attacker[Attacker / Scanner] -->|Port 22| FW_NAT{VM Firewall / NAT}
    Attacker -->|Port 2222| Real_SSH[Real SSH Daemon]
    
    FW_NAT -->|Redirects to 22222| Cowrie[Cowrie Honeypot]
    
    Real_SSH -->|Logs failed logins| AuthLog[/var/log/auth.log]
    Cowrie -->|Logs connections & commands| CowrieLog[/opt/cowrie/var/log/cowrie/cowrie.json]
    
    Dashboard[FastAPI Dashboard Service] -->|Tails via watchdog| AuthLog
    Dashboard -->|Tails via watchdog| CowrieLog
    
    Nginx[Nginx Reverse Proxy] -->|Proxies /fail2ban/| Dashboard
    Browser[Admin Browser] -->|Basic Auth| Nginx
```

---

## Complete Step-by-Step Setup Guide

Follow this guide to deploy your own honeypot, configure firewall redirection, set up Nginx with SSL, and run this interactive dashboard.

### 1. Configure Domain & Dynamic DNS (DuckDNS)
If your server has a dynamic IP, use DuckDNS (or any other dynamic DNS provider) to map a hostname (e.g., `yourhost.duckdns.org`) to your public IP.
1. Sign up on [DuckDNS](https://www.duckdns.org/).
2. Create a domain.
3. Set up a cron job on your server to update your IP periodically:
   ```bash
   mkdir -p ~/duckdns
   cat << 'EOF' > ~/duckdns/duck.sh
   echo url="https://www.duckdns.org/update?domains=YOUR_DOMAIN&token=YOUR_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -
   EOF
   chmod 700 ~/duckdns/duck.sh
   # Add to crontab: */5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
   ```

### 2. Move Administrative SSH Port
We want the standard SSH port (`22`) to host the honeypot, so we must relocate your administrative SSH daemon to `2222`.
1. Edit `/etc/ssh/sshd_config`:
   ```text
   Port 2222
   ```
2. Restart SSH daemon:
   ```bash
   sudo systemctl restart sshd
   ```
   *Warning: Open a new terminal tab to verify your SSH connection to port 2222 works before closing your active session!*

### 3. Install & Configure Cowrie Honeypot
Cowrie is a medium-interaction SSH honeypot designed to log brute-force attacks and shell interactions.
1. Install dependencies:
   ```bash
   sudo apt-get update
   sudo apt-get install git python3-venv libssl-dev libffi-dev build-essential libpython3-dev -y
   ```
2. Create a non-privileged `cowrie` user:
   ```bash
   sudo adduser --disabled-password --gecos "" cowrie
   sudo su - cowrie
   ```
3. Clone and configure Cowrie:
   ```bash
   git clone http://github.com/cowrie/cowrie.git
   cd cowrie
   python3 -m venv cowrie-env
   source cowrie-env/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   cp etc/cowrie.cfg.dist etc/cowrie.cfg
   # Exit back to your admin user
   exit
   ```
4. Start Cowrie:
   ```bash
   sudo su - cowrie -c "cd ~/cowrie && bin/cowrie start"
   ```
   *Cowrie by default will start up and listen on port `22222`.*

### 4. Setup VM Firewall Redirection (Port 22 -> 22222)
Since Cowrie runs as a non-root user, it cannot bind to port `22`. We redirect incoming traffic on port `22` to `22222` using `nftables` or `iptables`.

#### Using `nftables` (Recommended):
Add the following rule to your NAT table:
```text
table ip nat {
    chain PREROUTING {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport 22 counter redirect to :22222
    }
    chain OUTPUT {
        type nat hook output priority dstnat; policy accept;
        tcp dport 22 counter redirect to :22222
    }
}
```

#### Using `iptables`:
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 22222
sudo iptables -t nat -A OUTPUT -p tcp --dport 22 -j REDIRECT --to-port 22222
```

Make sure your public firewall (e.g. OCI Security List or AWS Security Group) allows inbound TCP port `22` and port `2222` from everywhere.

---

### 5. Install and Configure Nginx with SSL (Certbot)
1. Install Nginx and Certbot:
   ```bash
   sudo apt install nginx certbot python3-certbot-nginx -y
   ```
2. Obtain an SSL Certificate:
   ```bash
   sudo certbot --nginx -d yourhost.duckdns.org
   ```
3. Open your Nginx site configuration `/etc/nginx/sites-available/default` and add the `/fail2ban/` location block to your server config:
   ```nginx
   server {
       listen 443 ssl http2;
       server_name yourhost.duckdns.org;

       # ... standard SSL configurations ...

       location ^~ /fail2ban/ {
           proxy_pass http://127.0.0.1:8765/;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_http_version 1.1;

           # SSE support (long-lived connection, no buffering)
           proxy_buffering off;
           proxy_cache off;
           proxy_read_timeout 86400s;
           proxy_send_timeout 86400s;
           chunked_transfer_encoding on;

           # Disable caching of proxy errors
           proxy_next_upstream error timeout http_502 http_503 http_504;
           proxy_connect_timeout 3s;
           add_header Cache-Control "no-store, no-cache, must-revalidate" always;
       }
   }
   ```
4. Reload Nginx:
   ```bash
   sudo systemctl reload nginx
   ```

---

### 6. Install & Configure the Dashboard App
1. Place the application files in `/opt/dnsmalik-dashboard/`.
2. Ensure the `ubuntu` user has permissions to read `/var/log/auth.log`. (Typically accomplished by adding `ubuntu` to the `adm` or `syslog` group, or adding read permission):
   ```bash
   sudo usermod -aG adm ubuntu
   ```
3. Download the MaxMind GeoLite2 databases (`GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`) and place them in the `/opt/dnsmalik-dashboard/geoip_db/` directory.
4. Set up a virtual environment and install dependencies:
   ```bash
   cd /opt/dnsmalik-dashboard
   python3 -m venv venv
   source venv/bin/activate
   pip install fastapi uvicorn watchdog geoip2 httpx
   ```
5. Configure HTTP Basic Authentication inside [app.py](app.py) if you wish to customize credentials:
   ```python
   correct_username = secrets.compare_digest(credentials.username, "fail2ban")
   correct_password = secrets.compare_digest(credentials.password, "hello")
   ```

6. Create a Systemd Service for the dashboard `/etc/systemd/system/dnsmalik-dashboard.service`:
   ```ini
   [Unit]
   Description=dnsmalik.fail2ban dashboard backend
   After=network.target

   [Service]
   User=ubuntu
   WorkingDirectory=/opt/dnsmalik-dashboard
   ExecStart=/opt/dnsmalik-dashboard/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8765 --workers 1 --log-level info
   Restart=always
   RestartSec=3

   [Install]
   WantedBy=multi-user.target
   ```
7. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable dnsmalik-dashboard.service
   sudo systemctl start dnsmalik-dashboard.service
   ```

Now, visit `https://yourhost.duckdns.org/fail2ban/`. You will be prompted to log in with username `fail2ban` and password `hello`, after which the live threat map dashboard will load!

---

## License
MIT License. Feel free to modify and deploy!

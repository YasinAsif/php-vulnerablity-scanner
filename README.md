# Tezhost PHP2Shell Vulnerability Scanner (PHPscanner.tezhost.com)

Production-ready web application and API for auditing remote infrastructure against **PHP2Shell (CVE-2026-109618 & CVE-2026-109619)** multipart memory exhaustion vulnerabilities.

Inspired by Assetnote's security research and designed with a high-end, modern **Light Mode enterprise UI** for Tezhost Hosting & Cloud Services.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Client Web Browser (UI)   |
                      |  Light Mode / Tailored UX   |
                      +--------------+--------------+
                                     |
               HTTP GET / (Static)   |   SSE Stream & POST /api/scan
                                     v
                 +-----------------------------------+
                 |    Nginx Reverse Proxy & SSL      |
                 |      PHPscanner.tezhost.com       |
                 +-----------------+-----------------+
                                   |
                                   v
                 +-----------------------------------+
                 |        FastAPI Core Server        |
                 |       (Uvicorn Multi-worker)      |
                 +-----------------+-----------------+
                                   |
            +----------------------+----------------------+
            |                                             |
            v                                             v
+-----------------------+                     +-----------------------+
|  SSRF & IP Guard      |                     |  Assetnote Progressive|
|  Blocks 127.0.0.1,    |                     |  Scanner Engine       |
|  RFC1918 & Cloud Meta |                     |  62-level Hash Probes |
+-----------------------+                     +-----------------------+
```

---

## Key Features That Exceed Other Tools

1. **Enterprise Light-Mode Design**: Clean, crisp typography (Inter + JetBrains Mono), responsive layout, and zero dark-mode eye strain.
2. **Interactive Live Payload Telemetry**: Visualizes multipart packets flowing across the wire, with real-time PHP heap allocation gauges.
3. **SSRF Hardening**: Pre-flight DNS validation strictly rejects loopback, RFC 1918 private subnets, link-local, and cloud metadata (`169.254.169.254`) addresses.
4. **Real-time Diagnostic Terminal**: Streams live stage-by-stage probe events with millisecond timestamps and color-coded status badges via Server-Sent Events (SSE).
5. **Instant Demo Presets**: Includes one-click test presets for Vulnerable, Patched, and WAF-protected targets so clients and reviewers can evaluate results instantly.
6. **Actionable Remediation Suite**: Instant copy-paste mitigation directives for Nginx reverse proxies, Apache HTTPD, PHP packages, and Docker containers.
7. **Export & Audit Logging**: 1-click JSON report generation and printable PDF layout.

---

## Quick Start (Local Run)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 3. Open in your browser
http://localhost:8000
```

---

## 1-Click Production Deployment (Docker Compose)

```bash
docker compose up -d --build
```

---

## Nginx VirtualHost Configuration (`PHPscanner.tezhost.com`)

```nginx
server {
    listen 80;
    server_name PHPscanner.tezhost.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name PHPscanner.tezhost.com;

    ssl_certificate /etc/letsencrypt/live/PHPscanner.tezhost.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/PHPscanner.tezhost.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Crucial for SSE Live Streaming
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
    }
}
```

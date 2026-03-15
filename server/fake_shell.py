import random
from server.mitre_mapper import map_command_to_technique, extract_urls

FAKE_HOSTNAME = "ubuntu-prod-01"
FAKE_IP = "10.0.2.15"
FAKE_USER = "root"

FAKE_RESPONSES = {
    "whoami":           "root",
    "id":               "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a":         f"Linux {FAKE_HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP Thu Nov 2 15:36:04 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname":            "Linux",
    "hostname":         FAKE_HOSTNAME,
    "pwd":              "/root",
    "cat /etc/os-release": """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
""",
    "cat /etc/passwd":  """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
""",
    "ls":               "snap  .bashrc  .profile  .ssh  .cache",
    "ls -la":           """total 36
drwx------  5 root root 4096 Mar 12 09:23 .
drwxr-xr-x 20 root root 4096 Mar 12 09:21 ..
-rw-r--r--  1 root root 3106 Mar 12 09:21 .bashrc
drwx------  3 root root 4096 Mar 12 09:23 .cache
-rw-r--r--  1 root root  161 Mar 12 09:21 .profile
drwx------  2 root root 4096 Mar 12 09:23 .ssh
""",
    "ls -la /":         """total 64
drwxr-xr-x  20 root root 4096 Mar 12 09:21 .
drwxr-xr-x  20 root root 4096 Mar 12 09:21 ..
drwxr-xr-x   2 root root 4096 Mar 12 09:21 bin
drwxr-xr-x   3 root root 4096 Mar 12 09:21 boot
drwxr-xr-x   2 root root 4096 Mar 12 09:21 etc
drwxr-xr-x   3 root root 4096 Mar 12 09:21 home
drwxr-xr-x   2 root root 4096 Mar 12 09:21 var
""",
    "ifconfig":         f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {FAKE_IP}  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
""",
    "ip addr":          f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet {FAKE_IP}/24 brd 10.0.2.255 scope global eth0
""",
    "ps aux":           """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 225888  9416 ?        Ss   09:21   0:01 /sbin/init
root       423  0.0  0.2  72296 17840 ?        Ss   09:21   0:00 /usr/sbin/sshd
root       891  0.0  0.1  13352  8204 ?        Ss   09:21   0:00 /usr/sbin/cron
www-data   923  0.0  0.3 204496 14520 ?        S    09:21   0:00 /usr/sbin/apache2
""",
    "free -m":          """               total        used        free      shared  buff/cache   available
Mem:            7982        1823        4901         234        1258        5924
Swap:           2047           0        2047
""",
    "df -h":            """Filesystem      Size  Used Avail Use% Mounted on
udev            3.9G     0  3.9G   0% /dev
tmpfs           799M  1.1M  798M   1% /run
/dev/sda1        50G   12G   36G  25% /
""",
    "netstat -an":      """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
""",
    "w":                f"""09:23:45 up 2:02,  1 user,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    {FAKE_IP}        09:21    0.00s  0.03s  0.00s w
""",
    "history":          """    1  apt-get update
    2  apt-get upgrade -y
    3  ufw enable
    4  ufw allow 22/tcp
    5  systemctl restart nginx
    6  ls -la
""",
    "cat /etc/crontab": """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
""",
    "env":              """SHELL=/bin/bash
PWD=/root
HOME=/root
USER=root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
""",
    "cat /proc/cpuinfo":"""processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model name      : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
cpu MHz         : 2400.072
cache size      : 30720 KB
""",
}

PROMPT = f"root@{FAKE_HOSTNAME}:~# "

class FakeShell:
    def __init__(self, session_id: int, source_ip: str):
        self.session_id = session_id
        self.source_ip = source_ip
        self.detected_techniques = []
        self.malware_urls = []
        self.command_count = 0

    def handle_command(self, command: str) -> str:
        command = command.strip()
        if not command:
            return PROMPT

        self.command_count += 1

        technique = map_command_to_technique(command)
        if technique and technique not in self.detected_techniques:
            self.detected_techniques.append(technique)

        urls = extract_urls(command)
        self.malware_urls.extend(urls)

        response = self._generate_response(command)

        from storage.db import log_shell_command
        log_shell_command(
            session_id=self.session_id,
            command=command,
            response=response,
            technique_id=technique["id"] if technique else None,
            technique_name=technique["name"] if technique else None,
            flagged=1 if technique and technique["risk"] in ["high", "critical"] else 0
        )

        return response + "\n" + PROMPT

    def _generate_response(self, command: str) -> str:
        if command in FAKE_RESPONSES:
            return FAKE_RESPONSES[command]

        cmd_lower = command.lower()

        if cmd_lower.startswith(("wget ", "curl ")):
            url = command.split()[-1]
            filename = url.split("/")[-1] or "index.html"
            return f"--2026-03-12 09:23:45--  {url}\nResolving host... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4096\nSaving to: '{filename}'\n{filename} 100%[===================>] 4.00K  --.-KB/s    in 0s\n2026-03-12 09:23:45 (45.2 MB/s) - '{filename}' saved [4096/4096]"

        if cmd_lower.startswith("chmod "):
            return ""

        if cmd_lower.startswith("cd "):
            return ""

        if cmd_lower.startswith("echo "):
            content = command[5:]
            if ">>" in content:
                return ""
            return content.replace('"', '').replace("'", "")

        if cmd_lower.startswith("cat "):
            filepath = command[4:].strip()
            if filepath in FAKE_RESPONSES:
                return FAKE_RESPONSES[filepath]
            return f"cat: {filepath}: No such file or directory"

        if cmd_lower.startswith("rm "):
            return ""

        if cmd_lower.startswith("mkdir "):
            return ""

        if cmd_lower.startswith("crontab"):
            return ""

        if cmd_lower.startswith(("useradd ", "adduser ")):
            username = command.split()[-1]
            return f"Adding user '{username}' ...\nAdding new group '{username}' (1001) ...\nAdding new user '{username}' (1001) with group '{username}' ...\nCreating home directory '/home/{username}' ..."

        if cmd_lower.startswith("passwd"):
            return "passwd: password updated successfully"

        if cmd_lower.startswith("systemctl "):
            return ""

        if cmd_lower.startswith("ping "):
            target = command.split()[1] if len(command.split()) > 1 else "localhost"
            return f"PING {target}: 56 data bytes\n64 bytes from {target}: icmp_seq=0 ttl=64 time=0.423 ms\n64 bytes from {target}: icmp_seq=1 ttl=64 time=0.387 ms"

        if cmd_lower.startswith("ssh "):
            return "ssh: connect to host: Connection timed out"

        if cmd_lower.startswith(("python", "python3")):
            return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]\nType 'help', 'credits' or 'license' for more information.\n>>>"

        if "history" in cmd_lower and "-c" in cmd_lower:
            return ""

        if cmd_lower.startswith("export "):
            return ""

        if any(m in cmd_lower for m in ["xmrig", "minerd", "cgminer"]):
            return f"[2026-03-12 09:23:45] Starting mining operation...\n[2026-03-12 09:23:45] Connecting to pool...\n[2026-03-12 09:23:46] Connected to stratum+tcp://pool.minexmr.com:4444\n[2026-03-12 09:23:46] Mining at 0.00 H/s"

        cmd_name = command.split()[0] if command.split() else command
        return f"bash: {cmd_name}: command not found"

    def get_session_summary(self) -> dict:
        from server.mitre_mapper import assess_session_risk
        return {
            "total_commands": self.command_count,
            "detected_techniques": self.detected_techniques,
            "malware_urls": self.malware_urls,
            "risk_level": assess_session_risk(self.detected_techniques),
            "mitre_ids": [t["id"] for t in self.detected_techniques]
        }

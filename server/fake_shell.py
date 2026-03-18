"""
Stateful Fake Shell — looks completely real to attackers.
Tracks current directory, filesystem changes, command history.
Never executes any real commands.
"""

import random
from server.mitre_mapper import map_command_to_technique, extract_urls

FAKE_HOSTNAME = "ubuntu-prod-01"
FAKE_IP = "10.0.2.15"

# Fake filesystem — directory: [contents]
FAKE_FILESYSTEM = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "srv", "sys", "tmp", "usr", "var"],
    "/root": ["snap", ".bashrc", ".profile", ".ssh", ".cache", ".bash_history"],
    "/root/.ssh": ["authorized_keys", "known_hosts"],
    "/root/.aws": ["credentials", "config"],
    "/tmp": [],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "crontab", "os-release", "ssh", "mysql", "nginx"],
    "/etc/ssh": ["sshd_config", "ssh_config"],
    "/var": ["log", "www", "lib", "cache"],
    "/var/log": ["syslog", "auth.log", "kern.log", "nginx", "mysql"],
    "/var/www": ["html"],
    "/var/www/html": ["index.html", "wp-config.php", "config.php", ".htaccess"],
    "/home": ["ubuntu"],
    "/home/ubuntu": [".bashrc", ".profile", ".ssh"],
    "/opt": [],
    "/usr": ["bin", "lib", "local", "share"],
    "/proc": ["cpuinfo", "meminfo", "version"],
}

# Fake file contents
FAKE_FILE_CONTENTS = {
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash""",
    "/etc/shadow": """root:$6$xyz$fakehashfakehashfakehash:19000:0:99999:7:::
ubuntu:$6$abc$anotherfakehash:19000:0:99999:7:::
www-data:!:19000:0:99999:7:::""",
    "/etc/hosts": """127.0.0.1 localhost
10.0.2.15 ubuntu-prod-01
10.0.2.1  gateway
10.0.2.20 db-server
10.0.2.30 backup-server""",
    "/etc/hostname": "ubuntu-prod-01",
    "/etc/os-release": """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04" """,
    "/root/.bashrc": """# ~/.bashrc: executed by bash(1) for non-login shells.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'""",
    "/root/.bash_history": """apt-get update
systemctl restart nginx
mysql -u root -p
cd /var/www/html
ls -la
cat wp-config.php
exit""",
    "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB admin@prod",
    "/root/.aws/credentials": """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1""",
    "/root/.aws/config": """[default]
region = us-east-1
output = json""",
    "/var/www/html/wp-config.php": """<?php
$db_host = 'localhost';
$db_user = 'wpuser';
$db_pass = 'Str0ngP@ssw0rd!';
$db_name = 'wordpress_db';
define('AUTH_KEY', 'fakesecretkey12345');
define('SECURE_AUTH_KEY', 'anotherfakekey67890');
?>""",
    "/var/www/html/config.php": """<?php
$db_host = 'localhost';
$db_user = 'webapp';
$db_pass = 'S3cur3P@ss!';
$db_name = 'production_db';
?>""",
    "/etc/crontab": """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
0 2 * * 0 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )""",
    "/proc/cpuinfo": """processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model name      : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
cpu MHz         : 2400.072
cache size      : 30720 KB""",
    "/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Thu Nov 2 15:36:04 UTC 2023",
}

def _format_ls(contents: list, long: bool = False) -> str:
    if not contents:
        return ""
    if not long:
        return "  ".join(contents)
    lines = ["total " + str(len(contents) * 4)]
    for item in contents:
        lines.append(f"drwxr-xr-x 2 root root 4096 Mar 12 09:23 {item}")
    return "\n".join(lines)

class FakeShell:
    def __init__(self, session_id: int, source_ip: str):
        self.session_id = session_id
        self.source_ip = source_ip
        self.detected_techniques = []
        self.malware_urls = []
        self.command_count = 0

        # State
        self.cwd = "/root"
        self.env = {
            "HOME": "/root",
            "USER": "root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "HOSTNAME": FAKE_HOSTNAME,
        }
        self.filesystem = {k: list(v) for k, v in FAKE_FILESYSTEM.items()}
        self.file_contents = dict(FAKE_FILE_CONTENTS)
        self.command_history = []
        self.crontabs = []

    @property
    def prompt(self):
        display_cwd = "~" if self.cwd == "/root" else self.cwd
        return f"root@{FAKE_HOSTNAME}:{display_cwd}# "

    def _resolve_path(self, path: str) -> str:
        if not path or path == "~":
            return "/root"
        if path.startswith("~/"):
            path = "/root/" + path[2:]
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        # Normalize
        parts = []
        for part in path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        return "/" + "/".join(parts) if parts else "/"

    def handle_command(self, command: str) -> str:
        command = command.strip()
        if not command:
            return self.prompt

        # Expand environment variables
        for key, val in self.env.items():
            command = command.replace(f"${key}", val)
            command = command.replace(f"${{{key}}}", val)

        self.command_count += 1
        self.command_history.append(command)

        # Map to MITRE technique
        technique = map_command_to_technique(command)
        if technique and technique not in self.detected_techniques:
            self.detected_techniques.append(technique)

        # Extract malware URLs
        urls = extract_urls(command)
        self.malware_urls.extend(urls)

        # Handle pipes
        if "|" in command and not command.startswith("echo"):
            parts = command.split("|")
            result = self._execute(parts[0].strip())
            for part in parts[1:]:
                part = part.strip()
                if part.startswith("grep "):
                    search = part[5:].strip().strip('"\'')
                    result = "\n".join(
                        line for line in result.split("\n")
                        if search.lower() in line.lower()
                    )
                elif part in ("wc -l", "wc"):
                    result = str(len([l for l in result.split("\n") if l]))
                elif part == "head":
                    result = "\n".join(result.split("\n")[:10])
                elif part == "tail":
                    result = "\n".join(result.split("\n")[-10:])
                elif part.startswith("head -"):
                    n = int(part.split("-")[1].strip())
                    result = "\n".join(result.split("\n")[:n])
                elif part.startswith("tail -"):
                    n = int(part.split("-")[1].strip())
                    result = "\n".join(result.split("\n")[-n:])
                elif part == "sort":
                    lines = result.split("\n")
                    result = "\n".join(sorted(lines))
                elif part == "uniq":
                    lines = result.split("\n")
                    result = "\n".join(dict.fromkeys(lines))
        else:
            result = self._execute(command)

        # Log to database
        from storage.db import log_shell_command
        log_shell_command(
            session_id=self.session_id,
            command=command,
            response=result,
            technique_id=technique["id"] if technique else None,
            technique_name=technique["name"] if technique else None,
            flagged=1 if technique and technique["risk"] in ["high", "critical"] else 0
        )

        return result + "\n" + self.prompt

    def _execute(self, command: str) -> str:
        cmd = command.strip()
        if not cmd:
            return ""

        parts = cmd.split()
        base = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # Handle sudo — strip and re-execute
        if base == "sudo":
            if args:
                if args[0] == "-l":
                    return """Matching Defaults entries for root:
    env_reset, mail_badpass
User root may run the following commands:
    (ALL : ALL) ALL"""
                if args[0] == "-i" or args[0] == "su":
                    return ""
                return self._execute(" ".join(args))
            return ""

        # cd
        if base == "cd":
            target = args[0] if args else "/root"
            resolved = self._resolve_path(target)
            if resolved in self.filesystem:
                self.cwd = resolved
                return ""
            return f"bash: cd: {target}: No such file or directory"

        # pwd
        if base == "pwd":
            return self.cwd

        # ls
        if base == "ls":
            long = "-l" in cmd or "-la" in cmd or "-al" in cmd
            all_files = "-a" in cmd or "-la" in cmd or "-al" in cmd
            target_dir = self.cwd
            for arg in args:
                if not arg.startswith("-"):
                    target_dir = self._resolve_path(arg)
                    break
            contents = self.filesystem.get(target_dir, None)
            if contents is None:
                return f"ls: cannot access '{target_dir}': No such file or directory"
            display = list(contents)
            if all_files:
                display = [".", ".."] + display
            if not long:
                return "  ".join(display) if display else ""
            lines = [f"total {len(display) * 4}"]
            for item in display:
                if item in [".", ".."]:
                    lines.append(f"drwxr-xr-x 2 root root 4096 Mar 12 09:23 {item}")
                elif item.startswith("."):
                    lines.append(f"-rw-r--r-- 1 root root  220 Mar 12 09:23 {item}")
                else:
                    lines.append(f"drwxr-xr-x 2 root root 4096 Mar 12 09:23 {item}")
            return "\n".join(lines)

        # mkdir
        if base == "mkdir":
            if not args:
                return "mkdir: missing operand"
            for arg in args:
                if arg.startswith("-"):
                    continue
                new_dir = self._resolve_path(arg)
                parent = "/".join(new_dir.split("/")[:-1]) or "/"
                dir_name = new_dir.split("/")[-1]
                if parent in self.filesystem:
                    if dir_name not in self.filesystem[parent]:
                        self.filesystem[parent].append(dir_name)
                    self.filesystem[new_dir] = []
            return ""

        # rm
        if base == "rm":
            if not args:
                return "rm: missing operand"
            for arg in args:
                if arg.startswith("-"):
                    continue
                target = self._resolve_path(arg)
                parent = "/".join(target.split("/")[:-1]) or "/"
                name = target.split("/")[-1]
                if parent in self.filesystem and name in self.filesystem[parent]:
                    self.filesystem[parent].remove(name)
                    if target in self.filesystem:
                        del self.filesystem[target]
            return ""

        # touch
        if base == "touch":
            if not args:
                return ""
            for arg in args:
                target = self._resolve_path(arg)
                parent = "/".join(target.split("/")[:-1]) or "/"
                name = target.split("/")[-1]
                if parent in self.filesystem and name not in self.filesystem[parent]:
                    self.filesystem[parent].append(name)
                    self.file_contents[target] = ""
            return ""

        # cat
        if base == "cat":
            if not args:
                return ""
            filepath = self._resolve_path(args[0])
            if filepath in self.file_contents:
                return self.file_contents[filepath]
            # Check by name only
            for key in self.file_contents:
                if key.endswith("/" + args[0]):
                    return self.file_contents[key]
            return f"cat: {args[0]}: No such file or directory"

        # echo
        if base == "echo":
            content = " ".join(args)
            # Handle redirect
            if ">>" in cmd:
                parts_r = cmd.split(">>", 1)
                text = parts_r[0].replace("echo", "").strip().strip('"\'')
                filepath = self._resolve_path(parts_r[1].strip())
                self.file_contents[filepath] = self.file_contents.get(filepath, "") + text + "\n"
                parent = "/".join(filepath.split("/")[:-1]) or "/"
                name = filepath.split("/")[-1]
                if parent in self.filesystem and name not in self.filesystem[parent]:
                    self.filesystem[parent].append(name)
                return ""
            if ">" in cmd:
                parts_r = cmd.split(">", 1)
                text = parts_r[0].replace("echo", "").strip().strip('"\'')
                filepath = self._resolve_path(parts_r[1].strip())
                self.file_contents[filepath] = text + "\n"
                parent = "/".join(filepath.split("/")[:-1]) or "/"
                name = filepath.split("/")[-1]
                if parent in self.filesystem and name not in self.filesystem[parent]:
                    self.filesystem[parent].append(name)
                return ""
            return content.strip('"\'')

        # whoami
        if base == "whoami":
            return "root"

        # id
        if base == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"

        # uname
        if base == "uname":
            if "-a" in cmd:
                return f"Linux {FAKE_HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP Thu Nov 2 15:36:04 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            return "Linux"

        # hostname
        if base == "hostname":
            return FAKE_HOSTNAME

        # env/printenv
        if base in ("env", "printenv"):
            return "\n".join(f"{k}={v}" for k, v in self.env.items())

        # export
        if base == "export":
            if args:
                for arg in args:
                    if "=" in arg:
                        k, v = arg.split("=", 1)
                        self.env[k] = v.strip('"\'')
            return ""

        # history
        if base == "history":
            if "-c" in cmd:
                self.command_history = []
                return ""
            lines = []
            for i, cmd_h in enumerate(self.command_history[-50:], 1):
                lines.append(f"  {i:3}  {cmd_h}")
            return "\n".join(lines) if lines else ""

        # ps
        if base == "ps":
            return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 225888  9416 ?        Ss   09:21   0:01 /sbin/init
root       423  0.0  0.2  72296 17840 ?        Ss   09:21   0:00 /usr/sbin/sshd
root       891  0.0  0.1  13352  8204 ?        Ss   09:21   0:00 /usr/sbin/cron
www-data   923  0.0  0.3 204496 14520 ?        S    09:21   0:00 /usr/sbin/apache2"""

        # free
        if base == "free":
            return """               total        used        free      shared  buff/cache   available
Mem:            7982        1823        4901         234        1258        5924
Swap:           2047           0        2047"""

        # df
        if base == "df":
            return """Filesystem      Size  Used Avail Use% Mounted on
udev            3.9G     0  3.9G   0% /dev
tmpfs           799M  1.1M  798M   1% /run
/dev/sda1        50G   12G   36G  25% /"""

        # ifconfig
        if base == "ifconfig":
            return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {FAKE_IP}  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0"""

        # ip
        if base == "ip":
            return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet {FAKE_IP}/24 brd 10.0.2.255 scope global eth0"""

        # netstat
        if base == "netstat":
            return """Proto Recv-Q Send-Q Local Address   Foreign Address  State
tcp        0      0 0.0.0.0:22      0.0.0.0:*        LISTEN
tcp        0      0 0.0.0.0:80      0.0.0.0:*        LISTEN
tcp        0      0 127.0.0.1:3306  0.0.0.0:*        LISTEN"""

        # ss
        if base == "ss":
            return """State   Recv-Q  Send-Q  Local Address:Port
LISTEN  0       128     0.0.0.0:22
LISTEN  0       128     0.0.0.0:80
LISTEN  0       128     127.0.0.1:3306"""

        # crontab
        if base == "crontab":
            if "-l" in cmd:
                return "\n".join(self.crontabs) if self.crontabs else "no crontab for root"
            if "-e" in cmd:
                return ""
            if "-r" in cmd:
                self.crontabs = []
                return ""
            return ""

        # wget/curl
        if base in ("wget", "curl"):
            url = args[-1] if args else ""
            if not url.startswith("http"):
                url = args[0] if args else "unknown"
            filename = url.split("/")[-1] or "index.html"
            if base == "wget":
                return f"--2026-03-16 09:23:45--  {url}\nResolving host... connected.\nHTTP request sent... 200 OK\nSaving to: '{filename}'\n{filename} 100%[=====>] 4.00K in 0s\n'{filename}' saved [4096]"
            else:
                return f"  % Total    % Received\n100  4096  100  4096    0     0   4096      0  0:00:01\n" + "A" * 20

        # chmod/chown
        if base in ("chmod", "chown", "chattr"):
            return ""

        # useradd/adduser
        if base in ("useradd", "adduser"):
            username = args[-1] if args else "newuser"
            return f"Adding user '{username}' ...\nCreating home directory '/home/{username}' ..."

        # passwd
        if base == "passwd":
            return "passwd: password updated successfully"

        # systemctl
        if base == "systemctl":
            action = args[0] if args else ""
            service = args[1] if len(args) > 1 else ""
            if action == "status":
                return f"● {service}.service - {service}\n   Active: active (running)"
            return ""

        # ping
        if base == "ping":
            target = args[0] if args else "localhost"
            return f"PING {target}: 56 data bytes\n64 bytes from {target}: icmp_seq=1 ttl=64 time=0.423 ms\n64 bytes from {target}: icmp_seq=2 ttl=64 time=0.387 ms"

        # ssh lateral movement
        if base == "ssh":
            return "ssh: connect to host: Connection timed out"

        # python
        if base in ("python", "python3"):
            if "-c" in cmd:
                return ""
            return "Python 3.10.12 (main, Nov 20 2023)\nType 'help' for more information.\n>>>"

        # nmap
        if base == "nmap":
            return """Starting Nmap 7.80
Nmap scan report for 10.0.2.10
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Nmap scan report for 10.0.2.20
PORT     STATE SERVICE
3306/tcp open  mysql
Nmap done: 256 IP addresses scanned in 12.34 seconds"""

        # find
        if base == "find":
            if "-perm" in cmd and "4000" in cmd:
                return """/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/su
/usr/lib/openssh/ssh-keysign"""
            if "-name" in cmd:
                return ""
            return ""

        # apt/apt-get/yum
        if base in ("apt", "apt-get", "yum", "dnf"):
            pkg = args[-1] if args else "package"
            return f"""Reading package lists... Done
Building dependency tree... Done
The following NEW packages will be installed: {pkg}
0 upgraded, 1 newly installed.
Setting up {pkg} ..."""

        # mysql
        if base == "mysql":
            return """Welcome to the MySQL monitor.
Your MySQL connection id is 8
Server version: 8.0.32 MySQL Community Server
mysql>"""

        # xmrig/mining
        if any(m in base for m in ["xmrig", "minerd", "cgminer"]):
            return f"""[2026-03-16 09:23:45] Starting miner...
[2026-03-16 09:23:45] Connecting to pool stratum+tcp://pool.minexmr.com:4444
[2026-03-16 09:23:46] Mining at 0.00 H/s"""

        # vi/vim/nano
        if base in ("vi", "vim", "nano"):
            return ""

        # w/who/last
        if base == "w":
            return f"""09:23:45 up 2:02,  1 user,  load average: 0.00
USER     TTY      FROM             LOGIN@   IDLE
root     pts/0    {FAKE_IP}        09:21    0.00s"""
        if base == "who":
            return f"root     pts/0        2026-03-16 09:21 ({FAKE_IP})"
        if base == "last":
            return f"""root     pts/0        {FAKE_IP}    Mon Mar 16 09:21   still logged in
reboot   system boot  5.15.0-91        Mon Mar 16 09:20   still running"""

        # base64
        if base == "base64":
            if "-d" in cmd or "--decode" in cmd:
                return "decoded_content_here"
            return "ZmFrZWVuY29kZWRjb250ZW50"

        # Default — command not found
        return f"bash: {base}: command not found"

    def get_session_summary(self) -> dict:
        from server.mitre_mapper import assess_session_risk
        return {
            "total_commands": self.command_count,
            "detected_techniques": self.detected_techniques,
            "malware_urls": self.malware_urls,
            "risk_level": assess_session_risk(self.detected_techniques),
            "mitre_ids": [t["id"] for t in self.detected_techniques]
        }

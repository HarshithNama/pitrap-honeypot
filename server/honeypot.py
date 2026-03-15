import socket
import threading
import paramiko
import os
import sys
import logging
import random
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import init_db, insert_attempt, create_session_tables, \
                       create_shell_session, close_shell_session
from server.enricher import enrich
from server.classifier import classify_attacker
from server.fake_shell import FakeShell, PROMPT

load_dotenv()

HOST = os.getenv("HONEYPOT_HOST", "0.0.0.0")
PORT = int(os.getenv("HONEYPOT_PORT", 22))

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

broadcast_callback = None

def set_broadcast_callback(callback):
    global broadcast_callback
    broadcast_callback = callback

class HoneypotServer(paramiko.ServerInterface):

    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_version = "Unknown"
        self.event = threading.Event()
        self.auth_attempts = 0
        self.grant_after = random.randint(3, 6)
        self.shell_granted = False
        self.last_attempt_id = None
        self.last_username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        if self.shell_granted:
            threading.Thread(
                target=self._run_fake_shell,
                args=(channel,),
                daemon=True
            ).start()
            return True
        return False

    def check_channel_pty_request(self, channel, term, width,
                                   height, pixelwidth, pixelheight, modes):
        return True

    def check_auth_password(self, username: str, password: str):
        self.auth_attempts += 1
        self.last_username = username
        print(f"[HONEYPOT] {self.client_ip} tried {username}:{password} "
              f"(attempt {self.auth_attempts}/{self.grant_after})")

        enriched = enrich(self.client_ip)
        attacker_type = classify_attacker(self.client_ip, username, password)

        attempt = {
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "username": username,
            "password": password,
            "client_version": self.client_version,
            "country": enriched["country"],
            "city": enriched["city"],
            "isp": enriched["isp"],
            "latitude": enriched["latitude"],
            "longitude": enriched["longitude"],
            "abuse_score": enriched["abuse_score"],
            "attacker_type": attacker_type
        }

        attempt_id = insert_attempt(attempt)
        self.last_attempt_id = attempt_id
        attempt["id"] = attempt_id
        attempt["timestamp"] = datetime.now().isoformat()

        if broadcast_callback:
            broadcast_callback(attempt)

        if self.auth_attempts >= self.grant_after:
            print(f"[HONEYPOT] Granting fake shell to {self.client_ip} "
                  f"after {self.auth_attempts} attempts!")
            self.shell_granted = True
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def _run_fake_shell(self, channel):
        print(f"[SHELL] Starting fake shell session for {self.client_ip}")

        session_id = create_shell_session({
            "attempt_id": self.last_attempt_id,
            "source_ip": self.client_ip,
            "username": self.last_username
        })

        fake_shell = FakeShell(session_id, self.client_ip)

        try:
            banner = (
                f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux "
                f"5.15.0-91-generic x86_64)\r\n\r\n"
                f" * Documentation:  https://help.ubuntu.com\r\n"
                f" * Management:     https://landscape.canonical.com\r\n\r\n"
                f"Last login: Fri Mar 12 08:14:22 2026 from 10.0.0.1\r\n"
            )
            channel.send(banner)
            channel.send(PROMPT)

            command_buffer = ""
            while True:
                data = channel.recv(1024)
                if not data:
                    break

                decoded = data.decode("utf-8", errors="ignore")

                for char in decoded:
                    if char in ("\r", "\n"):
                        channel.send("\r\n")
                        if command_buffer.strip():
                            response = fake_shell.handle_command(command_buffer)
                            response_formatted = response.replace("\n", "\r\n")
                            channel.send(response_formatted)
                        else:
                            channel.send(PROMPT)
                        command_buffer = ""
                    elif char == "\x7f":
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send("\b \b")
                    elif char == "\x03":
                        channel.send("^C\r\n" + PROMPT)
                        command_buffer = ""
                    elif char == "\x04":
                        channel.send("logout\r\n")
                        break
                    else:
                        command_buffer += char
                        channel.send(char)

        except Exception as e:
            print(f"[SHELL] Session error for {self.client_ip}: {e}")
        finally:
            summary = fake_shell.get_session_summary()
            close_shell_session(
                session_id=session_id,
                mitre_techniques=str(summary["mitre_ids"]),
                malware_urls=str(summary["malware_urls"]),
                risk_level=summary["risk_level"]
            )
            print(f"[SHELL] Session ended for {self.client_ip}")
            print(f"[SHELL] Commands: {summary['total_commands']}")
            print(f"[SHELL] MITRE techniques: {summary['mitre_ids']}")
            print(f"[SHELL] Risk: {summary['risk_level']}")
            if summary["malware_urls"]:
                print(f"[SHELL] Malware URLs: {summary['malware_urls']}")
            channel.close()

def generate_host_key():
    key_path = os.path.expanduser("~/.pitrap_host_key")
    if os.path.exists(key_path):
        return paramiko.RSAKey(filename=key_path)
    print("[HONEYPOT] Generating RSA host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(key_path)
    return key

def handle_connection(client_socket, client_address):
    client_ip, client_port = client_address
    print(f"[HONEYPOT] Connection from {client_ip}:{client_port}")

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        transport.add_server_key(generate_host_key())

        server = HoneypotServer(client_ip, client_port)
        transport.start_server(server=server)
        server.client_version = transport.remote_version or "Unknown"

        server.event.wait(120)

    except Exception as e:
        print(f"[HONEYPOT] Error from {client_ip}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass
        try:
            client_socket.close()
        except:
            pass

def start_honeypot():
    init_db()
    create_session_tables()
    generate_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((HOST, PORT))
    except PermissionError:
        print(f"[ERROR] Cannot bind to port {PORT} — run setcap first")
        sys.exit(1)

    sock.listen(100)
    print(f"[HONEYPOT] Listening on {HOST}:{PORT}")
    print(f"[HONEYPOT] Granting shell after 3-6 failed attempts")

    while True:
        try:
            client_socket, client_address = sock.accept()
            thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[HONEYPOT] Accept error: {e}")

    sock.close()

if __name__ == "__main__":
    start_honeypot()

import time
from collections import defaultdict

# Track attempts per IP in memory
# Structure: {ip: [(timestamp, username, password), ...]}
ip_tracker = defaultdict(list)

WINDOW = 300  # 5 minutes

DEFAULT_CREDENTIALS = [
    ("root", "root"), ("root", "123456"), ("root", "password"),
    ("root", "toor"), ("root", "admin"), ("admin", "admin"),
    ("admin", "password"), ("admin", "123456"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("user", "user"), ("test", "test"),
    ("guest", "guest"), ("oracle", "oracle"), ("postgres", "postgres"),
]

def classify_attacker(ip: str, username: str, password: str) -> str:
    now = time.time()

    # Add current attempt
    ip_tracker[ip].append((now, username, password))

    # Keep only attempts within window
    ip_tracker[ip] = [
        (t, u, p) for t, u, p in ip_tracker[ip]
        if now - t < WINDOW
    ]

    attempts = ip_tracker[ip]
    attempt_count = len(attempts)
    usernames_tried = set(u for _, u, _ in attempts)

    # Bot — high volume attempts
    if attempt_count >= 10:
        return "bot"

    # Script kiddie — trying default credentials
    if (username, password) in DEFAULT_CREDENTIALS:
        return "script_kiddie"

    # Scanner — low attempts, moving on quickly
    if attempt_count <= 2:
        return "scanner"

    # Targeted — custom username not in default list
    if username not in [u for u, _ in DEFAULT_CREDENTIALS]:
        return "targeted"

    return "script_kiddie"

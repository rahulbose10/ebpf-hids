import os
import secrets
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("HIDS_DATA_DIR", BASE_DIR / "data"))
MODEL_DIR = Path(os.environ.get("HIDS_MODEL_DIR", BASE_DIR / "server" / "ml"))
RULES_DIR = BASE_DIR / "server" / "rules"
CONSOLE_DIST = BASE_DIR / "console" / "dist"

DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATA_DIR / "hids.db"
SECRET_KEY_FILE = DATA_DIR / "secret.key"

HOST = os.environ.get("HIDS_HOST", "127.0.0.1")
PORT = int(os.environ.get("HIDS_PORT", "5000"))
SESSION_HOURS = 12

SEED_USER = os.environ.get("HIDS_ADMIN_USER", "admin")
SEED_PASS = os.environ.get("HIDS_ADMIN_PASS")

MAX_LIMIT = 1000
REPORT_MAX_ROWS = 100000
TREE_MAX_NODES = 500

REORDER_HOLD_SECONDS = 0.15
REORDER_MAX_EVENTS = 5000
INGEST_QUEUE_MAX = 10000
EVENT_BATCH_SIZE = 200
EVENT_FLUSH_SECONDS = 0.5
SENSOR_STALE_SECONDS = 60

SIM_WHITELIST = {
    "demo": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_demo.py")],
    "reverse-shell": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_reverse_shell.py")],
    "privilege-escalation": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_privilege_escalation.py")],
    "benign-exec-chain": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_benign_exec_chain.py")],
    "ransomware": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_ransomware.py")],
    "rootkit": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_rootkit.py")],
    "persistence": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_persistence.py")],
    "credaccess": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_credaccess.py")],
    "backdoor": [sys.executable, str(BASE_DIR / "server" / "simulations" / "sim_backdoor.py")],
}
SIM_TIMEOUT_SECONDS = 30

RESPONSE_ENABLED = False
RESPONSE_DRY_RUN = True
RESPONSE_MIN_SEVERITY = "critical"
RESPONSE_GRACE_SECONDS = 3

NEVER_KILL = {
    "systemd", "init", "sshd", "dbus-daemon", "containerd", "dockerd",
    "systemd-journal", "systemd-logind", "systemd-udevd", "systemd-resolve",
    "systemd-network", "containerd-shim", "NetworkManager", "rsyslogd",
    "cron", "agetty", "login", "polkitd", "auditd",
    "loader", "ips_enforce", "sensor",
}

MIN_SAFE_PID = 300
RESPONSE_LOG_MAX = 500

ALERT_ENABLED = False
ALERT_MIN_SEVERITY = "high"
ALERT_THROTTLE_SECONDS = 300
ALERT_WEBHOOK_URL = ""
ALERT_WEBHOOK_TIMEOUT = 5
ALERT_SYSLOG_ENABLED = False
ALERT_SYSLOG_HOST = "127.0.0.1"
ALERT_SYSLOG_PORT = 514


def load_secret_key():
    from_env = os.environ.get("HIDS_SECRET_KEY")
    if from_env:
        return from_env
    try:
        key = SECRET_KEY_FILE.read_text(encoding="ascii").strip()
        if key:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(key, encoding="ascii")
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return key

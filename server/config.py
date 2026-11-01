import os
import sys


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
RULES_DIR = os.path.join(BASE_DIR, "server", "rules")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "hids.db")
SECRET_KEY = os.environ.get("HIDS_SECRET_KEY", "dev-secret-key-change-in-production")
SESSION_HOURS = 12

SEED_USER = os.environ.get("HIDS_ADMIN_USER", "admin")
SEED_PASS = os.environ.get("HIDS_ADMIN_PASS", "admin123")

SIM_WHITELIST = {
    "revshell": os.path.join(BASE_DIR, "simulations", "sim_revshell.sh"),
    "ptrace": os.path.join(BASE_DIR, "simulations", "sim_ptrace.sh"),
    "suid": os.path.join(BASE_DIR, "simulations", "sim_suid.sh"),
    "recon": os.path.join(BASE_DIR, "simulations", "sim_recon.sh")
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_PATH = os.path.join(BASE_DIR, "hids.db")

SECRET_KEY = "dev-secret-change-me"

PORT = 5000

SIM_WHITELIST = {
    "demo": [sys.executable, os.path.join(BASE_DIR, "simulations", "sim_demo.py")],
}

SIM_TIMEOUT_SECONDS = 30
INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive")
RESPONSE_ENABLED = False
RESPONSE_DRY_RUN = True
RESPONSE_MIN_SEVERITY = "critical"
RESPONSE_GRACE_SECONDS = 3

NEVER_KILL = {
    "systemd", "init", "sshd", "dbus-daemon", "containerd", "dockerd",
    "systemd-journal", "systemd-logind", "systemd-udevd", "systemd-resolve",
    "systemd-network", "containerd-shim", "NetworkManager", "rsyslogd",
    "cron", "agetty", "login", "polkitd", "auditd",
    "loader", "sensor",
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

import pyotp
import qrcode
import subprocess
import time
import os
import secrets
import smtplib
import sqlite3
import json
import geoip2.errors
import geoip2.database 
import copy
import random
import uvicorn
import asyncio
import threading
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPAuthorizationCredentials
from jose import jwt
from fastapi import FastAPI, Request, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware 
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime, timedelta
from fastapi import HTTPException
from fastapi import Depends, HTTPException, status
from starlette.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Query, Request, BackgroundTasks, UploadFile, File
from fastapi.responses import StreamingResponse, HTMLResponse
from email.message import EmailMessage
from pydantic import BaseModel
from typing import Dict, Any, List, Union
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from fastapi import Header
from dotenv import load_dotenv
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from threading import Lock
import requests


load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")

DEMO_TTL_SECONDS = int(os.getenv("DEMO_TTL_SECONDS", str(48 * 3600)))
DEMO_AUTO_UNBLOCK_INTERVAL_MINUTES = int(
 os.getenv("DEMO_AUTO_UNBLOCK_INTERVAL_MINUTES", "60"))

security = HTTPBasic(auto_error=False)

FAILED_COUNTER = {}
USER_TRACKER = {}
LAST_ATTEMPT_TIME = {}
ALERT_SENT = set()

app = FastAPI()
connected_clients = []
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8001",
        "http://localhost:8001",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "https://brute-force-detection-dashboard.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


BASE_DIR = os.path.dirname(__file__)
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "public")

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
else:
    print("[WARNING] Frontend static directory not found.")

BLOCKED_IPS_FILE = "persistent_block.json"

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
AUTH_FILE = "admin_auth.json"
ADMIN_PASSWORD_HASHED: str = ""
TOTP_SECRET = pyotp.random_base32()
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "alert.db")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.getenv("SMTP_USER")
SMTP_APP_PASSWORD = os.getenv("SMTP_APP_PASSWORD")

GEOIP_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
GEOIP_READER = None

try:
    asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
except Exception as e:
    print("[ASN WARNING]", e)
    asn_reader = None
try:
    if not os.path.exists(GEOIP_DB_PATH):
        raise FileNotFoundError(
            "GeoLite2-City.mmdb not found in project root.")

    GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
    print("[GEOIP] database loaded successfully.")
except Exception as e:
    print(
        f"[WARN] GeoIP database not loaded. Map feature will be disabled.Error: {e}")


DETECTION_SETTINGS = {
    "FAILED_LOGIN_THRESHOLD": 6,
    "DISTINCT_USER_THRESHOLD": 2,
    "RATE_LIMIT_HITS": 10,
    "GEOLOCATION_FILTER": "Enabled",
    "BLOCKED_COUNTRIES": ["North Korea", "Russia", "Iran", "China"],
    "ACTIVE_STATUS": "ACTIVE"

}

CONTROL_SETTING = {
    "SYSTEM_ACTIVE": True,
    "AUTO_BLOCK_ENABLED": True,
    "SENSITIVITY": "CONSERVATIVE",
    "SENSITIVITY_VALUE0": 50
}

RECENT_ATTACK_WINDOW_SECONDS = 60
AGGRESSIVE_CRITICAL_THRESHOLD = 2
RESTORE_TO_CONSERVATIVE_AFTER_SECONDS = 90
recent_critical_attacks: List[float] = []


RECENT_ATTACKS_LOCK = Lock()
reset_tokens: Dict[str, Dict[str, Any]] = {}
forgot_password_tokens = {}
blocked_ips: Dict[str, Dict[str, Any]] = {}
BLOCKED_LOCK = Lock()
country_attack_counter: Dict[str, int] = {}


class AttackInput(BaseModel):
    failed_attempts_last_5min: int
    success_last_hour: int
    distinct_usernames_per_ip: int
    time_between_attempts: float
    user_email: str


class PasswordResetInput(BaseModel):
    token: str
    new_password: str

class UserPasswordReset(BaseModel):
    token: str
    new_password: str

class RegisterInput(BaseModel):
    full_name: str
    email: str
    password: str


def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    return request.client.host


def generate_random_ip():
    """Generates a random, valid-looking IP address for simulation."""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 150)}.{random.randint(1, 255)}"


def get_ip_location(ip: str) -> dict:
    """Uses GeoIP to find city, country, latitude, and longitude of an IP."""
    if GEOIP_READER is None:
        return {"country": "N/A", "latitude": 0.0, "longitude": 0.0}
    if ip == '127.0.0.1':
        ip = "193.201.224.225"

    try:
        response = GEOIP_READER.city(ip)

        lat = response.location.latitude if response.location.latitude is not None else 0.0
        lon = response.location.longitude if response.location.longitude is not None else 0.0

        if lat == 0.0 and lon == 0.0:
            lat = 40.7128
            lon = -74.0060
        return {
            "city": response.city.name,
            "country": response.country.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "source": "GeoIP"

        }
    except geoip2.errors.AddressNotFoundError:
        print(f"[GEOIP] No data for {ip}, fallback to default coords.")
        return {"country": "Unknown", "latitude": 40.7128, "longitude": -74.0060, "source": "GeoIP Fallback"}
    except Exception as e:
        return {"country": "Fallback", "latitude": 40.7128, "longitude": -74.0060, "source": "Error Fallback"}


def get_ip_details(ip):
    """Enhanced IP lookup with ASN + VPN Detection"""
    result = {
        "city": "Unknown",
        "country": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": "Unknown",
        "isp": "Unknown",
        "vpn_suspected": False
    }

    try:
        response = GEOIP_READER.city(ip)
        result["city"] = response.city.name
        result["country"] = response.country.name
        result["latitude"] = response.location.latitude
        result["longitude"] = response.location.longitude
    except:
        pass

    try:
        if asn_reader:
            asn_res = asn_reader.asn(ip)
            result["asn"] = asn_res.autonomous_system_number
            result["isp"] = asn_res.autonomous_system_organization

        vpn_keywords = [
            "VPN", "Hosting", "Cloud",
            "DigitalOcean", "AWS", "Google",
            "Hetzner", "OVH", "Contabo"
        ]

        if any(k.lower() in result["isp"].lower() for k in vpn_keywords):
            result["vpn_suspected"] = True

    except:
        pass

    print("[ASN CHECK]", ip, result)

    return result


def initialize_db():
    """Initializes SQLite database and creates the alerts table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
             ''')
        c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                ''')
        conn.commit()
        conn.close()
        print("[DB SETUP] Database initialized and table is ready at:", DB_PATH)
    except Exception as e:
        print(f"[ERROR] Database logging failed: {e}")


def log_alert_to_db(ip: str, status: str, reason_data: Dict[str, Any]):
    """
    Logs the alert record into the SQLite database (robust).
    Ensures reason JSON always contains the expected keys so frontend shows Attempts/Users.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if not isinstance(reason_data, dict):
            print(f"[WARN] reason_data not a dict for (ip). Forcing dict()")
            safe_reason_data = {"raw_reason": str(reason_data)}
        else:

            safe_reason_data = copy.deepcopy(reason_data)

        safe_reason_data.setdefault("failed_attempts_last_5min", 0)
        safe_reason_data.setdefault("distinct_usernames_per_ip", 0)
        safe_reason_data.setdefault("time_between_attempts", 0.0)

        loc = safe_reason_data.get("location_data")
        if not isinstance(loc, dict):
            safe_reason_data.setdefault(
                "location_data", {"country": "N/A", "city": "N/A", "source": "N/A"})

        try:

            reason_str = json.dumps(safe_reason_data, default=str)
        except Exception as e:
            print(f"[WARN] Could not JSON encode reason for {ip}: {e}")
            reason_str = str(safe_reason_data)

        c.execute(
            "INSERT INTO alerts (ip_address, status, reason) VALUES (?, ?, ?)",
            (ip, status, reason_str))

        conn.commit()
        if status == "CRITICAL_ATTACK":
            with RECENT_ATTACKS_LOCK:
                recent_critical_attacks.append(time.time())
                if len(recent_critical_attacks) > 1000:
                    recent_critical_attacks.pop(0)
            print(
                f"[ADAPTIVE LOG] Recorded critical attack for sensitivity tracking.")

        conn.close()

        print(
            f"[DB LOGGED] Alert for {ip} ->  status: {status}, attempts:{safe_reason_data['failed_attempts_last_5min']}, users:{safe_reason_data['distinct_usernames_per_ip']}")
        try:
            loc = safe_reason_data.get("location_data", {})
            country = loc.get("country", "Unknown")
            if status == "CRITICAL_ATTACK":
                country_attack_counter[country] = country_attack_counter.get(
                    country, 0) + 1
                if country_attack_counter[country] > 5 and country not in DETECTION_SETTINGS["BLOCKED_COUNTRIES"]:
                    DETECTION_SETTINGS["BLOCKED_COUNTRIES"].append(country)
                    print(
                        f"[ADAPTIVE BLOCK] Country '{country}' auto-added to BLOCKED_COUNTRIES due to repeated attacks.")
        except Exception as e:
            print(f"[ADAPTIVE BLOCK ERROR] {e}")

    except Exception as e:
        print(f"[ERROR] Database logging failed for {ip}: {e}")
        try:
            send_alert_email(
                os.getenv("ADMIN_EMAIL", SMTP_USER),  # send to admin email
                ip,
                {"error": str(e)},
                "CRITICAL SYSTEM FAILURE: DB Logging Failed"
            )
        except Exception as mail_error:
            print(
                f"[EMAIL ALERT FAILED] Could not send DB failure alert: {mail_error}")


def load_admin_hash_on_startup():
    """Loads the admin hash from persistent storage or initializes it, setting the GLOBAL variable."""
    global ADMIN_PASSWORD_HASHED

    initial_plain_password = os.getenv("DEFAULT_ADMIN_PASSWORD")
    default_hash = pwd_context.hash(initial_plain_password)

    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r") as f:
                data = json.load(f)
            file_hash = data.get("password_hash")
            file_user = data.get("username", ADMIN_USER)

            if isinstance(file_hash, str) and file_hash.strip():
                try:

                    pwd_context.verify(
                        "dummy-check-password-should-fail"[:72], file_hash)
                except Exception as verify_e:
                    print(
                        f"[AUTH WARNING] Existing hash invalid/unrecognized: {verify_e}. Recreating auth file with default password.")
                    with open(AUTH_FILE, "w") as f:
                        json.dump({"username": ADMIN_USER,
                                  "password_hash": default_hash}, f)
                    ADMIN_PASSWORD_HASHED = default_hash
                    print(
                        f"[AUTH INIT] New admin_auth.json created with default password.")
                    return
                ADMIN_PASSWORD_HASHED = file_hash
                print("[AUTH LOADED] Hash loaded from file.")
                return
            else:
                print(
                    "[AUTH WARNING] admin_auth.json present but missing 'password_hash' value. Recreating file.")
        except Exception as e:
            print(
                f"[AUTH WARNING] Failed to read/parse {AUTH_FILE}: {e}. Will recreate with default credentials.")

    try:
        with open(AUTH_FILE, "w") as f:
            json.dump({"username": ADMIN_USER,
                      "password_hash": default_hash}, f)
        ADMIN_PASSWORD_HASHED = default_hash
        print(
            f"[AUTH SUCCESS] Default HASH saved to file for {AUTH_FILE}. Default password is: {initial_plain_password}")
    except Exception as e:
        ADMIN_PASSWORD_HASHED = default_hash
        print(
            f"[AUTH ERROR] Could not write {AUTH_FILE} to disk: {e}. Using in-memory default hash.")


def authenticate_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Authenticates using the globally loaded hash, avoiding file I/O on every request."""

    global ADMIN_PASSWORD_HASHED

    if not ADMIN_PASSWORD_HASHED or not pwd_context.identify(ADMIN_PASSWORD_HASHED):
        print(
            "[AUTH WARNING] Invalid or missing admin hash detected. Re-initializing hash store...")
        load_admin_hash_on_startup()  # recreate valid default hash

    LATEST_HASH = ADMIN_PASSWORD_HASHED

    is_correct_username = secrets.compare_digest(
        credentials.username, ADMIN_USER)

    try:
        is_correct_password = pwd_context.verify(
            credentials.password[:72], LATEST_HASH)
    except Exception as e:
        print(
            f"[AUTH ERROR] Password verification failed due to invalid hash: {e}")
        load_admin_hash_on_startup()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or corrupted authentication hash. Please try again.",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not (is_correct_username and is_correct_password):
        print(
            f"[AUTH FAILED] Invalid login attempt for {credentials.username}.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Access denied.",
            headers={"WWW-Authenticate": "Basic"},
        )

    print(
        f"[AUTH SUCCESS] User: {credentials.username} logged in successfully.")
    return credentials.username


def get_all_alerts(limit: int = 50) -> list:
    """"Fetches all alert records from the database for the list view."""
    try:

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("""
            SELECT * FROM alerts
            WHERE timestamp >= datetime('now', '-1 day')
            ORDER BY timestamp DESC
            LIMIT ?
          """, (limit,))

        alerts = [dict(row) for row in c.fetchall()]

        conn.close()
        print(f"[DB FETCH] Fetched {len(alerts)} alert records.")
        return alerts

    except Exception as e:
        print(f"[ERROR] Could not fetch alerts: {e}")
    try:
        send_alert_email(
            os.getenv("ADMIN_EMAIL", SMTP_USER),
            "127.0.0.1",
            {"error": str(e)},
            "CRITICAL SYSTEM FAILURE: DB Connection Lost"
        )

    except Exception:
        pass
    return [{"error": str(e), "message": "Database error during fetch."}]


def soft_token(authorization: str = Header(None)):
    """
    Soft auth: Dashboard data allowed without forcing login.
    Only blocks admin-level actions.
    """
    if not authorization:
        return "anonymous"

    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload.get("sub", "anonymous")
    except:
        return "anonymous"


def strict_token(authorization: str = Header(None)):
    """
    Strict auth: Admin-level protected endpoints.
    Requires valid token.
    """
    if authorization is None:
        raise HTTPException(
            status_code=401, detail="Missing Authorization header")

    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload["sub"]
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def generate_report_content() -> str:
    """Fetches all data and compiles it into a structured text report."""
    try:
        metrics = get_system_metrics()

        alerts = get_all_alerts(limit=1000)  # Saari alerts fetch karein

        report = []
        report.append("="*80)
        report.append("    BRUTE FORCE ATTACK DETECTION - SECURITY REPORT")
        report.append(f"    Generated On: {time.ctime()}")
        report.append("="*80)

        report.append("\n[ I. SYSTEM SUMMARY ]")
        report.append("-" * 30)
        report.append(
            f"System Status: {'ACTIVE' if CONTROL_SETTING['SYSTEM_ACTIVE'] else 'INACTIVE'}")
        report.append(
            f"Auto-Block: {'ENABLED' if CONTROL_SETTING['AUTO_BLOCK_ENABLED'] else 'DISABLED'}")
        report.append(
            f"Sensitivity: {CONTROL_SETTING['SENSITIVITY']} ({CONTROL_SETTING.get('SENSITIVITY_VALUE0', 'N/A')})")
        report.append(
            f"Total Threats Logged: {metrics.get('total_threats_count', 0)}")
        report.append(
            f"Currently Blocked IPs: {metrics.get('total_blocked_count', 0)}")

        report.append("\n[ II. RECENT CRITICAL ALERTS ]")
        report.append("-" * 30)

        critical_alerts = [a for a in alerts if a['status']
        in ['CRITICAL_ATTACK', 'ATTACK_DETECTED']]

        if not critical_alerts:
            report.append("No critical alerts found in the database.")
        else:
            for i, alert in enumerate(critical_alerts[:10]):

                try:
                    reason_data = json.loads(alert['reason'])
                    loc = reason_data.get('location_data', {})
                    summary = f"Attempts: {reason_data.get('failed_attempts_last_5min', 'N/A')}, Distinct Users: {reason_data.get('distinct_usernames_per_ip', 'N/A')}"
                except:
                    summary = "Reason data unparsable."
                    loc = {"country": "N/A"}

                report.append(
                    f"    {i+1}. IP: {alert['ip_address']} | Status: {alert['status']} | Country: {loc.get('country', 'N/A')}")
                report.append(f"    Time: {alert['timestamp']} | {summary}")

        report.append("\n" + "="*80)

        return "\n".join(report)

    except Exception as e:
        return f"CRITICAL REPORT GENERATION ERROR: {str(e)}"


def get_system_metrics() -> dict:
    """Calculates and returns system-wide security metrics."""

    global blocked_ips

    db_status = "ACTIVE"
    total_threats = 0
    critical_threats = 0
    active_threats_db = 0
    unique_ips = 0

    total_blocked = len(blocked_ips)

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT COUNT(id) FROM alerts WHERE status != 'NORMAL'")
        total_threats = c.fetchone()[0]

        c.execute("SELECT COUNT(id) FROM alerts WHERE status = 'CRITICAL_ATTACK'")
        critical_threats = c.fetchone()[0]

        c.execute(
            "SELECT COUNT(id) FROM alerts WHERE status != 'NORMAL' AND timestamp >= datetime('now', '-1 day')")
        active_threats_db = c.fetchone()[0]

        c.execute("SELECT COUNT(DISTINCT ip_address) FROM alerts")
        unique_ips = c.fetchone()[0]

        conn.close()

    except sqlite3.OperationalError:
        db_status = "DOWN (Table Missing)"
        total_blocked = 0
        unique_ips = 0
        active_threats_db = 0
    except Exception:
        db_status = "DOWN (Connection Error)"
        total_blocked = 0
        unique_ips = 0
        active_threats_db = 0

    return {
        "status_db": db_status,
        "total_threats_count": total_threats,
        "active_threats_count": active_threats_db,  
        "total_blocked_count": total_blocked,
        "critical_threats_count": critical_threats,
        "monitored_ip_count": unique_ips,
        "api_health": "UP"
    }


def block_ip(ip: str, reason: dict):

    import platform

    rule_name = f"Block-{ip}-{int(time.time())}"

    try:

        if platform.system() == "Windows":

            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f'name={rule_name}',
                "dir=in",
                "interface=any",
                "action=block",
                f"remoteip={ip}"
            ]

            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False
            )

            print(f"[WINDOWS BLOCK] {ip} blocked.")

        else:

            print(
                f"[SIMULATION MODE] Linux/Render detected. Simulated block for {ip}"
            )

        unblock_time = time.time() + DEMO_TTL_SECONDS

        blocked_ips[ip] = {
            "reason": reason,
            "time": time.time(),
            "unblock_time": unblock_time,
            "rule": rule_name
        }

        save_blocked_ips()

    except Exception as e:

        print(f"[BLOCK ERROR] {e}")


def block_ip_sync(ip: str, reason: dict):
    """Actual blocking logic moved here to run in a safe background thread."""
    if ip == "127.0.0.1" or ip.startswith("127."):
        print("[SAFE MODE] Localhost block attempt ignored.")
        return
    block_ip(ip, reason)


async def block_ip_async(ip: str, reason: dict):
    """Runs IP block operation asynchronously (non-blocking)."""
    await asyncio.to_thread(block_ip_sync, ip, reason)


def save_blocked_ips():
    """Saves the current blocked_ips dictionalry to a JSON file."""
    try:
        with BLOCKED_LOCK:

            with open(BLOCKED_IPS_FILE, "w") as f:
                json.dump(blocked_ips, f, indent=4)
                print("[PERSIST] Blocked IPs saved to disk.")
    except Exception as e:
        print(f"[ERROR] Failed to save blocked ips: {e}")


def load_blocked_ips():
    """Loads the blocked_ips dictionary from the JSON file on startup."""
    global blocked_ips
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as f:
                loaded_data = json.load(f)

                if isinstance(loaded_data, dict):
                    blocked_ips = loaded_data
                    print(
                        f"[PERSIST] {len(blocked_ips)} IPs loaded from disk.")
                else:
                    print(
                        f"[PERSIST] Loaded file is invalid, starting with empty list.")
        else:
            print("[PERSIST] No blocked IP file found, starting fresh.")
    except Exception as e:
        print(f"[ERROR] Failed to load blocked IPs: {e}")
        blocked_ips = {}


def generate_reset_link(user_email: str) -> str:
    token = secrets.token_urlsafe(16)
    expiry = int(time.time()) + (3 * 3600)
    reset_tokens[token] = {"email": user_email, "expiry": expiry}

    BASE_URL = "https://brute-force-detection-dashboard.onrender.com"
    link = f"{BASE_URL}/reset_password?token={token}"

    print("[DEBUG] Reset link generated:", link)
    return link


def send_alert_email(user_email: str, ip: str, reason: dict, reset_link: str):
    """Send email using SMTP with STARTTLS with professional formatting."""

    if not CONTROL_SETTING["SYSTEM_ACTIVE"]:
        print(
            f"[FREEZE] Alert email to {user_email} dropped. System is INACTIVE.")
        return

    msg = EmailMessage()
    msg['Subject'] = f" URGENT Security Alert: Suspicious Activity Detected From {ip}"
    msg['From'] = SMTP_USER
    msg['To'] = user_email
    msg['Reply-To'] = SMTP_USER

    attempts = reason.get("failed_attempts_last_5min", "N/A")
    users = reason.get("distinct_usernames_per_ip", "N/A")
    time_gap = reason.get("time_between_attempts", "N/A")

    location_data = reason.get("location_data", {})
    country = location_data.get("country", "Unknown")
    city = location_data.get("city")
    city_display = city if city and city.lower() != 'none' else "N/A"

    email_body = f"""
Dear User,

We are writing to inform you of a serious security event detected on your account.

* * * THREAT LEVEL: CRITICAL * * * We detected a highly suspicious, automated login attempt pattern originating from the following source:

--- ATTACK DETAILS ---
IP Address: {ip}
Location: {city_display} ({country})
Source Analysis: {location_data.get("source", "N/A")}

--- THREAT METRICS ---
Failed Attempts (last 5 min): {attempts}
Distinct Usernames Tried: {users}
Average Time Between Attempts: {time_gap} seconds

--- ACTION REQUIRED (URGENT) ---

1. SECURE YOUR ACCOUNT: We strongly recommend you reset your password immediately.

Use the secure link below:
{reset_link}

2. CONTACT SUPPORT: If you recognize this activity, you can safely ignore this email. If not, please contact support immediately.

---
This alert was generated automatically by the Brute Force Detection System.
"""

    msg.set_content(email_body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        print(f"[EMAIL SENT] Alert email sent to {user_email}")
    except Exception as e:
        print(f"[ERROR] Email could not be sent: {e}")


def detect_attack(data: AttackInput, request_headers: dict = None) -> str:
    """Enhanced detection with VPN mismatch detection."""
    score = 0

    if data.failed_attempts_last_5min > DETECTION_SETTINGS["FAILED_LOGIN_THRESHOLD"]:
        score += 60
    if data.distinct_usernames_per_ip > DETECTION_SETTINGS["DISTINCT_USER_THRESHOLD"]:
        score += 25

    if request_headers:
        accept_lang = request_headers.get("accept-language", "") or ""
        if ("en-US" not in accept_lang) and ("en-GB" not in accept_lang) and ("IN" not in accept_lang) and accept_lang != "":
            score += 20
            print(
                "[INTEL] VPN/mismatch suspected (Accept-Language). Threat score increased by 20.")

    if score >= 80:
        return "CRITICAL_ATTACK"
    elif score >= 40:
        return "ATTACK_DETECTED"
    return "NORMAL"


def create_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=8)  # token valid 8 hrs
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_token(authorization: str = Header(None)):
    """
    SAFE TOKEN VERIFICATION FOR DASHBOARD:
    - Never break endpoint with 401
    - Always return a fallback user
    - Prevents dashboard empty state & API errors
    """
    if authorization is None:
        return "anonymous"

    try:
        parts = authorization.split(" ")
        if len(parts) != 2:
            return "anonymous"

        token = parts[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload.get("sub", "anonymous")

    except Exception as e:
        print("[AUTH WARNING] Invalid or expired token but NOT blocking:", str(e))
        return "anonymous"


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    await websocket.accept()

    connected_clients.append(websocket)

    print("[WEBSOCKET] Client connected")

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:

        connected_clients.remove(websocket)

        print("[WEBSOCKET] Client disconnected")


@app.post("/predict")
async def predict_attack(data: AttackInput, request: Request, background_tasks: BackgroundTasks) -> dict:

    forwarded_ip = request.headers.get("x-forwarded-for")
    ip = forwarded_ip if forwarded_ip else request.client.host
    print(f"\n--- Processing Request from IP: {ip} ---")

    ip_for_geo = "8.8.8.8" if ip == '127.0.0.1' or ip == '172.0.0.1' else ip

    if not CONTROL_SETTING["SYSTEM_ACTIVE"]:
        status = "INACTIVE_SYSTEM"
        background_tasks.add_task(log_alert_to_db, ip, status, data.dict())
        return {
            "status": status,
            "is_attack": False,
            "message": "System is currently INACTIVE. Request logged."
        }
    location_data = get_ip_details(ip_for_geo)

    is_geo_blocked = False

    if DETECTION_SETTINGS["GEOLOCATION_FILTER"] == "Enabled" and location_data.get("country"):

        blocked_countries_upper = [
            c.upper() for c in DETECTION_SETTINGS["BLOCKED_COUNTRIES"]]

        if location_data["country"].upper() in blocked_countries_upper:
            is_geo_blocked = True

            failed = getattr(data, "failed_attempts_last_5min",
                             0) if hasattr(data, "__dict__") else 0
            distinct = getattr(data, "distinct_usernames_per_ip", 0) if hasattr(
                data, "__dict__") else 0
            tb = getattr(data, "time_between_attempts", 0.0) if hasattr(
                data, "__dict__") else 0.0

            reason_geo = {
                "geo_block_reason": f"IP from blocked country: {location_data['country']}",
                "failed_attempts_last_5min": int(failed),
                "distinct_usernames_per_ip": int(distinct),
                "time_between_attempts": float(tb),
                "location_data": location_data
            }

            background_tasks.add_task(
                log_alert_to_db, ip, "CRITICAL_ATTACK", reason_geo)

            if CONTROL_SETTING["AUTO_BLOCK_ENABLED"]:
                background_tasks.add_task(block_ip, ip, reason_geo)
                print(
                    f"[GEO-BLOCK] Action: IP {ip} scheduled for block due to high-risk location.")

            return {
                "status": "CRITICAL_ATTACK",
                "is_attack": True,
                "message": f"Geo-Blocked: IP from {location_data['country']}",
                "location_data": location_data
            }
    status = detect_attack(data, dict(request.headers))
    is_attack = status != "NORMAL"
    location_data = get_ip_details(ip_for_geo)

    reason = {
        "failed_attempts_last_5min": data.failed_attempts_last_5min,
        "distinct_usernames_per_ip": data.distinct_usernames_per_ip,
        "time_between_attempts": data.time_between_attempts,
        "location_data": location_data
    }

    if is_attack:
        reset_link = generate_reset_link(data.user_email)
        background_tasks.add_task(
            send_alert_email, data.user_email, ip, reason, reset_link)

        background_tasks.add_task(log_alert_to_db, ip, status, reason)

        for client in connected_clients:
            try:
                await client.send_json({
                    "type": "LIVE_ATTACK",
                    "ip": ip,
                    "status": status,
                    "country": location_data.get("country"),
                    "city": location_data.get("city"),
                    "attempts": data.failed_attempts_last_5min
                })
            except Exception as e:
                print("[WEBSOCKET ERROR]", e)

        if CONTROL_SETTING["AUTO_BLOCK_ENABLED"]:
            background_tasks.add_task(block_ip_sync, ip, reason)
            print(f"[NOTE] Action: Blocked & Alerted scheduled by Auto-Block.")

        else:
            print(
                f"[NOTE] Action: Alerted only (Auto-Block is OFF). No blocking action taken.")

    else:
        clean_reason = {
            "activity": "Normal successful login or low failure count."}
        background_tasks.add_task(log_alert_to_db, ip, "NORMAL", clean_reason)

    return {
        "attack_probability": 0.9 if is_attack else 0.1,
        "is_attack": is_attack,
        "status": status,
        "feature_impact": data.dict(),
        "location_data": location_data
    }


@app.post("/admin/action/simulate_attacks")
def trigger_attack_simulation(
    background_tasks: BackgroundTasks,  # FIX: Added BackgroundTasks dependency
    num_attacks: int = Query(10, ge=1, le=50),
    username: str = Depends(strict_token)  # <-- ADDED AUTH
):
    results = []

    MY_REAL_EMAIL = os.getenv("ADMIN_EMAIL", SMTP_USER)

    for i in range(num_attacks):
        ip = generate_random_ip()

        payload = {
            "failed_attempts_last_5min": random.randint(7, 15),
            "success_last_hour": 0,
            "distinct_usernames_per_ip": random.randint(1, 3),
            "time_between_attempts": 0.1,
            "user_email": f"user_{i}_{random.randint(100, 999)}@test.com"
        }

        try:
            ip_for_geo = ip
            location_data = get_ip_details(ip_for_geo)

            status = "CRITICAL_ATTACK"

            reason_data = {
                "failed_attempts_last_5min": payload["failed_attempts_last_5min"],
                "distinct_usernames_per_ip": payload["distinct_usernames_per_ip"],
                "time_between_attempts": payload["time_between_attempts"],
                "location_data": location_data,
                "simulation": True,
                "user_email": payload["user_email"]
            }

            print(
                f"[SIMULATOR] Attack simulated for IP={ip} (NO BLOCK APPLIED).")
            background_tasks.add_task(log_alert_to_db, ip, status, reason_data)

            if CONTROL_SETTING["AUTO_BLOCK_ENABLED"]:
                background_tasks.add_task(block_ip_sync, ip, reason_data)
                print(f"[SIMULATOR] IP {ip} sent to block queue.")

            if CONTROL_SETTING.get("AUTO_EMAIL_ALERT", True):
                reset_link = generate_reset_link(payload['user_email'])
                background_tasks.add_task(
                    send_alert_email, MY_REAL_EMAIL, ip, reason_data, reset_link)
                print(f"[SIMULATOR] Alert email scheduled to {MY_REAL_EMAIL}")

            results.append({"ip": ip, "status": status,
                           "country": location_data.get('country')})

        except Exception as e:
            results.append({"ip": ip, "status": "Error", "message": str(e)})

    return {"status": "success", "attacks": results, "message": f"Successfully scheduled {len(results)} attack simulations."}

@app.post("/forgot-password")
def forgot_password(email: str = Form(...)):

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        )

        user = c.fetchone()

        conn.close()

        if not user:
            return {
                "status": "error",
                "message": "Email not registered"
            }

        token = secrets.token_urlsafe(32)

        forgot_password_tokens[token] = {
            "email": email,
            "expiry": time.time() + 3600
        }

        reset_link = f"https://brute-force-detection-dashboard.onrender.com/reset-password-page?token={token}"

        msg = EmailMessage()

        msg["Subject"] = "Password Reset Request"
        msg["From"] = SMTP_USER
        msg["To"] = email

        msg.set_content(f"""
Hello,

We received a password reset request.

Click the link below to reset your password:

{reset_link}

This link expires in 1 hour.

If you did not request this, ignore this email.
""")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
            smtp.send_message(msg)

        return {
            "status": "success",
            "message": "Password reset email sent"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
    
@app.post("/reset-user-password")
def reset_user_password(data: UserPasswordReset):

    try:

        if data.token not in forgot_password_tokens:
            return {
                "status": "error",
                "message": "Invalid token"
            }

        token_data = forgot_password_tokens[data.token]

        if time.time() > token_data["expiry"]:
            del forgot_password_tokens[data.token]

            return {
                "status": "error",
                "message": "Token expired"
            }

        email = token_data["email"]

        new_hash = pwd_context.hash(
            data.new_password[:72]
        )

        conn = sqlite3.connect(DB_PATH)

        c = conn.cursor()

        c.execute(
            """
            UPDATE users
            SET password = ?
            WHERE email = ?
            """,
            (new_hash, email)
        )

        conn.commit()
        conn.close()

        del forgot_password_tokens[data.token]

        return {
            "status": "success",
            "message": "Password reset successful"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.post("/reset_password")
def reset_password(data: PasswordResetInput):
    """Validates the reset token and allows for password reset."""

    global ADMIN_PASSWORD_HASHED

    token = data.token
    new_password = data.new_password

    if token not in reset_tokens:
        return {"status": "error", "message": "Invalid or unknown reset token."}
    info = reset_tokens[token]

    if info["expiry"] < time.time():
        del reset_tokens[token]
        return {"status": "error", "message": "Reset link expired. Please request a new one."}

    try:
        email = info["email"]
        new_hashed_password = pwd_context.hash(data.new_password[:72])
        with open(AUTH_FILE, "w") as f:
            json.dump({"username": ADMIN_USER,
                      "password_hash": new_hashed_password}, f)

        ADMIN_PASSWORD_HASHED = new_hashed_password
        print("[AUTH SYNC] Admin hash updated successfully.")
        del reset_tokens[token]

        print(f"[RESET SUCCESS] User {email}'s password has been updated!")
        return {"status": "success", "message": f"Password successfully reset for {email}. you can now log in with the new password."}

    except Exception as e:
        return {"status": "error", "message": f"Internal server error during reset process: {e}"}
    

@app.get("/reset-password-page", response_class=HTMLResponse)
def reset_password_page(token: str):

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reset Password</title>
    </head>

    <body style="font-family: Arial; background:#111; color:white; padding:40px;">

        <h2>Reset Your Password</h2>

        <input
            type="password"
            id="newPassword"
            placeholder="Enter new password"
            style="padding:10px; width:300px;"
        />

        <br><br>

        <button onclick="resetPassword()"
            style="padding:10px 20px;">
            Reset Password
        </button>

        <p id="msg"></p>

        <script>

        async function resetPassword() {{

            const password =
                document.getElementById("newPassword").value;

            const response = await fetch(
                "/reset-user-password",
                {{
                    method: "POST",

                    headers: {{
                        "Content-Type": "application/json"
                    }},

                    body: JSON.stringify({{
                        token: "{token}",
                        new_password: password
                    }})
                }}
            );

            const result = await response.json();

            document.getElementById("msg").innerHTML =
                result.message;
        }}

        </script>

    </body>
    </html>
    """


@app.get("/reset_password", response_class=HTMLResponse)
def get_reset_form(token: str = Query(..., description="Secure reset token")):
    """Serves the HTML form to collect the new password using the token."""

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Reset Password</title></head>
    <body style="font-family: sans-serif; background-color: #121212; color: #f0f0f0;">
        <div style="max-width: 400px; margin: 50px auto; padding: 20px; background-color: #1e1e1e; border-radius: 8px;">
            <h2>🛡️ New Password Setup</h2>
            <p>Please enter your new strong password below.</p>
            
            <input type="hidden" id="token_field" value="{token}">
            
            <label for="password_field">New Password:</label>
            <input type="password" id="password_field" required 
            style="width: 95%; padding: 10px; margin: 10px 0; border: 1px solid #00bcd4; border-radius: 4px; background-color: #333; color: #f0f0f0;">
            
            <button onclick="submitNewPassword()" 
            style="width: 100%; padding: 10px; background-color: #00bcd4; color: #121212; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
                Reset Password Now
            </button>
            <p id="status_message" style="margin-top: 15px; color: #ffc107;"></p>
        </div>
        <script>
            // JavaScript to handle the POST request
            async function submitNewPassword() {{
                const token = document.getElementById('token_field').value;
                const newPassword = document.getElementById('password_field').value;
                const statusMessage = document.getElementById('status_message');
                
                if (newPassword.length < 8) {{
                    statusMessage.style.color = '#ff3d67';
                    statusMessage.textContent = 'Password must be at least 8 characters long.';
                    return;
                }}

                statusMessage.style.color = '#00bcd4';
                statusMessage.textContent = 'Processing...';

                try {{
                    // 💡 NOTE: Yahaan hum POST request bhej rahe hain, jo backend expect karta hai
                    const response = await fetch('/reset_password', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ token: token, new_password: newPassword }})
                    }});
                    
                    const result = await response.json();
                    
                    statusMessage.style.color = result.status === 'success' ? '#00ff7f' : '#ff3d67';
                    statusMessage.textContent = result.message;

                    if (result.status === 'success') {{
                             document.getElementById('password_field').value = '';
                    }}

                }} catch (e) {{
                    statusMessage.style.color = '#ff3d67';
                    statusMessage.textContent = 'Network error. Could not reach server.';
                }}
            }}
        </script>
    </body>
    </html>
    """


@app.get("/alerts")
def get_alerts_dashboard(
    limit: int = 50,
    user=Depends(verify_token)
) -> list:
    """API endpoint to get all security alerts (Notification Feed)."""
    return get_all_alerts(limit=limit)



@app.get("/stream_alerts")
async def stream_alerts(username: str = Depends(verify_token)):
    async def event_stream():
        last_data = None
        while True:
            alerts = get_all_alerts()
            if alerts != last_data:
                yield f"data: {json.dumps(alerts)}\n\n"
                last_data = alerts
            await asyncio.sleep(3)
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/metrics/summary")
def get_dashboard_metrics(username: str = Depends(soft_token)) -> dict:
    """API endpoint to get key security metrics for the dashboard summary (KPIs)."""
    return get_system_metrics()


@app.post("/admin/unblock/{ip_address}")
def unblock_ip(ip_address: str, username: str = Depends(verify_token)):
    """Admin API to remove a specific IP from the Windows Firewall."""

    import platform

    try:

        if platform.system() == "Windows":

            command_list = [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"remoteip={ip_address}"
            ]

            result = subprocess.run(
                command_list,
                check=False,
                capture_output=True,
                text=True,
                encoding='latin-1'
            )

            output = result.stdout.lower() if result.stdout else ""
            error = result.stderr.lower() if result.stderr else ""

            is_successful = (
                result.returncode == 0 or
                result.returncode == 1 or
                "no rules match" in output or
                "no rules match" in error
            )

        else:

            print(f"[SIMULATION MODE] Unblock simulated for {ip_address}")

            is_successful = True
            error = ""

        if is_successful:

            global blocked_ips

            deleted_key = False

            if ip_address in blocked_ips:
                del blocked_ips[ip_address]
                deleted_key = True

            elif '/' in ip_address and ip_address in blocked_ips:
                del blocked_ips[ip_address]
                deleted_key = True

            elif f"{ip_address}/32" in blocked_ips:
                del blocked_ips[f"{ip_address}/32"]
                deleted_key = True

            if not deleted_key:

                for key in list(blocked_ips.keys()):

                    if key.startswith(ip_address) and '/' in key:

                        print(
                            f"[UNBLOCK: SMART MATCH] Found CIDR block {key} for plain IP {ip_address}"
                        )

                        del blocked_ips[key]

                        deleted_key = True

                        break

            if deleted_key:

                print(
                    f"[UNBLOCK SUCCESS] IP {ip_address} removed from list."
                )

                return {
                    "status": "success",
                    "message": f"IP {ip_address} unblocked successfully."
                }

            else:

                return {
                    "status": "success",
                    "message": f"IP {ip_address} unblocked successfully (list entry missing)."
                }

        else:

            error_detail = error if error else "Unknown firewall error."

            return {
                "status": "error",
                "message": f"Firewall command failed. Detail: {error_detail}"
            }

    except Exception as e:

        return {
            "status": "error",
            "message": f"Critical Error during unblock: {str(e)}"
        }

@app.get("/admin/alerts")
def get_recent_alerts(limit: int = 20, username: str = Depends(soft_token)):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/blocked")
def get_blocked_ips(username: str = Depends(strict_token)) -> Dict[str, Dict[str, Any]]:
    return blocked_ips


class IPList(BaseModel):
    ips: List[str]


@app.post("/admin/action/bulk_unblock")
def bulk_unblock_ips(ip_list_data: IPList, username: str = Depends(strict_token
    )):
    """Admin API to remove a list of IPs from the Windows Firewall and the blocked_ips list."""
    global blocked_ips
    unblocked_count = 0

    for ip_address in ip_list_data.ips:
        try:
            import platform

            if platform.system() == "Windows":

                command_list = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"remoteip={ip_address}"
                ]

                subprocess.run(
                    command_list,
                    check=False,
                    capture_output=True
                )

            else:

                print(
                    f"[SIMULATION MODE] Bulk unblock simulated for {ip_address}"
                )

            if ip_address in blocked_ips:
                del blocked_ips[ip_address]
                unblocked_count += 1
            elif f"{ip_address}/32" in blocked_ips:
                del blocked_ips[f"{ip_address}/32"]
                unblocked_count += 1
            elif '/' in ip_address and ip_address in blocked_ips:
                del blocked_ips[ip_address]
                unblocked_count += 1
            else:
                unblocked_count += 1  
            print(f"[BULK UNBLOCK] {ip_address} unblocked.")

        except Exception as e:
            print(f"[BULK UNBLOCK ERROR] Failed to unblock {ip_address}: {e}")

    if unblocked_count > 0:
        return {"status": "success", "message": f"Successfully unblocked {unblocked_count} IPs.", "unblocked_count": unblocked_count}
    else:
        return {"status": "warning", "message": "No IPs were found to unblock."}


@app.post("/admin/action/dismiss-all-alerts")
def dismiss_all_alerts_api(username: str = Depends(strict_token)):
    """
    Sets all alerts in the database (status != 'NORMAL') 
    to 'INACTIVE_SYSTEM' to clear the dashboard and notifications.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("""
            UPDATE alerts
            SET status = 'INACTIVE_SYSTEM'
            WHERE status != 'NORMAL' AND status != 'INACTIVE_SYSTEM'
        """)

        updated_rows = c.rowcount
        conn.commit()
        conn.close()

        print(
            f"[DISMISSAL SUCCESS] {updated_rows} alerts were set to INACTIVE_SYSTEM.")

        return {"status": "success", "message": f"Successfully dismissed {updated_rows} alerts."}

    except Exception as e:
        print(f"[DISMISSAL ERROR] Failed to dismiss alerts: {e}")
        return {"status": "error", "message": f"Database error during dismissal: {str(e)}"}


@app.get("/metrics/pattern")
def get_attack_patterns(username: str = Depends(verify_token)):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM alerts WHERE status = 'CRITICAL_ATTACK'")
        critical = c.fetchone()[0]

        c.execute("""
            SELECT COUNT(*) FROM alerts 
            WHERE LOWER(status) = 'attack_detected'
        """)
        high = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM alerts WHERE status = 'NORMAL'")
        normal = c.fetchone()[0]

        conn.close()

        return {
            "Critical": critical,
            "High": high,
            "Normal": normal
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/action/generate_report")
def get_report(username: str = Depends(soft_token)):
    """Generates a text report from all available data."""
    report_content = generate_report_content()

    return StreamingResponse(
        content=iter([report_content]),
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=security_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"}
    )


@app.get("/")
def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.post("/admin/action/import_blocklist")
async def import_blocklist(file: UploadFile = File(...), username: str = Depends(verify_token)):

    """
    Reads a file containing IPs (one per line) and adds them to the blocked_ips list
    for immediate firewall blocking.
    """
    global blocked_ips

    reason_data = {"reason": "Imported Blocklist", "file_name": file.filename}
    imported_count = 0

    try:
        content = await file.read()
        ip_list = content.decode('utf-8').splitlines()

        for ip in ip_list:
            ip = ip.strip()

            if ip and not ip.startswith('#'):
                if ip not in blocked_ips:
                    block_ip(ip, reason_data)
                    imported_count += 1

        if imported_count > 0:
            return {
                "status": "success",
                "message": f"Blocklist imported successfully. {imported_count} new IP/CIDR added.",
                "imported_count": imported_count
            }
        else:
            return {
                "status": "success",
                "message": "File processed, but no new valid IPs were added.",
                "imported_count": 0
            }

    except Exception as e:
        print(f"[IMPORT ERROR] Critical file import error: {e}")
        return {"status": "error", "message": f"Critical error during file processing: {str(e)}"}


@app.get("/admin/rules")
def get_active_rules(username: str = Depends(strict_token)):
    """Displays the active configuration parameters for the Detection Engine."""
    return {
        "status": DETECTION_SETTINGS["ACTIVE_STATUS"],
        "Failed_Login_Threshold": f"> {DETECTION_SETTINGS['FAILED_LOGIN_THRESHOLD']} in 5 min",
        "Distinct_Username_Threshold": f"> {DETECTION_SETTINGS['DISTINCT_USER_THRESHOLD']}",
        "Geolocation_Filter": DETECTION_SETTINGS["GEOLOCATION_FILTER"],
        "Rate_Limit_Status": "Enabled (10/min)"
    }


@app.post("/admin/action/block_range")
def block_ip_range(
    cidr_range: str = Query(..., description="E.g., 10.0.0.0/24"),
    username: str = Depends(verify_token)
):
    """Blocks an entire CIDR IP range."""

    import platform

    try:

        rule_name = f"ADMIN_BLOCK_{cidr_range.replace('.', '_').replace('/', '_')}"

        if platform.system() == "Windows":

            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f'name="{rule_name}"',
                "dir=in",
                "interface=any",
                "action=block",
                f"remoteip={cidr_range}"
            ]

            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                encoding='latin-1',
            )

            print(
                f"[BLOCK SUCCESS] Rule added: {rule_name}. Output: {result.stdout.strip()}"
            )

        else:

            print(
                f"[SIMULATION MODE] CIDR block simulated for {cidr_range}"
            )

        global blocked_ips

        blocked_ips[cidr_range] = {
            "reason": "Admin Manual Block",
            "time": time.time(),
            "rule": rule_name
        }

        save_blocked_ips()

        return {
            "status": "success",
            "message": f"Successfully blocked CIDR range: {cidr_range}",
            "rule": rule_name
        }

    except subprocess.CalledProcessError as e:

        error_output = e.stderr.strip() if e.stderr else "Unknown firewall error."

        print(f"[BLOCK ERROR] {error_output}")

        return {
            "status": "error",
            "message": f"Block Failed: {error_output}"
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/admin/action/export_logs")
def export_logs(username: str = Depends(verify_token)):
    """Safely exports blocked IP logs."""
    try:
        if not os.path.exists("blocked_ips.log"):
            return {"status": "error", "message": "No logs found. File blocked_ips.log missing."}

        processed_logs = []
        with open("blocked_ips.log", "r") as f:
            raw_lines = f.readlines()

        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                log_data = json.loads(line)

                reason = log_data.get("reason", {})

                attempts = reason.get("failed_attempts_last_5min", "N/A")
                users = reason.get("distinct_usernames_per_ip", "N/A")

                rule = log_data.get("rule", "N/A")
                ip = log_data.get("ip", "N/A")
                unblock_time = log_data.get("unblock_time")
                timestamp = log_data.get("timestamp", time.time())

                timestamp_readable = time.ctime(timestamp)

                summary = f"Failed Attempts={attempts}, Users={users}"

                formatted_line = f"[{timestamp_readable}] IP: {ip} BLOCKED. Rule: {rule}. Summary: {summary}"
                processed_logs.append(formatted_line)

            except Exception:
                processed_logs.append(f"[INVALID LOG ENTRY] {line}")

        return {"status": "success", "logs": processed_logs}

    except Exception as e:
        print("[EXPORT ERROR]", e)
        return {
            "status": "error",
            "message": f"Could not export logs: {str(e)}"
        }


@app.get("/admin/controls")
def get_security_controls(username: str = Depends(strict_token)) -> dict:
    """Returns the current status of all security controls."""
    print(f"[AUTH LOG] Controls accessed by user: {username}")

    return {**CONTROL_SETTING, "detection_settings": DETECTION_SETTINGS}


@app.post("/admin/controls/update")
def update_security_controls(
    auto_block: Union[bool, None] = None,
    sensitivity_value: Union[int, None] = Query(None, ge=0, le=100),
    failed_attempts: Union[int, None] = None,
    distinct_users: Union[int, None] = None,
    geo_countries: Union[str, None] = None,
    username: str = Depends(strict_token)
):
    print(f"[SETTINGS UPDATE] Controls updated by user: {username}")

    global CONTROL_SETTING, DETECTION_SETTINGS
    if sensitivity_value is not None:
        if sensitivity_value >= 50:
            CONTROL_SETTING["SENSITIVITY"] = "AGGRESSIVE"
        else:
            CONTROL_SETTING["SENSITIVITY"] = "CONSERVATIVE"

        CONTROL_SETTING["SENSITIVITY_VALUE0"] = sensitivity_value

        if auto_block is not None:
            CONTROL_SETTING["AUTO_BLOCK_ENABLED"] = auto_block

        if failed_attempts is not None:
            DETECTION_SETTINGS["FAILED_LOGIN_THRESHOLD"] = failed_attempts

        if distinct_users is not None:
            DETECTION_SETTINGS["DISTINCT_USER_THRESHOLD"] = distinct_users

        if geo_countries is not None:
            country_list = [c.strip()
                            for c in geo_countries.split(',') if c.strip()]
            DETECTION_SETTINGS["BLOCKED_COUNTRIES"] = country_list
            DETECTION_SETTINGS["GEOLOCATION_FILTER"] = "Enabled" if country_list else "Disabled"
    try:
        with open("control_settings.json", "w") as f:
            json.dump(CONTROL_SETTING, f, indent=4)
        print("[CONTROL SAVE] Settings persisted to disk.")
    except Exception as e:
        print(
            f"[CONTROL SAVE ERROR] Could not save control_settings.json: {e}")

    return {"status": "success", "current_setting": CONTROL_SETTING, "detection_settings": DETECTION_SETTINGS
            }


@app.post("/admin/controls/toggle_active")
def toggle_system(
    is_active: bool,
    username: str = Depends(verify_token)
):
    """Toggle the system state only if authentication passes."""
    print(
        f"[AUTH LOG] System state changed to {is_active} by user: {username}")

    global CONTROL_SETTING
    CONTROL_SETTING["SYSTEM_ACTIVE"] = is_active
    status = "ACTIVE" if is_active else "INACTIVE"
    return {"status": "success", "message": f"Security system state set to: {status}"}


@app.post("/admin/action/emergency_lock")
def activate_emergency_lock(username: str = Depends(strict_token)):
    """Immediately stops the system and resets all controls to their safest, most conservative defaults."""

    global CONTROL_SETTING

    CONTROL_SETTING["SYSTEM_ACTIVE"] = False

    CONTROL_SETTING["AUTO_BLOCK_ENABLED"] = True
    CONTROL_SETTING["SENSITIVITY"] = "CONSERVATIVE"
    CONTROL_SETTING["SENSITIVITY_VALUE0"] = 50

    print("[EMERGENCY] System Forcefully INACTIVE and Controls RESET to Conservative Defaults.")

    return {
        "status": "success",
        "message": "EMERGENCY LOCK activated. System is INACTIVE and controls have been reset to CONSERVATIVE."
    }


@app.get("/admin/verify_session")
def verify_session(authorization: str = Header(None)):
    """Verifies if the Authorization header is valid."""

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    auth = authorization.strip()

    if auth.lower().startswith("basic"):
        token = auth.split(" ", 1)[1]

    elif auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1]

    else:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization format"
        )

    try:

        jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGO]
        )

    except Exception as e:

        print("[VERIFY SESSION ERROR]", e)

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return {
        "status": "ok",
        "message": "Session still valid"
    }

@app.get("/generate-2fa")
def generate_2fa():

    totp = pyotp.TOTP(TOTP_SECRET)

    uri = totp.provisioning_uri(
        name="kaif786",
        issuer_name="Brute Force Detection"
    )

    img = qrcode.make(uri)

    qr_path = "2fa_qr.png"
    img.save(qr_path)

    return {
        "secret": TOTP_SECRET,
        "qr_saved_as": qr_path,
        "message": "Scan QR using Google Authenticator"
    }

@app.post("/verify-2fa")
def verify_2fa(code: str = Form(...)):

    totp = pyotp.TOTP(TOTP_SECRET)

    if totp.verify(code):
        return {"status": "success", "message": "2FA verified"}

    raise HTTPException(
        status_code=401,
        detail="Invalid OTP"
    )

@app.post("/register")
def register_user(data: RegisterInput):

    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE email = ?",
            (data.email,)
        )

        existing = c.fetchone()

        if existing:
            conn.close()
            return {
                "status": "error",
                "message": "Email already registered"
            }

        hashed_password = pwd_context.hash(data.password[:72])

        c.execute("""
            INSERT INTO users (full_name, email, password)
            VALUES (?, ?, ?)
        """, (
            data.full_name,
            data.email,
            hashed_password
        ))

        conn.commit()
        conn.close()

        return {
            "status": "success",
            "message": "Registration successful"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/admin/login")
def admin_login(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
    username: str = Form(None),
    password: str = Form(None)
):
    """
    Dual-mode login:
    - Browser / Swagger → HTTPBasic
    - Hydra / Attacker → Form-data
    """

    if username is not None and password is not None:
        if username == ADMIN_USER and pwd_context.verify(password[:72], ADMIN_PASSWORD_HASHED):
                token = create_token(username)
                return {"token": token}
        else:
            return JSONResponse(
                status_code=401,
                content={"detail": "Not authenticated"},
                headers={}
            )

    if credentials:
        if credentials.username == ADMIN_USER and pwd_context.verify(credentials.password[:72], ADMIN_PASSWORD_HASHED):
            token = create_token(credentials.username)
            return {"token": token}

    return JSONResponse(
        status_code=401,
        content={"detail": "Not authenticated"},
        headers={}
    )

@app.post("/login")
def user_login(
    email: str = Form(...),
    password: str = Form(...)
):

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        )

        user = c.fetchone()

        conn.close()

        if not user:
            return {
                "status": "error",
                "message": "User not found"
            }

        stored_password = user["password"]

        if not pwd_context.verify(password[:72], stored_password):
            return {
                "status": "error",
                "message": "Invalid password"
            }

        token = create_token(email)

        return {
            "status": "success",
            "token": token,
            "user": {
                "name": user["full_name"],
                "email": user["email"]
            }
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/admin/login-form")
async def admin_login_form(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip = get_client_ip(request)
    now = time.time()

    FAILED_COUNTER[client_ip] = FAILED_COUNTER.get(client_ip, 0) + 1
    USER_TRACKER.setdefault(client_ip, set()).add(username)

    last_time = LAST_ATTEMPT_TIME.get(client_ip, now)
    time_gap = round(now - last_time, 2)
    LAST_ATTEMPT_TIME[client_ip] = now

    print(f"[LOGIN ATTEMPT] IP={client_ip} FAILS={FAILED_COUNTER[client_ip]} GAP={time_gap}")

    if username == ADMIN_USER and pwd_context.verify(password[:72], ADMIN_PASSWORD_HASHED):
        FAILED_COUNTER.pop(client_ip, None)
        USER_TRACKER.pop(client_ip, None)
        LAST_ATTEMPT_TIME.pop(client_ip, None)
        ALERT_SENT.discard(client_ip)

        return JSONResponse(
            status_code=200,
            content={"status": "SUCCESS", "token": create_token(username)}
        )

    if (
        FAILED_COUNTER[client_ip] >= DETECTION_SETTINGS["FAILED_LOGIN_THRESHOLD"]
        and client_ip not in ALERT_SENT
    ):
        payload = {
            "failed_attempts_last_5min": FAILED_COUNTER[client_ip],
            "success_last_hour": 0,
            "distinct_usernames_per_ip": len(USER_TRACKER[client_ip]),
            "time_between_attempts": time_gap,
            "user_email": "kaifmalik9688@gmail.com"
        }

        try:
            BASE_URL = "https://brute-force-detection-dashboard.onrender.com"

            requests.post(
                f"{BASE_URL}/predict",
                json=payload,
                headers={"X-Forwarded-For": client_ip},
                timeout=3
            )
            ALERT_SENT.add(client_ip)
            print(f"[ALERT TRIGGERED] Predict + Email sent for IP {client_ip}")
        except Exception as e:
            print("[PREDICT ERROR]", e)

    return JSONResponse(
        status_code=200,
        content={"detail": "LOGIN_FAILED"}
    )




@app.get("/ping")
def ping(username: str = Depends(soft_token)):
    """Simple health check endpoint for forntend session verification."""
    return {"status": "ok", "message": "Server reachable"}


scheduler = AsyncIOScheduler()


def import_remote_blocklist_task():
    """Fetch remote blocklist and add new IPs automatically."""
    url = os.getenv("BLOCKLIST_URL", "")
    if not url:
        print("[AUTOMATION] No remote blocklist URL found.")
        return
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        added = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            if ip not in blocked_ips:
                reason = {"reason": "Remote blocklist auto-import"}
                block_ip(ip, reason)
                added += 1
        print(
            f"[AUTOMATION] Remote blocklist import done. Added {added} new IPs.")
    except Exception as e:
        print(f"[AUTOMATION ERROR] Remote blocklist fetch failed: {e}")


def auto_unblock_cleanup_task():
    """Automatically remove expired blocked IPs after TTL or unblock_time."""
    print(
        f"[DEBUG] Auto-Unblock Task running... now={time.time()} blocked_count={len(blocked_ips)}")

    now = time.time()
    removed = []
    for ip, meta in list(blocked_ips.items()):
        unblock_time = meta.get("unblock_time", 0)
        if unblock_time and now > unblock_time:
            print(f"[AUTO-UNBLOCK] {ip} expired.Removing firewall rule.")
            try:

                import platform

                if platform.system() == "Windows":

                    subprocess.run(
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            f"remoteip={ip}"
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False
                    )

                    print(f"[WINDOWS AUTO-UNBLOCK] {ip}")

                else:

                    print(
                        f"[SIMULATION MODE] Auto-unblock simulated for {ip}"
                    )

            except Exception as e:

                print(f"[WARN] Auto-unblock failed for {ip}: {e}")
            del blocked_ips[ip]
            removed.append(ip)
    if removed:
        save_blocked_ips()
        print(f"[AUTO-UNBLOCK] Removed {len(removed)} IPs: {removed}")


def adaptive_geo_decay_task():
    """Removes dynamic high-risk countries every 24 hours."""
    try:
        if DETECTION_SETTINGS["BLOCKED_COUNTRIES"]:
            print("[ADAPTIVE BLOCK] Cleaning old countries from dynamic list...")
            DETECTION_SETTINGS["BLOCKED_COUNTRIES"] = DETECTION_SETTINGS["BLOCKED_COUNTRIES"][:4]
            print("[ADAPTIVE BLOCK] Reset dynamic countries, kept static entries safe.")
    except Exception as e:
        print(f"[ADAPTIVE BLOCK CLEANUP ERROR] {e}")


def daily_report_task():
    """Generate a report and email it automatically every day."""
    try:
        report = generate_report_content()
        admin_email = os.getenv("ADMIN_EMAIL", SMTP_USER)
        msg = EmailMessage()
        msg["Subject"] = "Daily Security Report - Brute Force System"
        msg["From"] = SMTP_USER
        msg["To"] = admin_email
        msg.set_content(report)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
            smtp.send_message(msg)
        print(
            f"[AUTOMATION] Daily report emailed successfully to {admin_email}")
    except Exception as e:
        print(f"[AUTOMATION ERROR] Daily report failed: {e}")


def adaptive_sensitivity_task():
    """
    Periodic task that examines recent critical attacks and flips the CONTROL_SETTING['SENSITIVITY']
    between 'AGGRESSIVE' and 'CONSERVATIVE' automatically.
    """
    print("[DEBUG] Adaptive sensitivity task running...")

    global CONTROL_SETTING

    now = time.time()
    cutoff = now - RECENT_ATTACK_WINDOW_SECONDS

    try:
        with RECENT_ATTACKS_LOCK:
            while recent_critical_attacks and recent_critical_attacks[0] < cutoff:
                recent_critical_attacks.pop(0)
            recent_count = len(recent_critical_attacks)

        if recent_count >= AGGRESSIVE_CRITICAL_THRESHOLD:
            if CONTROL_SETTING.get("SENSITIVITY") != "AGGRESSIVE":
                CONTROL_SETTING["SENSITIVITY"] = "AGGRESSIVE"
                CONTROL_SETTING["SENSITIVITY_VALUE0"] = max(
                    CONTROL_SETTING.get("SENSITIVITY_VALUE0", 50), 75)
                print(
                    f"[ADAPTIVE SENSITIVITY] Elevated to AGGRESSIVE (recent_critical={recent_count}).")
                with open("control_settings.json", "w") as f:
                    json.dump(CONTROL_SETTING, f, indent=4)
        else:
            last_ts = None
            with RECENT_ATTACKS_LOCK:
                if recent_critical_attacks:
                    last_ts = recent_critical_attacks[-1]
            if last_ts is None or (now - last_ts) > RESTORE_TO_CONSERVATIVE_AFTER_SECONDS:
                if CONTROL_SETTING.get("SENSITIVITY") != "CONSERVATIVE":
                    CONTROL_SETTING["SENSITIVITY"] = "CONSERVATIVE"
                    CONTROL_SETTING["SENSITIVITY_VALUE0"] = min(
                        CONTROL_SETTING.get("SENSITIVITY_VALUE0", 75), 50)
                    print(
                        f"[ADAPTIVE SENSITIVITY] Restored to CONSERVATIVE (recent_critical={recent_count}).")
                    with open("control_settings.json", "w") as f:
                        json.dump(CONTROL_SETTING, f, indent=4)

    except Exception as e:
        print(f"[ADAPTIVE SENSITIVITY ERROR] {e}")


def load_control_settings_from_disk():
    global CONTROL_SETTING
    try:
        if os.path.exists("control_settings.json"):
            with open("control_settings.json", "r") as f:
                saved = json.load(f)
                saved["SYSTEM_ACTIVE"] = True
                CONTROL_SETTING.update(saved)
            print("[PERSIST] Control settings loaded from disk ✅")

    except Exception as e:
        print(f"[WARN] Could not load control_settings.json: {e}")


@app.on_event("startup")
def start_automation_scheduler():
    """Start the automation scheduler when FastAPI boots."""
    try:
        print("[STARTUP] Initialization started...")
        initialize_db()
        load_blocked_ips()
        load_admin_hash_on_startup()
        load_control_settings_from_disk()

        if not scheduler.running:
            scheduler.add_job(import_remote_blocklist_task, IntervalTrigger(
                minutes=30), id="import_blocklist", replace_existing=True)
            scheduler.add_job(
                auto_unblock_cleanup_task,
                'interval',
                seconds= 30,
                id="auto_unblock",
                replace_existing=True
            )
            scheduler.add_job(
                adaptive_sensitivity_task,
                'interval',
                seconds=30,
                id="adaptive_sensitivity",
                replace_existing=True
            )
            scheduler.add_job(adaptive_geo_decay_task, IntervalTrigger(
                hours=24), id="geo_decay", replace_existing=True)
            time_str = os.getenv("DAILY_REPORT_TIME", "03:00")
            hh, mm = map(int, time_str.split(":"))
            scheduler.add_job(daily_report_task, CronTrigger(
                hour=hh, minute=mm), id="daily_report", replace_existing=True)
            scheduler.start()
            print(
                "[AUTOMATION] Scheduler started with import, cleanup, and report tasks.")
    except Exception as e:
        print(f"[AUTOMATION ERROR] Scheduler start failed: {e}")


@app.on_event("shutdown")
def stop_automation_scheduler():
    """Stop scheduler on app shutdown."""
    try:
        save_blocked_ips()
        if scheduler.running:
            scheduler.shutdown(wait=False)
            print("[AUTOMATION] Scheduler stopped.")
    except Exception as e:
        print(f"[AUTOMATION ERROR] Scheduler shutdown failed: {e}")


if __name__ == "__main__":
    print("[SYSTEM] All modules initialized. Automation and Security Engine online ✅")
    print("🚀 FastAPI Backend is starting...")
    print("📍 visit: http://127.0.0.1:8001/docs or /redoc for API reference.")
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=True)

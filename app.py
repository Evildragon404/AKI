import os
import json
import signal
import subprocess
import shutil
import zipfile
import hashlib
import hmac
import psutil
import threading
import time
import sys
import shlex
import re
import secrets
import stat
import logging
import platform
import tempfile
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager
from pathlib import Path
import pathlib
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from werkzeug.exceptions import HTTPException

# Private account metadata and operational logs should not be world-readable.
os.umask(0o077)

try:
    import fcntl
except ImportError:  # Windows development fallback; deployments use POSIX file locks.
    fcntl = None
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1").lower() not in {"0", "false", "no"},
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("TEAM_AKI_DATA_DIR", str(BASE_DIR))).expanduser()
if not DATA_DIR.is_absolute():
    DATA_DIR = (BASE_DIR / DATA_DIR).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "data.json"
SERVERS_DIR = DATA_DIR / "servers"
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
SHARED_PYTHON_ENV = DATA_DIR / "shared-python-env"
SHARED_PYTHON_LOCK_FILE = DATA_DIR / ".shared-python.lock"
LOG_FILE = DATA_DIR / "app.log"

DEFAULT_USERNAME = os.environ.get("DEFAULT_USERNAME", "aki").strip().lower() or "aki"
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", DEFAULT_USERNAME).strip().lower() or DEFAULT_USERNAME
DEFAULT_PASSWORD = os.environ.get("DEFAULT_PASSWORD", "aki")
PROCESS_STARTED_AT = time.monotonic()

# Thread locks protect concurrent requests; the lock file also coordinates
# Gunicorn processes that share the same persistent data directory.
DATA_LOCK = threading.RLock()
SHARED_PYTHON_LOCK = threading.RLock()
SERVER_LOCKS = {}
SERVER_LOCKS_LOCK = threading.Lock()
LOGIN_LOCK = threading.Lock()
RUNNING_PROCESSES = {}
LOGIN_FAILURES = {}
RESTARTING = set()
RESTART_LOCK = threading.Lock()
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{2,20}$")
MAX_ZIP_FILES = 2000
MAX_ZIP_UNPACKED = 200 * 1024 * 1024


class JsonLogFormatter(logging.Formatter):
    """Emit machine-readable operational logs for diagnostics and ingestion."""
    def format(self, record):
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).astimezone().isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("event", "details", "request_id", "method", "path", "status_code", "duration_ms", "remote_addr", "username"):
            value = getattr(record, field, None)
            if value is not None:
                entry[field] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


class ColorConsoleFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[90m", "INFO": "\033[36m", "WARNING": "\033[33m",
        "ERROR": "\033[31m", "CRITICAL": "\033[1;31m",
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        message = super().format(record)
        return f"{color}{message}{self.RESET}" if color else message


logger = logging.getLogger("team_aki")
logger.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO))
logger.propagate = False
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorConsoleFormatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(console_handler)
    try:
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8")
        file_handler.setFormatter(JsonLogFormatter())
        logger.addHandler(file_handler)
        try:
            os.chmod(LOG_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        logger.exception("Application file logging is unavailable; console logging remains active")

if not os.environ.get("SECRET_KEY"):
    logger.warning("SECRET_KEY is not set; a temporary key was generated for this process. Set a stable secret for persistent deployments.")


def log_event(event, level=logging.INFO, **details):
    """Record a structured operational event without secrets or credentials."""
    logger.log(level, event, extra={"event": event, "details": details})


def _default_data():
    return {
        "servers": {},
        "users": {},
        "settings": {
            "maintenance": False,
            "maintenance_msg": "System under maintenance.",
            "theme_color": "#ffc83d",
            "site_name": "TEAM AKI",
            "auto_restart_interval": 300,
        },
    }


@contextmanager
def _storage_lock():
    """Serialize state reads/writes across threads and POSIX worker processes."""
    with DATA_LOCK:
        lock_path = DATA_DIR / ".data.lock"
        with lock_path.open("a+") as lock_handle:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _read_data_unlocked():
    if DATA_FILE.exists():
        try:
            parsed = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("data.json root must be an object")
            parsed.setdefault("servers", {})
            parsed.setdefault("users", {})
            parsed.setdefault("settings", {})
            if not isinstance(parsed["servers"], dict) or not isinstance(parsed["users"], dict) or not isinstance(parsed["settings"], dict):
                raise ValueError("data.json has an invalid section type")
            if any(not isinstance(account, dict) for account in parsed["users"].values()):
                raise ValueError("data.json contains an invalid account record")
            if any(not isinstance(config, dict) for config in parsed["servers"].values()):
                raise ValueError("data.json contains an invalid project record")
            safe_users = {username: account for username, account in parsed["users"].items()
                          if isinstance(username, str) and USERNAME_RE.fullmatch(username)}
            safe_servers = {name: config for name, config in parsed["servers"].items()
                            if isinstance(name, str) and SERVER_NAME_RE.fullmatch(name) and name not in {".", ".."}}
            if len(safe_users) != len(parsed["users"]) or len(safe_servers) != len(parsed["servers"]):
                logger.warning("Ignoring unsafe account or project keys in data.json")
            parsed["users"] = safe_users
            parsed["servers"] = safe_servers
            return parsed
        except (OSError, json.JSONDecodeError, ValueError):
            # Preserve a damaged store for manual recovery instead of silently
            # destroying the only copy when the app initializes a new store.
            try:
                backup = DATA_DIR / f"data.json.corrupt-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                shutil.copy2(DATA_FILE, backup)
            except OSError:
                pass
            logger.exception("State store could not be read; using an empty recovery state")
    return _default_data()


def _write_data_unlocked(data):
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=DATA_DIR, prefix=".data-", suffix=".tmp", delete=False
        ) as temp_file:
            temporary_path = Path(temp_file.name)
            try:
                os.fchmod(temp_file.fileno(), 0o600)
            except (AttributeError, OSError):
                pass
            json.dump(data, temp_file, indent=2, ensure_ascii=False, default=str)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temporary_path, DATA_FILE)
        try:
            os.chmod(DATA_FILE, 0o600)
            dir_fd = os.open(DATA_DIR, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        logger.exception("Failed to persist application state")
        raise


def load_data():
    with _storage_lock():
        return _read_data_unlocked()


def save_data(data):
    """Atomically replace JSON state. Use data_transaction for read-modify-write."""
    with _storage_lock():
        _write_data_unlocked(data)


@contextmanager
def data_transaction():
    """Lock, reload, mutate, and atomically commit the latest JSON state."""
    with _storage_lock():
        data = _read_data_unlocked()
        yield data
        _write_data_unlocked(data)


def get_server_lock(name):
    with SERVER_LOCKS_LOCK:
        return SERVER_LOCKS.setdefault(name, threading.RLock())


def server_locked(func):
    """Validate a project identifier and serialize access to its files/process."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        name = kwargs.get("name")
        if name is None:
            return func(*args, **kwargs)
        if not isinstance(name, str) or not SERVER_NAME_RE.fullmatch(name) or name in {".", ".."}:
            return "Server not found", 404
        with get_server_lock(name):
            return func(*args, **kwargs)
    return wrapper


def hash_password(password):
    """Use Werkzeug's adaptive password hash for all newly stored passwords."""
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash, password):
    """Verify modern hashes and transparently migrate legacy SHA-256 hashes."""
    stored_hash = str(stored_hash or "")
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_hash, password), False
        except (ValueError, TypeError):
            return False, False
    legacy = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(stored_hash, legacy), True


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def protect_post_requests():
    g.request_started_at = time.monotonic()
    g.request_id = secrets.token_hex(8)
    if request.method == "POST":
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
            log_event("csrf_rejected", level=logging.WARNING, method=request.method, path=request.path,
                      remote_addr=request.remote_addr or "unknown")
            return jsonify({"success": False, "error": "Your session expired. Refresh the page and try again."}), 400


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.path != "/api/ping" and not request.path.startswith("/static/"):
        started = getattr(g, "request_started_at", time.monotonic())
        logger.info("http_request", extra={
            "event": "http_request", "request_id": getattr(g, "request_id", None),
            "method": request.method, "path": request.path,
            "status_code": response.status_code,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "remote_addr": request.remote_addr or "unknown",
            "username": session.get("username"),
        })
    return response


@app.errorhandler(Exception)
def handle_unexpected_exception(error):
    if isinstance(error, HTTPException):
        return error
    request_id = getattr(g, "request_id", "unknown")
    logger.exception("Unhandled request exception", extra={
        "event": "unhandled_exception", "request_id": request_id,
        "method": request.method, "path": request.path,
        "username": session.get("username"),
    })
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"success": False, "error": "An unexpected server error occurred.", "request_id": request_id}), 500
    return render_template("error.html", request_id=request_id), 500


def initialize_database():
    """Create the primary account and normalize/migrate the persistent schema."""
    with data_transaction() as data:
        data.setdefault("servers", {})
        users = data.setdefault("users", {})
        users.setdefault(DEFAULT_USERNAME, {
            "joined": datetime.now().isoformat(),
            "password_hash": hash_password(DEFAULT_PASSWORD),
        })
        for username, account in users.items():
            account.setdefault("role", "admin" if username == ADMIN_USERNAME else "user")
        if ADMIN_USERNAME in users:
            users[ADMIN_USERNAME]["role"] = "admin"
        settings = data.setdefault("settings", {})
        settings.pop("normal_password", None)
        settings.setdefault("site_name", "TEAM AKI")
        settings.setdefault("maintenance", False)
        settings.setdefault("maintenance_msg", "System under maintenance.")
        settings.setdefault("theme_color", "#ffc83d")
        settings.setdefault("auto_restart_interval", 300)
        for cfg in data["servers"].values():
            cfg.setdefault("owner", DEFAULT_USERNAME)
            cfg.setdefault("manual_stop", False)
            cfg.setdefault("auto_restart_armed", bool(cfg.get("pid") or cfg.get("status") == "running"))
    log_event("database_initialized", accounts=len(data.get("users", {})), projects=len(data.get("servers", {})))

initialize_database()
log_event("application_started", pid=os.getpid(), python=platform.python_version(), data_dir=str(DATA_DIR))

def get_theme_color():
    data = load_data()
    return data.get("settings", {}).get("theme_color", "#00ff41")

@app.context_processor
def inject_theme():
    return {"theme_color": get_theme_color(), "csrf_token": csrf_token}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        data = load_data()
        if session.get("username") not in data.get("users", {}):
            session.clear()
            return redirect(url_for("login"))
        session["is_admin"] = session.get("username") == ADMIN_USERNAME
        settings = data.get("settings", {})
        if settings.get("maintenance"):
            return render_template("maintenance.html", message=settings.get("maintenance_msg", "Under maintenance"), site_name=settings.get("site_name", "ZX JIHAD HOST"), theme_color=get_theme_color())
        return f(*args, **kwargs)
    return decorated


def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("username") != ADMIN_USERNAME:
            return "Administrator access required", 403
        return func(*args, **kwargs)
    return wrapper

def _process_create_time(pid):
    try:
        return psutil.Process(int(pid)).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
        return None


def is_process_alive(pid, expected_create_time=None):
    """Only trust persisted PIDs when their recorded creation time matches."""
    try:
        if not pid or expected_create_time is None:
            return False
        process = psutil.Process(int(pid))
        if abs(process.create_time() - float(expected_create_time)) > 0.01:
            return False
        return process.is_running() and process.status() not in {psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD}
    except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
        return False


def kill_process(pid, expected_create_time=None):
    """Terminate a process tree only when its recorded identity is verified."""
    try:
        if not pid or expected_create_time is None:
            logger.warning("Refusing to terminate unverified PID %s", pid)
            return
        process = psutil.Process(int(pid))
        if abs(process.create_time() - float(expected_create_time)) > 0.01:
            logger.warning("Refusing to terminate PID %s because its creation time changed", pid)
            return
        descendants = process.children(recursive=True)
        for child in reversed(descendants):
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return
        _gone, alive = psutil.wait_procs([process, *descendants], timeout=5)
        for survivor in alive:
            try:
                survivor.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if alive:
            psutil.wait_procs(alive, timeout=2)
    except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, ValueError):
        return


PROJECT_IGNORED_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".git", ".pytest_cache", ".mypy_cache"}


def _walk_project_files(project_dir, filename=None):
    """Yield safe project files in stable root-first order, skipping generated folders."""
    project_dir = Path(project_dir).resolve()
    candidates = []
    if not project_dir.is_dir():
        return candidates
    for current, dirs, files in os.walk(project_dir, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            d for d in dirs
            if d not in PROJECT_IGNORED_DIRS and not d.startswith(".")
            and not (current_path / d).is_symlink()
        )
        for item in files:
            if filename is not None and item != filename:
                continue
            full_path = current_path / item
            if full_path.is_symlink() or not full_path.is_file():
                continue
            candidates.append(full_path)
    return sorted(candidates, key=lambda p: (len(p.relative_to(project_dir).parts), str(p).lower()))


def find_project_file(project_dir, filename):
    """Find a manifest/entry file at the root or in a single-folder ZIP wrapper."""
    matches = _walk_project_files(project_dir, filename)
    return matches[0] if matches else None


def auto_detect_main_file(extract_dir, runtime=None):
    """Detect the most likely entry point for the selected runtime, including ZIP wrappers."""
    extract_dir = Path(extract_dir).resolve()
    runtime = (runtime or "python").lower()
    if runtime == "static":
        index_file = find_project_file(extract_dir, "index.html")
        return index_file.relative_to(extract_dir).as_posix() if index_file else "index.html"

    candidates_by_runtime = {
        "python": ("main.py", "app.py", "bot.py", "run.py", "index.py"),
        "node": ("index.js", "server.js", "main.js", "app.js", "bot.js", "index.mjs", "index.ts"),
        "php": ("index.php", "main.php", "app.php"),
        "go": ("main.go",),
        "sh": ("start.sh", "main.sh", "run.sh", "index.sh"),
    }
    candidates = candidates_by_runtime.get(runtime, candidates_by_runtime["python"])
    for filename in candidates:
        matches = _walk_project_files(extract_dir, filename)
        if matches:
            return matches[0].relative_to(extract_dir).as_posix()

    extensions_by_runtime = {
        "python": {".py"}, "node": {".js", ".mjs", ".cjs", ".ts"},
        "php": {".php"}, "go": {".go"}, "sh": {".sh"},
    }
    allowed = extensions_by_runtime.get(runtime, {".py", ".js", ".mjs", ".cjs", ".ts", ".php", ".go", ".sh"})
    for path in _walk_project_files(extract_dir):
        if path.suffix.lower() in allowed:
            return path.relative_to(extract_dir).as_posix()
    default_names = {"python": "main.py", "node": "index.js", "php": "index.php", "go": "main.go", "sh": "start.sh"}
    return default_names.get(runtime, "main.py")

def build_project_environment():
    """Copy the runtime environment while excluding likely host credentials."""
    blocked_fragments = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "APIKEY")
    blocked_exact = {"SECRET_KEY", "DEFAULT_PASSWORD", "FLASK_SECRET_KEY"}
    env = {}
    for key, value in os.environ.items():
        upper_key = key.upper()
        if upper_key in blocked_exact or any(fragment in upper_key for fragment in blocked_fragments):
            continue
        env[key] = value
    return env


@contextmanager
def shared_python_package_lock():
    """Serialize writes to the shared Python environment across threads/workers."""
    with SHARED_PYTHON_LOCK:
        with SHARED_PYTHON_LOCK_FILE.open("a+") as lock_handle:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def ensure_shared_python_env(log_path=None):
    """Create one persistent Python environment shared by all hosted Python projects."""
    python_path = SHARED_PYTHON_ENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    marker = SHARED_PYTHON_ENV / ".team_aki_shared_python"
    try:
        with shared_python_package_lock():
            if SHARED_PYTHON_ENV.is_symlink():
                raise RuntimeError("Shared Python environment path is a symbolic link")
            expected_version = f"{sys.version_info.major}.{sys.version_info.minor}"
            if python_path.is_file() and marker.is_file():
                try:
                    marker_version = marker.read_text(encoding="utf-8").strip().splitlines()[-1]
                except (OSError, IndexError):
                    marker_version = ""
                if marker_version == expected_version:
                    return python_path
            if SHARED_PYTHON_ENV.exists():
                shutil.rmtree(SHARED_PYTHON_ENV)
            result = subprocess.run(
                [sys.executable, "-m", "venv", str(SHARED_PYTHON_ENV)],
                capture_output=True, text=True, timeout=180, env=build_project_environment(),
            )
            if result.returncode != 0 or not python_path.is_file():
                detail = (result.stderr or result.stdout or "venv creation did not produce a Python executable")[-1600:]
                raise RuntimeError(detail)
            marker.write_text(f"TEAM AKI shared Python environment\n{sys.version_info.major}.{sys.version_info.minor}\n", encoding="utf-8")
            try:
                os.chmod(marker, 0o600)
            except OSError:
                pass
            return python_path
    except Exception as exc:
        logger.warning("Could not create shared Python environment at %s: %s", SHARED_PYTHON_ENV, exc)
        if log_path:
            try:
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write(f"[SYSTEM WARNING] Shared Python environment unavailable; falling back to panel Python: {exc}\n")
            except OSError:
                pass
        return Path(sys.executable)


def ensure_project_venv(extract_dir, log_path=None):
    """Compatibility wrapper retained for existing integrations; environments are host-shared."""
    return ensure_shared_python_env(log_path)


def _project_python_paths(extract_dir):
    root = Path(extract_dir).resolve()
    paths = [root]
    for candidate in (root / "src", root / "app", root / "lib"):
        if candidate.is_dir() and not candidate.is_symlink():
            paths.append(candidate)
    return list(dict.fromkeys(str(path) for path in paths))


def python_dependency_specs(extract_dir):
    """Return pip install commands for common Python dependency manifests."""
    root = Path(extract_dir).resolve()
    specs = []
    requirements = find_project_file(root, "requirements.txt")
    if requirements:
        specs.append((["install", "-r", str(requirements)], requirements.parent,
                      requirements.relative_to(root).as_posix()))

    pyproject = find_project_file(root, "pyproject.toml")
    setup_py = find_project_file(root, "setup.py")
    if pyproject:
        try:
            pyproject_text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pyproject_text = ""
        if "[project]" in pyproject_text or "[build-system]" in pyproject_text or setup_py:
            specs.append((["install", "-e", str(pyproject.parent)], pyproject.parent,
                          pyproject.relative_to(root).as_posix() + " (editable project install)"))
    elif setup_py:
        specs.append((["install", "-e", str(setup_py.parent)], setup_py.parent,
                      setup_py.relative_to(root).as_posix() + " (editable project install)"))
    return specs


def prepare_environment_and_deps(extract_dir, log_path, runtime="python"):
    env = build_project_environment()
    extract_dir = Path(extract_dir).resolve()
    paths = _project_python_paths(extract_dir)
    existing_pythonpath = env.get("PYTHONPATH", "")
    new_pythonpath = os.pathsep.join(paths)
    env["PYTHONPATH"] = f"{new_pythonpath}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else new_pythonpath
    project_python = None

    try:
        if runtime == "node":
            pkg_json = find_project_file(extract_dir, "package.json")
            if pkg_json and not (pkg_json.parent / "node_modules").exists():
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write(f"\n[SYSTEM] Installing Node.js dependencies from {pkg_json.relative_to(extract_dir)}...\n")
                result = subprocess.run(["npm", "install"], cwd=str(pkg_json.parent), capture_output=True,
                                        text=True, timeout=600, env=env)
                if result.returncode:
                    with open(log_path, "a", encoding="utf-8") as handle:
                        handle.write((result.stderr or result.stdout or "npm install failed")[-3000:] + "\n")
        elif runtime == "python":
            project_python = ensure_shared_python_env(log_path)
            try:
                project_python.relative_to(SHARED_PYTHON_ENV)
                using_shared_env = True
            except ValueError:
                using_shared_env = False
            if using_shared_env:
                env["VIRTUAL_ENV"] = str(SHARED_PYTHON_ENV)
                env["PATH"] = str(project_python.parent) + os.pathsep + env.get("PATH", "")

            dependency_specs = python_dependency_specs(extract_dir)
            install_success = True
            for install_args, install_cwd, manifest_label in dependency_specs:
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write(f"\n[SYSTEM] Installing dependencies from {manifest_label} into the shared host Python environment...\n")
                result = pip_run(install_args, cwd=str(install_cwd), project_root=extract_dir)
                if result.returncode:
                    install_success = False
                    with open(log_path, "a", encoding="utf-8") as handle:
                        handle.write((result.stderr or result.stdout or "pip install failed")[-3000:] + "\n")
            if dependency_specs and install_success and using_shared_env:
                # Reclaim space from old panel-created environments only after the
                # shared environment has successfully consumed the project's manifests.
                legacy_env = extract_dir / ".venv"
                legacy_marker = legacy_env / ".team_aki_venv"
                if legacy_env.is_dir() and not legacy_env.is_symlink() and legacy_marker.is_file():
                    shutil.rmtree(legacy_env, ignore_errors=True)
                    with open(log_path, "a", encoding="utf-8") as handle:
                        handle.write("[SYSTEM] Migrated project dependencies to the shared host environment; removed the old project .venv to save disk space.\n")
    except Exception as exc:
        logger.exception("Project dependency preparation failed for %s", extract_dir.name)
        try:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"\n[SYSTEM WARNING] Dependency preparation error: {exc}\n")
        except OSError:
            pass

    return env, project_python

def get_run_command(runtime, main_file, python_executable=None):
    ext = Path(main_file).suffix.lower()
    if runtime == "node" or ext in (".js", ".ts", ".mjs"):
        return ["node", main_file]
    elif runtime == "php" or ext == ".php":
        return ["php", main_file]
    elif runtime == "go" or ext == ".go":
        return ["go", "run", main_file]
    elif runtime == "sh" or ext == ".sh":
        return ["bash", main_file]
    elif runtime == "static":
        return [sys.executable, "-m", "http.server", "8080", "--bind", "0.0.0.0"]
    else:
        return [str(python_executable or sys.executable), "-u", main_file]

def _sync_process_status():
    changed = False
    with data_transaction() as data:
        for cfg in data.get("servers", {}).values():
            pid = cfg.get("pid")
            if pid and not is_process_alive(pid, cfg.get("process_created_at")):
                cfg["status"] = "stopped"
                cfg["pid"] = None
                cfg.pop("process_created_at", None)
                changed = True
    if changed:
        log_event("process_state_reconciled")

_sync_process_status()

# Self-pinging background keep-alive loops were removed: they created duplicate
# traffic and can mask unhealthy deployments. Use the lightweight health endpoint.
@app.route("/api/ping")
def ping():
    return "pong", 200


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"success": False, "error": "Upload exceeds the 64 MB limit"}), 413


# ==================== AUTO RESTART SYSTEM ====================
def auto_restart_server(name):
    with RESTART_LOCK:
        if name in RESTARTING:
            return
        RESTARTING.add(name)

    proc = None
    process_created_at = None
    log_file = None
    log_path = SERVERS_DIR / name / "logs.txt"
    try:
        with get_server_lock(name):
            data = load_data()
            cfg = data.get("servers", {}).get(name)
            if not cfg or cfg.get("manual_stop", False) or not cfg.get("auto_restart_armed", False):
                return

            pid = cfg.get("pid")
            if pid and is_process_alive(pid, cfg.get("process_created_at")):
                kill_process(pid, cfg.get("process_created_at"))
            entry = RUNNING_PROCESSES.pop(name, None)
            if entry:
                try:
                    if entry["proc"].poll() is None:
                        kill_process(entry["proc"].pid, entry.get("created_at") or cfg.get("process_created_at"))
                except Exception:
                    logger.exception("Could not stop prior in-memory process for %s", name)
                try:
                    entry["log_file"].close()
                except Exception:
                    logger.exception("Could not close prior project log handle for %s", name)

            extract_dir = SERVERS_DIR / name / "extracted"
            main_file = cfg.get("main_file") or auto_detect_main_file(extract_dir, cfg.get("runtime", "python"))
            main_cmd = cfg.get("main_command") or ""
            main_path = (extract_dir / main_file).resolve()
            runtime = cfg.get("runtime", "python")
            if extract_dir.resolve() not in main_path.parents and main_path != extract_dir.resolve():
                log_event("auto_restart_rejected_path", level=logging.WARNING, project=name)
                return
            if runtime == "static":
                static_index = find_project_file(extract_dir, "index.html")
                if not static_index:
                    return
                main_file = static_index.relative_to(extract_dir).as_posix()
                main_path = static_index
            elif not main_path.is_file():
                return

            try:
                port = int(cfg.get("port", 8080))
            except (TypeError, ValueError):
                port = 8080
            if not 1024 <= port <= 65535:
                raise ValueError("Project port is outside the allowed range")

            env, project_python = prepare_environment_and_deps(extract_dir, log_path, runtime)
            env["PORT"] = str(port)
            if main_cmd:
                cmd = shlex.split(main_cmd)
                if not cmd:
                    raise ValueError("Custom command is empty")
            elif runtime == "static":
                cmd = [sys.executable, "-m", "http.server", str(port), "--bind", "0.0.0.0"]
            else:
                cmd = get_run_command(runtime, main_file, project_python)
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"\n{'='*50}\n[{datetime.now().isoformat()}] AUTO-RESTART triggered\n{'='*50}\n")
            log_file = open(log_path, "a", encoding="utf-8")
            launch_cwd = main_path.parent if runtime == "static" else extract_dir
            if not main_cmd and runtime != "static":
                launch_cwd = main_path.parent
                command_entry = main_path.name
                if runtime == "go":
                    go_mod = find_project_file(extract_dir, "go.mod")
                    if go_mod and go_mod.parent in main_path.parents:
                        launch_cwd = go_mod.parent
                        command_entry = main_path.relative_to(launch_cwd).as_posix()
                cmd = get_run_command(runtime, command_entry, project_python)
            proc = subprocess.Popen(cmd, cwd=str(launch_cwd), stdout=log_file, stderr=log_file,
                                    env=env, start_new_session=True, close_fds=True)
            process_created_at = _process_create_time(proc.pid)
            RUNNING_PROCESSES[name] = {"proc": proc, "log_file": log_file, "created_at": process_created_at}

            with data_transaction() as latest:
                fresh_cfg = latest.get("servers", {}).get(name)
                if not fresh_cfg or fresh_cfg.get("owner") != cfg.get("owner"):
                    kill_process(proc.pid, process_created_at)
                    RUNNING_PROCESSES.pop(name, None)
                    log_file.close()
                    log_file = None
                    proc = None
                    return
                fresh_cfg.update({"status": "running", "pid": proc.pid, "auto_restart_armed": True,
                                  "process_created_at": process_created_at})
            log_event("project_auto_restarted", project=name, pid=proc.pid, runtime=runtime)
    except Exception:
        logger.exception("Auto-restart failed for project %s", name)
        if proc is not None:
            try:
                kill_process(proc.pid, process_created_at)
            except Exception:
                logger.exception("Could not terminate failed auto-restart process for %s", name)
            current = RUNNING_PROCESSES.get(name)
            if current and current.get("proc") is proc:
                RUNNING_PROCESSES.pop(name, None)
        if log_file is not None and not log_file.closed:
            try:
                log_file.close()
            except OSError:
                logger.exception("Could not close auto-restart log handle for %s", name)
        try:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"[AUTO-RESTART ERROR] {datetime.now().isoformat()}\n")
        except OSError:
            pass
    finally:
        with RESTART_LOCK:
            RESTARTING.discard(name)

def auto_restart_monitor():
    while True:
        try:
            data = load_data()
            settings = data.get("settings", {})
            try:
                interval = max(30, min(3600, int(settings.get("auto_restart_interval", 300))))
            except (TypeError, ValueError):
                interval = 300

            for name, cfg in data.get("servers", {}).items():
                pid = cfg.get("pid")
                if pid and not is_process_alive(pid, cfg.get("process_created_at")):
                    with data_transaction() as latest:
                        fresh_cfg = latest.get("servers", {}).get(name)
                        if fresh_cfg and fresh_cfg.get("pid") == pid:
                            fresh_cfg["status"] = "stopped"
                            fresh_cfg["pid"] = None
                            fresh_cfg.pop("process_created_at", None)
                    log_event("project_process_exited", project=name, pid=pid, level=logging.WARNING)
                    cfg["status"] = "stopped"
                    cfg["pid"] = None
                    cfg.pop("process_created_at", None)

                if (cfg.get("status") == "stopped" and not cfg.get("manual_stop", False)
                        and cfg.get("auto_restart_armed", False)):
                    extract_dir = SERVERS_DIR / name / "extracted"
                    main_file = cfg.get("main_file") or auto_detect_main_file(extract_dir, cfg.get("runtime", "python"))
                    if ((cfg.get("runtime") == "static" and find_project_file(extract_dir, "index.html")) or
                            (cfg.get("runtime") != "static" and (extract_dir / main_file).is_file())):
                        threading.Thread(target=auto_restart_server, args=[name], daemon=True,
                                         name=f"auto-restart-{name}").start()
            time.sleep(interval)
        except Exception:
            logger.exception("Auto-restart monitor iteration failed")
            time.sleep(30)

threading.Thread(target=auto_restart_monitor, daemon=True).start()

# ==================== LANDING + LOGIN ====================

def site_name_value():
    return load_data().get("settings", {}).get("site_name", "TEAM AKI")

@app.route("/")
def landing():
    # First page: landing screen. START button -> login page.
    if session.get("username"):
        return redirect(url_for("dashboard"))
    data = load_data()
    return render_template("landing.html", site_name=site_name_value(),
                           total_users=len(data.get("users", {})),
                           total_servers=len(data.get("servers", {})),
                           theme_color=get_theme_color())

def login_is_limited(client_ip):
    now = time.monotonic()
    with LOGIN_LOCK:
        start, failures = LOGIN_FAILURES.get(client_ip, (now, 0))
        if now - start >= 900:
            LOGIN_FAILURES.pop(client_ip, None)
            return False
        return failures >= 8


def record_login_failure(client_ip):
    now = time.monotonic()
    with LOGIN_LOCK:
        start, failures = LOGIN_FAILURES.get(client_ip, (now, 0))
        if now - start >= 900:
            start, failures = now, 0
        LOGIN_FAILURES[client_ip] = (start, failures + 1)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("username"):
        return redirect(url_for("dashboard"))

    data = load_data()
    settings = data.get("settings", {})
    site_name = settings.get("site_name", "ZX FILE")

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        def fail(msg, count_failure=False):
            if count_failure:
                record_login_failure(client_ip)
                log_event("user_login_failure", level=logging.WARNING, username=username[:40], remote_addr=client_ip)
            return render_template("login.html", error=msg, username=username,
                                   theme_color=get_theme_color(), site_name=site_name)

        if login_is_limited(client_ip):
            return fail("Too many failed attempts. Try again in 15 minutes.")
        if not USERNAME_RE.fullmatch(username):
            return fail("Username must be 2-20 chars (a-z, 0-9, _ . -)", True)

        users = data.setdefault("users", {})
        account = users.get(username)
        if not account:
            return fail("Wrong username or password", True)
        valid, legacy_hash = verify_password(account.get("password_hash", ""), password)
        if not valid:
            return fail("Wrong username or password", True)
        if legacy_hash:
            migrated = False
            with data_transaction() as latest:
                latest_account = latest.get("users", {}).get(username)
                if latest_account:
                    fresh_valid, fresh_legacy = verify_password(latest_account.get("password_hash", ""), password)
                    if fresh_valid and fresh_legacy:
                        latest_account["password_hash"] = hash_password(password)
                        migrated = True
                    elif not fresh_valid:
                        return fail("Wrong username or password", True)
            if migrated:
                log_event("legacy_password_hash_migrated", username=username)

        with LOGIN_LOCK:
            LOGIN_FAILURES.pop(client_ip, None)
        session.clear()
        session.permanent = True
        session["username"] = username
        session["is_admin"] = username == ADMIN_USERNAME
        csrf_token()
        log_event("user_login_success", username=username, remote_addr=client_ip)
        return redirect(url_for("dashboard"))

    return render_template("login.html", error=None, username="",
                           theme_color=get_theme_color(), site_name=site_name)

@app.route("/account/password", methods=["POST"])
@login_required
def change_password():
    data = load_data()
    username = session["username"]
    account = data.get("users", {}).get(username)
    if not account:
        return jsonify({"success": False, "error": "Account not found"}), 404
    payload = request.get_json(silent=True) or request.form
    current_password = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    confirm_password = str(payload.get("confirm_password", ""))
    valid, _legacy = verify_password(account.get("password_hash", ""), current_password)
    if not valid:
        return jsonify({"success": False, "error": "Current password is incorrect"}), 400
    if len(new_password) < 12 or len(new_password) > 128:
        return jsonify({"success": False, "error": "Use a new password between 12 and 128 characters"}), 400
    if new_password != confirm_password:
        return jsonify({"success": False, "error": "New passwords do not match"}), 400
    if new_password == current_password:
        return jsonify({"success": False, "error": "Choose a password different from the current one"}), 400
    with data_transaction() as latest:
        current_account = latest.get("users", {}).get(username)
        if not current_account:
            return jsonify({"success": False, "error": "Account not found"}), 404
        current_valid, _ = verify_password(current_account.get("password_hash", ""), current_password)
        if not current_valid:
            return jsonify({"success": False, "error": "Current password is incorrect"}), 400
        current_account["password_hash"] = hash_password(new_password)
    log_event("account_password_changed", username=username)
    # Rotate the signed session and CSRF token after changing credentials.
    session.clear()
    session.permanent = True
    session["username"] = username
    csrf_token()
    return jsonify({"success": True, "message": "Password updated successfully"})


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username")
    session.clear()
    log_event("user_logged_out", username=username)
    return redirect(url_for("login"))

# ==================== DASHBOARD ====================
@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    data = load_data()
    settings = data.get("settings", {})
    site_name = settings.get("site_name", "TEAM AKI")
    user_servers = {k: v for k, v in data.get("servers", {}).items() if v.get("owner") == username}
    stale = [(name, cfg.get("pid")) for name, cfg in user_servers.items()
             if cfg.get("pid") and not is_process_alive(cfg.get("pid"), cfg.get("process_created_at"))]
    if stale:
        with data_transaction() as latest:
            for name, pid in stale:
                cfg = latest.get("servers", {}).get(name)
                if cfg and cfg.get("pid") == pid:
                    cfg["status"] = "stopped"
                    cfg["pid"] = None
                    cfg.pop("process_created_at", None)
        data = load_data()
        user_servers = {k: v for k, v in data.get("servers", {}).items() if v.get("owner") == username}
    running = sum(1 for v in user_servers.values() if v.get("status") == "running")
    return render_template("dashboard.html", servers=user_servers, running=running, total=len(user_servers),
                           username=username, site_name=site_name, theme_color=get_theme_color(),
                           is_admin=username == ADMIN_USERNAME)

def read_recent_application_logs(limit=100):
    """Read a bounded tail of structured application logs for diagnostics."""
    from collections import deque
    if not LOG_FILE.exists():
        return []
    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
            tail = deque(handle, maxlen=max(1, min(int(limit), 250)))
        entries = []
        for line in tail:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    entries.append(item)
            except json.JSONDecodeError:
                entries.append({"level": "INFO", "message": line.strip()})
        return list(reversed(entries))
    except OSError:
        logger.exception("Could not read application log tail")
        return []


def read_recent_project_logs(projects, max_lines=12, max_projects=12):
    """Read small, bounded tails from project runtime logs for the admin feed."""
    results = []
    for name, cfg in list(projects.items())[:max_projects]:
        path = SERVERS_DIR / name / "logs.txt"
        if not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 12000), os.SEEK_SET)
                lines = handle.read().decode("utf-8", errors="replace").splitlines()[-max_lines:]
            if lines:
                results.append({"project": name, "status": cfg.get("status", "unknown"), "lines": lines})
        except OSError:
            logger.exception("Could not read runtime log for project %s", name)
    return results


def diagnostics_snapshot():
    data = load_data()
    projects = data.get("servers", {})
    running = sum(1 for cfg in projects.values() if cfg.get("status") == "running")
    try:
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=None)
        disk = psutil.disk_usage(str(DATA_DIR))
        resources = {
            "cpu_percent": round(cpu_percent, 1),
            "memory_percent": round(memory.percent, 1),
            "memory_used_bytes": memory.used,
            "memory_total_bytes": memory.total,
            "disk_percent": round(disk.percent, 1),
            "disk_free_bytes": disk.free,
            "disk_total_bytes": disk.total,
        }
    except Exception:
        logger.exception("Could not read host resource metrics")
        resources = {"cpu_percent": None, "memory_percent": None, "disk_percent": None}

    storage_ok = DATA_DIR.is_dir() and os.access(DATA_DIR, os.W_OK) and (not DATA_FILE.exists() or os.access(DATA_FILE, os.R_OK))
    log_ok = LOG_FILE.exists() and os.access(LOG_FILE, os.R_OK) and any(isinstance(handler, RotatingFileHandler) for handler in logger.handlers)
    return {
        "status": "healthy" if storage_ok and log_ok else "degraded",
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "app": {
            "name": "TEAM AKI Hosting Panel",
            "uptime_seconds": max(0, int(time.monotonic() - PROCESS_STARTED_AT)),
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "pid": os.getpid(),
        },
        "resources": resources,
        "storage": {
            "healthy": storage_ok,
            "data_file_present": DATA_FILE.exists(),
            "data_file_size_bytes": DATA_FILE.stat().st_size if DATA_FILE.exists() else 0,
            "data_directory_writable": os.access(DATA_DIR, os.W_OK),
            "application_log_readable": log_ok,
            "application_log_size_bytes": LOG_FILE.stat().st_size if LOG_FILE.exists() else 0,
        },
        "projects": {"total": len(projects), "running": running, "stopped": max(0, len(projects) - running)},
        "accounts": {"total": len(data.get("users", {}))},
        "recent_logs": read_recent_application_logs(120),
        "project_runtime_logs": read_recent_project_logs(projects),
    }


@app.route("/diagnostics")
@admin_required
def diagnostics_page():
    return render_template("diagnostics.html", site_name=site_name_value(),
                           theme_color=get_theme_color(), username=session.get("username"))


@app.route("/api/diagnostics")
@admin_required
def diagnostics_api():
    return jsonify(diagnostics_snapshot())


@app.route("/api/stats")
@login_required
def system_stats():
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage(str(DATA_DIR)).percent
    return jsonify({"cpu": cpu, "ram": ram, "disk": disk})

# ==================== SERVER CRUD ====================
@app.route("/server/create", methods=["POST"])
@login_required
def create_server():
    name = request.form.get("name", "").strip().replace(" ", "-")
    runtime = request.form.get("runtime", "python").lower()
    if not SERVER_NAME_RE.fullmatch(name) or name in {".", ".."} or runtime not in {"python", "node", "static", "php", "go", "sh"}:
        return redirect(url_for("dashboard"))
    created = False
    with data_transaction() as data:
        if name not in data["servers"]:
            data["servers"][name] = {
                "name": name, "owner": session["username"], "runtime": runtime,
                "status": "stopped", "main_file": "", "main_command": "", "port": 8080,
                "pid": None, "manual_stop": False, "auto_restart_armed": False,
                "created": datetime.now().isoformat(),
            }
            created = True
    if not created:
        return redirect(url_for("dashboard"))
    (SERVERS_DIR / name / "extracted").mkdir(parents=True, exist_ok=True)
    log_event("project_created", username=session["username"], project=name, runtime=runtime)
    return redirect(url_for("server_detail", name=name))

@app.route("/server/delete/<name>", methods=["POST"])
@login_required
@server_locked
def delete_server(name):
    data = load_data()
    cfg = data.get("servers", {}).get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return redirect(url_for("dashboard"))
    pid = cfg.get("pid")
    if pid and is_process_alive(pid, cfg.get("process_created_at")):
        kill_process(pid, cfg.get("process_created_at"))
    entry = RUNNING_PROCESSES.pop(name, None)
    if entry:
        try:
            if entry["proc"].poll() is None:
                kill_process(entry["proc"].pid, entry.get("created_at") or cfg.get("process_created_at"))
        except Exception:
            logger.exception("Could not stop in-memory process for deleted project %s", name)
        try:
            entry["log_file"].close()
        except Exception:
            pass
    with data_transaction() as latest:
        latest_cfg = latest.get("servers", {}).get(name)
        if latest_cfg and latest_cfg.get("owner") == session["username"]:
            latest["servers"].pop(name, None)
    shutil.rmtree(SERVERS_DIR / name, ignore_errors=True)
    log_event("project_deleted", username=session["username"], project=name)
    return redirect(url_for("dashboard"))

@app.route("/server/<name>")
@login_required
@server_locked
def server_detail(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg:
        return "Server not found", 404
    if cfg.get("owner") != session["username"]:
        return "Access denied", 403
    pid = cfg.get("pid")
    if pid and not is_process_alive(pid, cfg.get("process_created_at")):
        with data_transaction() as latest:
            fresh_cfg = latest.get("servers", {}).get(name)
            if fresh_cfg and fresh_cfg.get("pid") == pid:
                fresh_cfg["status"] = "stopped"
                fresh_cfg["pid"] = None
                fresh_cfg.pop("process_created_at", None)
        data = load_data()
        cfg = data.get("servers", {}).get(name, cfg)
    if "main_command" not in cfg:
        cfg["main_command"] = ""
    extract_dir = SERVERS_DIR / name / "extracted"
    files = list_files(extract_dir)
    return render_template("server.html", server_name=name, config=cfg, files=files,
                           theme_color=get_theme_color(), is_admin=session.get("username") == ADMIN_USERNAME)

def list_files(directory, base="", depth=0):
    result = []
    if not directory.exists() or depth >= 24 or directory.is_symlink():
        return result
    try:
        for entry in sorted(directory.iterdir(), key=lambda e: (e.is_file(), e.name)):
            if entry.name in {".venv", "venv", "node_modules", "__pycache__", ".git"} or entry.is_symlink():
                continue
            rel = f"{base}/{entry.name}" if base else entry.name
            if entry.is_dir():
                result.append({"name": entry.name, "path": rel, "type": "dir", "size": 0})
                result.extend(list_files(entry, rel, depth + 1))
            else:
                result.append({"name": entry.name, "path": rel, "type": "file", "size": entry.stat().st_size})
    except Exception:
        pass
    return result

def pip_run(args, cwd=None, project_root=None):
    """Run pip against the one persistent host-shared Python package environment."""
    project_root = Path(project_root) if project_root is not None else None
    log_path = SERVERS_DIR / project_root.name / "logs.txt" if project_root else None
    python_executable = ensure_shared_python_env(log_path)
    safe_env = build_project_environment()
    try:
        python_executable.relative_to(SHARED_PYTHON_ENV)
        using_shared_env = True
    except ValueError:
        using_shared_env = False
    if using_shared_env:
        safe_env["VIRTUAL_ENV"] = str(SHARED_PYTHON_ENV)
        safe_env["PATH"] = str(python_executable.parent) + os.pathsep + safe_env.get("PATH", "")
    command = [str(python_executable), "-m", "pip"] + list(args)
    if not using_shared_env:
        return subprocess.CompletedProcess(
            command, 1, "", "Shared Python environment is unavailable; refusing to modify the hosting panel interpreter."
        )
    with shared_python_package_lock():
        res = subprocess.run(command, cwd=cwd, capture_output=True, text=True, env=safe_env, timeout=600)
    return res

def _auto_install_from_files(name):
    """Serialize background dependency installation with other project operations."""
    with get_server_lock(name):
        data = load_data()
        if name not in data.get("servers", {}):
            return
        _auto_install_from_files_locked(name)


def _auto_install_from_files_locked(name):
    """Install uploaded requirements/package manifests in the background."""
    extract_dir = SERVERS_DIR / name / "extracted"
    log_path = SERVERS_DIR / name / "logs.txt"
    def log(msg):
        with open(log_path, "a") as lf:
            lf.write(msg)
    try:
        runtime = load_data().get("servers", {}).get(name, {}).get("runtime", "python")
        if runtime == "python":
            for install_args, install_cwd, manifest_label in python_dependency_specs(extract_dir):
                log(f"\n[AUTO-INSTALL] Python dependencies found ({manifest_label}). Installing modules...\n")
                res = pip_run(install_args, cwd=str(install_cwd), project_root=extract_dir)
                if res.returncode == 0:
                    log(f"[AUTO-INSTALL] DONE: {manifest_label} processed successfully\n")
                else:
                    log((res.stderr or res.stdout or "")[-1500:] + f"\n[AUTO-INSTALL] FAILED: {manifest_label} could not be installed\n")
        pj = find_project_file(extract_dir, "package.json")
        if runtime == "node" and pj:
            log(f"\n[AUTO-INSTALL] package.json found. Running npm install...\n")
            res = subprocess.run(["npm", "install"], cwd=str(pj.parent), capture_output=True, text=True,
                                 env=build_project_environment(), timeout=300)
            if res.returncode == 0:
                log("[AUTO-INSTALL] DONE: npm modules installed successfully\n")
            else:
                log((res.stderr or res.stdout or "")[-1500:] + "\n[AUTO-INSTALL] FAILED: npm install error\n")
    except Exception as e:
        log(f"[AUTO-INSTALL] ERROR: {e}\n")

@app.route("/server/<name>/upload", methods=["POST"])
@login_required
@server_locked
def upload_file(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    original = uploaded.filename or ""
    if not original.strip():
        return jsonify({"success": False, "error": "Empty filename"}), 400
    # Do not permit client-supplied directory components.
    normalized = original.replace("\\", "/")
    if normalized.startswith("/") or ".." in pathlib.PurePosixPath(normalized).parts:
        return jsonify({"success": False, "error": "Invalid filename"}), 400
    safe_filename = pathlib.PurePosixPath(normalized).name
    if safe_filename in {"", ".", ".."}:
        return jsonify({"success": False, "error": "Invalid filename"}), 400

    extract_dir = (SERVERS_DIR / name / "extracted").resolve()
    extract_dir.mkdir(parents=True, exist_ok=True)
    upload_path = SERVERS_DIR / name / f"upload_{secrets.token_hex(5)}_{safe_filename}"
    uploaded.save(upload_path)

    if safe_filename.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(upload_path, "r") as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ZIP_FILES:
                    return jsonify({"success": False, "error": "ZIP contains too many files"}), 400
                total_unpacked = sum(info.file_size for info in infos)
                if total_unpacked > MAX_ZIP_UNPACKED:
                    return jsonify({"success": False, "error": "ZIP expands beyond the 200 MB safety limit"}), 400
                for info in infos:
                    member = info.filename.replace("\\", "/")
                    member_path = pathlib.PurePosixPath(member)
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if (member_path.is_absolute() or ".." in member_path.parts or "\x00" in member or
                            (member_path.parts and ":" in member_path.parts[0]) or stat.S_ISLNK(mode)):
                        return jsonify({"success": False, "error": "ZIP contains an unsafe path or symbolic link"}), 400
                    target = (extract_dir / pathlib.Path(*member_path.parts)).resolve()
                    if target != extract_dir and extract_dir not in target.parents:
                        return jsonify({"success": False, "error": "ZIP path is outside the project directory"}), 400
                for info in infos:
                    member_path = pathlib.PurePosixPath(info.filename.replace("\\", "/"))
                    target = extract_dir / pathlib.Path(*member_path.parts)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        resolved_target = target.resolve()
                        if extract_dir not in resolved_target.parents or target.is_symlink():
                            raise ValueError("ZIP entry resolves through an unsafe symbolic link")
                        with archive.open(info, "r") as source, target.open("wb") as dest:
                            shutil.copyfileobj(source, dest)
        except zipfile.BadZipFile:
            return jsonify({"success": False, "error": "The uploaded ZIP file is invalid"}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": f"ZIP extraction failed: {exc}"}), 500
        finally:
            upload_path.unlink(missing_ok=True)
    else:
        dest = extract_dir / safe_filename
        shutil.move(str(upload_path), str(dest))

    if not cfg.get("main_file"):
        with data_transaction() as latest:
            fresh_cfg = latest.get("servers", {}).get(name)
            if fresh_cfg and fresh_cfg.get("owner") == session["username"] and not fresh_cfg.get("main_file"):
                fresh_cfg["main_file"] = auto_detect_main_file(extract_dir, cfg.get("runtime", "python"))
    log_event("project_files_uploaded", username=session["username"], project=name,
              filename=safe_filename, archive=safe_filename.lower().endswith(".zip"))
    threading.Thread(target=_auto_install_from_files, args=(name,), daemon=True,
                     name=f"auto-install-{name}").start()
    return redirect(url_for("server_detail", name=name))


@app.route("/server/<name>/settings", methods=["POST"])
@login_required
@server_locked
def save_settings(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg:
        return jsonify({"success": False, "error": "Server not found"}), 404
    
    if cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403
    
    payload = request.get_json(silent=True) or {}
    main_file = str(payload.get("main_file", cfg.get("main_file", ""))).strip()
    main_command = str(payload.get("main_command", cfg.get("main_command", ""))).strip()
    try:
        port = int(payload.get("port", cfg.get("port", 8080)))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Port must be a number"}), 400
    if not 1024 <= port <= 65535:
        return jsonify({"success": False, "error": "Port must be between 1024 and 65535"}), 400
    if len(main_command) > 500:
        return jsonify({"success": False, "error": "Custom command is too long"}), 400
    if main_file:
        rel = pathlib.PurePosixPath(main_file.replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts or ":" in main_file or not rel.parts:
            return jsonify({"success": False, "error": "Main file must be inside the project directory"}), 400
        main_file = "/".join(rel.parts)
    with data_transaction() as latest:
        fresh_cfg = latest.get("servers", {}).get(name)
        if not fresh_cfg or fresh_cfg.get("owner") != session["username"]:
            return jsonify({"success": False, "error": "Server not found"}), 404
        fresh_cfg["main_file"] = main_file
        fresh_cfg["main_command"] = main_command
        fresh_cfg["port"] = port
    log_event("project_settings_updated", username=session["username"], project=name, port=port)
    return jsonify({"success": True})

@app.route("/server/<name>/start", methods=["POST"])
@login_required
@server_locked
def start_server(name):
    data = load_data()
    cfg = data.get("servers", {}).get(name)
    if not cfg:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    pid = cfg.get("pid")
    if pid and is_process_alive(pid, cfg.get("process_created_at")):
        return jsonify({"success": False, "error": "Already running"}), 409

    extract_dir = SERVERS_DIR / name / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    runtime = cfg.get("runtime", "python")
    main_file = cfg.get("main_file") or auto_detect_main_file(extract_dir, runtime)
    main_cmd = cfg.get("main_command") or ""
    if runtime == "static":
        index_file = find_project_file(extract_dir, "index.html")
        main_path = index_file.resolve() if index_file else (extract_dir / "index.html").resolve()
        if index_file:
            main_file = index_file.relative_to(extract_dir).as_posix()
    else:
        main_path = (extract_dir / main_file).resolve()
    if extract_dir.resolve() not in main_path.parents and main_path != extract_dir.resolve():
        return jsonify({"success": False, "error": "Main file must be inside the project directory"}), 400
    if runtime != "static" and not main_path.is_file():
        return jsonify({"success": False, "error": f"{main_file} not found. Upload your files first."}), 400
    if runtime == "static" and not main_path.is_file():
        return jsonify({"success": False, "error": "Upload a static site with an index.html file first."}), 400

    log_path = SERVERS_DIR / name / "logs.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        port = int(cfg.get("port", 8080))
        if not 1024 <= port <= 65535:
            raise ValueError("Port is outside the allowed range")
        env, project_python = prepare_environment_and_deps(extract_dir, log_path, runtime)
        env["PORT"] = str(port)
        if main_cmd:
            cmd = shlex.split(main_cmd)
            if not cmd:
                raise ValueError("Custom command is empty")
        elif runtime == "static":
            cmd = [sys.executable, "-m", "http.server", str(port), "--bind", "0.0.0.0"]
        else:
            cmd = get_run_command(runtime, main_file, project_python)

        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"\n{'='*50}\n[{datetime.now().isoformat()}] Starting: {' '.join(cmd)}\n{'='*50}\n")
        log_file = open(log_path, "a", encoding="utf-8")
        proc = None
        process_created_at = None
        try:
            launch_cwd = main_path.parent if runtime == "static" else extract_dir
            if not main_cmd and runtime != "static":
                launch_cwd = main_path.parent
                command_entry = main_path.name
                if runtime == "go":
                    go_mod = find_project_file(extract_dir, "go.mod")
                    if go_mod and go_mod.parent in main_path.parents:
                        launch_cwd = go_mod.parent
                        command_entry = main_path.relative_to(launch_cwd).as_posix()
                cmd = get_run_command(runtime, command_entry, project_python)
            proc = subprocess.Popen(cmd, cwd=str(launch_cwd), stdout=log_file, stderr=log_file,
                                    env=env, start_new_session=True, close_fds=True)
            process_created_at = _process_create_time(proc.pid)
        except Exception:
            log_file.close()
            raise

        RUNNING_PROCESSES[name] = {"proc": proc, "log_file": log_file, "created_at": process_created_at}
        with data_transaction() as latest:
            fresh_cfg = latest.get("servers", {}).get(name)
            if not fresh_cfg or fresh_cfg.get("owner") != session["username"]:
                kill_process(proc.pid, process_created_at)
                RUNNING_PROCESSES.pop(name, None)
                log_file.close()
                return jsonify({"success": False, "error": "Project was removed or access changed"}), 409
            fresh_cfg.update({
                "status": "running", "pid": proc.pid, "manual_stop": False,
                "auto_restart_armed": True, "main_file": main_file,
                "process_created_at": process_created_at,
            })
        log_event("project_started", username=session["username"], project=name, pid=proc.pid, runtime=runtime)
        return jsonify({"success": True, "pid": proc.pid})
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        if 'proc' in locals() and proc is not None:
            kill_process(proc.pid, process_created_at)
            RUNNING_PROCESSES.pop(name, None)
        if 'log_file' in locals() and not log_file.closed:
            log_file.close()
        logger.exception("Could not start project %s", name)
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(f"[START ERROR] {exc}\n")
        except OSError:
            pass
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        if 'proc' in locals() and proc is not None:
            kill_process(proc.pid, process_created_at)
            RUNNING_PROCESSES.pop(name, None)
        if 'log_file' in locals() and not log_file.closed:
            log_file.close()
        logger.exception("Unexpected start failure for project %s", name)
        return jsonify({"success": False, "error": "Unexpected startup failure"}), 500

@app.route("/server/<name>/stop", methods=["POST"])
@login_required
@server_locked
def stop_server(name):
    data = load_data()
    cfg = data.get("servers", {}).get(name)
    if not cfg:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    pid = cfg.get("pid")
    entry = RUNNING_PROCESSES.pop(name, None)
    if entry:
        try:
            if entry["proc"].poll() is None:
                kill_process(entry["proc"].pid, entry.get("created_at") or cfg.get("process_created_at"))
        finally:
            try:
                entry["log_file"].close()
            except Exception:
                pass
    elif pid and is_process_alive(pid, cfg.get("process_created_at")):
        kill_process(pid, cfg.get("process_created_at"))

    log_path = SERVERS_DIR / name / "logs.txt"
    try:
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"[{datetime.now().isoformat()}] Server stopped\n")
    except OSError:
        logger.exception("Could not append stop event to project log %s", name)

    with data_transaction() as latest:
        fresh_cfg = latest.get("servers", {}).get(name)
        if fresh_cfg and fresh_cfg.get("owner") == session["username"]:
            fresh_cfg.update({"status": "stopped", "pid": None, "manual_stop": True,
                              "auto_restart_armed": False})
            fresh_cfg.pop("process_created_at", None)
    log_event("project_stopped", username=session["username"], project=name)
    return jsonify({"success": True})

# ==================== LOGS & EXECUTION ====================
@app.route("/server/<name>/logs")
@login_required
@server_locked
def get_logs(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg:
        return jsonify({"logs": "Server not found"}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"logs": "Access denied"}), 403

    log_path = SERVERS_DIR / name / "logs.txt"
    if not log_path.exists():
        return jsonify({"logs": "No logs yet. Start the server to see output."})
    
    try:
        with open(log_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 50000), os.SEEK_SET)
            content = f.read().decode('utf-8', errors='ignore')
            
        lines = content.splitlines()
        if len(lines) > 200:
            lines = lines[-200:]
            content = "... (showing last 200 lines) ...\n" + "\n".join(lines)
        return jsonify({"logs": content or "No output yet."})
    except Exception as e:
        return jsonify({"logs": f"Error reading logs: {e}"})

@app.route("/server/<name>/exec", methods=["POST"])
@login_required
@server_locked
def exec_command(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    payload = request.get_json(silent=True) or {}
    cmd_text = str(payload.get("command", "")).strip()

    if not cmd_text or len(cmd_text) > 2000:
        return jsonify({"success": False, "error": "No command specified"})

    log_path = SERVERS_DIR / name / "logs.txt"
    extract_dir = SERVERS_DIR / name / "extracted"

    try:
        with open(log_path, "a") as lf:
            lf.write(f"\n$ {cmd_text}\n")

        # shlex ব্যবহার করে নিরাপদে আর্গুমেন্ট পার্স করা হচ্ছে
        cmd_args = shlex.split(cmd_text)
        with open(log_path, "a") as lf:
            subprocess.Popen(
                cmd_args,
                cwd=str(extract_dir),
                stdout=lf,
                stderr=lf,
                env=build_project_environment(),
                close_fds=True,
                start_new_session=True,
            )
        log_event("project_command_submitted", username=session["username"], project=name, command_chars=len(cmd_text))
        return jsonify({"success": True})
    except Exception as e:
        logger.exception("Project command execution failed for %s", name)
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(f"Command execution error: {e}\n")
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/server/<name>/logs/clear", methods=["POST"])
@login_required
@server_locked
def clear_logs(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg:
        return jsonify({"success": False}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    log_path = SERVERS_DIR / name / "logs.txt"
    try:
        log_path.write_text("", encoding="utf-8")
    except OSError:
        logger.exception("Could not clear project logs for %s", name)
        return jsonify({"success": False, "error": "Unable to clear project logs"}), 500
    log_event("project_logs_cleared", username=session["username"], project=name)
    return jsonify({"success": True})

# ==================== PACKAGE MANAGER ENDPOINTS ====================

@app.route("/server/<name>/packages", methods=["GET"])
@login_required
@server_locked
def list_packages(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    runtime = cfg.get("runtime", "python")
    if runtime not in {"python", "node"}:
        return jsonify({"success": True, "packages": [], "runtime": runtime,
                        "message": "Package manager is not available for this runtime."})
    installed = []
    try:
        if runtime == "node":
            extract_dir = SERVERS_DIR / name / "extracted"
            pkg_json = find_project_file(extract_dir, "package.json")
            if pkg_json:
                pdata = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = dict(pdata.get("dependencies", {}))
                deps.update(pdata.get("devDependencies", {}))
                installed = [{"name": pkg, "version": ver} for pkg, ver in sorted(deps.items())]
            scope = "project"
        else:
            log_path = SERVERS_DIR / name / "logs.txt"
            python_executable = ensure_shared_python_env(log_path)
            try:
                python_executable.relative_to(SHARED_PYTHON_ENV)
            except ValueError:
                return jsonify({"success": False,
                                "error": "The shared Python environment could not be created. Package listing is disabled to protect the hosting panel."}), 503
            with shared_python_package_lock():
                result = subprocess.run([str(python_executable), "-m", "pip", "list", "--format=json"],
                                        capture_output=True, text=True, env=build_project_environment(), timeout=60)
            if result.returncode != 0:
                return jsonify({"success": False, "error": (result.stderr or "Could not read shared packages")[-1200:]}), 500
            packages = json.loads(result.stdout or "[]")
            installed = [{"name": item.get("name", ""), "version": item.get("version", ""),
                          "protected": str(item.get("name", "")).lower() in {"pip", "setuptools", "wheel"}}
                         for item in packages if item.get("name")]
            installed.sort(key=lambda item: item["name"].lower())
            scope = "global_shared"
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "packages": installed[:500], "runtime": runtime,
                    "scope": scope, "shared": runtime == "python",
                    "package_count": len(installed)})

PKG_RE = re.compile(r"^(?!-)[A-Za-z0-9@][A-Za-z0-9@/_.-]{0,119}$")
PKG_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,39}$")

def _run_install(name, runtime, pkg_name, version):
    with get_server_lock(name):
        _run_install_locked(name, runtime, pkg_name, version)


def _run_install_locked(name, runtime, pkg_name, version):
    extract_dir = SERVERS_DIR / name / "extracted"
    log_path = SERVERS_DIR / name / "logs.txt"
    label = f"{pkg_name}=={version}" if (version and runtime != "node") else (f"{pkg_name}@{version}" if version else pkg_name)
    def log(msg):
        with open(log_path, "a") as lf:
            lf.write(msg)
    try:
        log(f"\n[PACKAGE] Installing {label} into the shared host Python environment ...\n" if runtime != "node" else f"\n[PACKAGE] Installing {label} ...\n")
        if runtime == "node":
            pkg_json = find_project_file(extract_dir, "package.json")
            npm_cwd = pkg_json.parent if pkg_json else extract_dir
            cmd = ["npm", "install", label]
            res = subprocess.run(cmd, cwd=str(npm_cwd), capture_output=True, text=True,
                                  env=build_project_environment(), timeout=600)
        else:
            res = pip_run(["install", label], cwd=str(extract_dir), project_root=extract_dir)
        if res.returncode != 0:
            log((res.stderr or res.stdout or "")[-1500:] + f"\n[PACKAGE] FAILED: {label}\n")
            return
        if runtime != "node":
            req_file = find_project_file(extract_dir, "requirements.txt") or (extract_dir / "requirements.txt")
            req_file.parent.mkdir(parents=True, exist_ok=True)
            lines = req_file.read_text(encoding="utf-8").splitlines() if req_file.exists() else []
            lines = [l for l in lines if not re.match(rf"^{re.escape(pkg_name)}(==|$)", l.strip(), re.I)]
            lines.append(label)
            req_file.write_text("\n".join(lines) + "\n")
        log(f"[PACKAGE] DONE: {label} installed successfully\n")
    except Exception as e:
        logger.exception("Package installation failed for %s in project %s", pkg_name, name)
        log(f"[PACKAGE] ERROR: {e}\n")

@app.route("/server/<name>/packages/install", methods=["POST"])
@login_required
@server_locked
def install_package(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    payload = request.get_json(silent=True) or {}
    pkg_name = str(payload.get("name", "")).strip()
    version = str(payload.get("version", "")).strip()

    if not pkg_name or not PKG_RE.fullmatch(pkg_name) or (version and not PKG_VERSION_RE.fullmatch(version)):
        return jsonify({"success": False, "error": "Invalid package name or version"}), 400

    runtime = cfg.get("runtime", "python")
    if runtime not in {"python", "node"}:
        return jsonify({"success": False, "error": "Package installation is supported for Python and Node.js projects only"}), 400
    (SERVERS_DIR / name / "extracted").mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_run_install, args=(name, runtime, pkg_name, version), daemon=True,
                     name=f"package-install-{name}").start()
    log_event("package_install_requested", username=session["username"], project=name, package=pkg_name)
    return jsonify({"success": True, "message": f"Installing {pkg_name}... check LOGS"})

@app.route("/server/<name>/file/delete", methods=["POST"])
@login_required
@server_locked
def delete_file(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403
    payload = request.get_json(silent=True) or {}
    rel = str(payload.get("filename", "")).strip()
    base = (SERVERS_DIR / name / "extracted").resolve()
    raw_target = base / rel
    if not rel or "\x00" in rel or raw_target.is_symlink():
        return jsonify({"success": False, "error": "Not found"}), 404
    target = raw_target.resolve()
    if base not in target.parents or not target.exists():
        return jsonify({"success": False, "error": "Not found"}), 404
    if target.is_dir():
        shutil.rmtree(target, ignore_errors=True)
    else:
        target.unlink()
    log_event("project_file_deleted", username=session["username"], project=name, filename=rel)
    return jsonify({"success": True})

@app.route("/server/<name>/packages/remove", methods=["POST"])
@login_required
@server_locked
def remove_package(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or cfg.get("owner") != session["username"]:
        return jsonify({"success": False, "error": "Access denied"}), 403

    payload = request.get_json(silent=True) or {}
    pkg_name = str(payload.get("name", "")).strip()

    if not pkg_name or not PKG_RE.fullmatch(pkg_name):
        return jsonify({"success": False, "error": "Invalid package name"}), 400

    runtime = cfg.get("runtime", "python")
    if runtime == "python" and pkg_name.lower() in {"pip", "setuptools", "wheel"}:
        return jsonify({"success": False, "error": "Core package-management tools are protected."}), 400
    if runtime not in {"python", "node"}:
        return jsonify({"success": False, "error": "Package removal is supported for Python and Node.js projects only"}), 400
    extract_dir = SERVERS_DIR / name / "extracted"

    try:
        if runtime == "node":
            pkg_json = find_project_file(extract_dir, "package.json")
            npm_cwd = pkg_json.parent if pkg_json else extract_dir
            cmd = ["npm", "uninstall", pkg_name]
            res = subprocess.run(cmd, cwd=str(npm_cwd), capture_output=True, text=True,
                                  env=build_project_environment(), timeout=600)
            if res.returncode != 0:
                return jsonify({"success": False, "error": res.stderr or "Failed to remove NPM package"})
        else:
            res = pip_run(["uninstall", "-y", pkg_name], cwd=str(extract_dir), project_root=extract_dir)
            if res.returncode != 0:
                return jsonify({"success": False, "error": res.stderr or "Failed to uninstall Python package"}), 400
            req_file = find_project_file(extract_dir, "requirements.txt") or (extract_dir / "requirements.txt")
            if req_file.exists():
                lines = req_file.read_text().splitlines()
                lines = [line for line in lines if not re.match(rf"^{re.escape(pkg_name)}(?:==|$)", line.strip(), re.I)]
                req_file.write_text("\n".join(lines) + ("\n" if lines else ""))

        log_event("package_removed", username=session["username"], project=name, package=pkg_name)
        return jsonify({"success": True, "message": f"Package {pkg_name} removed successfully!"})
    except Exception as e:
        logger.exception("Package removal failed for %s in project %s", pkg_name, name)
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

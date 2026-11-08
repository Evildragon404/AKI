# TEAM AKI Hosting Panel

A Flask-based private hosting/control panel for managing Python, Node.js, PHP, Go, shell, and static projects. The interface uses a responsive iOS-inspired Liquid Glass design, with translucent surfaces, aurora lighting, adaptive mobile layouts, and a live administrator diagnostics view.

## Included features

- Private login with legacy SHA-256 password migration to Werkzeug scrypt hashes and in-panel password changes (minimum 12 characters).
- Project creation and per-user ownership checks.
- Python, Node.js, PHP, Go, shell, and static HTTP server runtimes. Python dependencies are discovered from `requirements.txt` and installable `pyproject.toml` / `setup.py` projects; Node dependencies are read from nested `package.json` manifests.
- One persistent, host-shared Python virtual environment for all Python projects. Packages are installed once under the configured data directory and are visible to every Python project, reducing duplicate installations and disk usage. Each running project still has its own process and RAM use; shared packages do not merge runtime memory. The panel's own interpreter remains separate; package install operations are serialized across workers. Existing panel-managed project `.venv` directories are removed only after their dependencies migrate successfully.
- ZIP and individual-file uploads (64 MB request limit; ZIP extraction capped at 2,000 entries and 200 MB expanded size; rejects traversal paths and symlinks). Entry points and dependency manifests are discovered inside common one-folder ZIP layouts as well as at the project root; static sites can also serve a nested `index.html`.
- Start, stop, restart, crash recovery, process-tree termination, and manual-stop protection.
- Live console output, command execution, log clearing, file deletion, shared Python package management, and project-local Node package management.
- Live host CPU, RAM, and persistent-volume usage on the dashboard.
- Structured JSON application logs with rotation, color-coded console output, request path/status/duration logging, and exception traces.
- Administrator-only `/diagnostics` screen with health metrics, storage checks, recent application events, and project runtime log tails.
- Atomic JSON state replacement, a thread lock plus POSIX file lock for read-modify-write transactions, restrictive file permissions, and per-project operation locks.
- CSRF protection for POST requests, login-attempt throttling, secure session-cookie settings, and baseline browser security headers.

## Login and administrator access

The bundled `data.json` preserves the existing accounts. The starter `aki` account uses the existing password `aki`; change it from Dashboard → Change password before exposing the panel publicly. The application does not expose public account registration.

The diagnostics page is restricted to `ADMIN_USERNAME` (defaults to `aki`). Set `ADMIN_USERNAME` to another existing account name to change the administrator account. Existing project ownership and account password hashes are preserved during initialization.

## Configuration

Set these environment variables in the hosting provider:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Long, random, stable Flask session-signing secret. Required for persistent sessions across restarts. |
| `COOKIE_SECURE` | Defaults to `1`; set to `0` only for local HTTP development. |
| `TEAM_AKI_DATA_DIR` | Persistent data directory for `data.json`, `servers/`, `shared-python-env/`, and `app.log`. |
| `ADMIN_USERNAME` | Administrator account for `/diagnostics`; defaults to `aki`. |
| `DEFAULT_USERNAME` | Username created when no account database exists; defaults to `aki`. |
| `DEFAULT_PASSWORD` | Password created only when the default account does not already exist; defaults to `aki` for compatibility. |
| `LOG_LEVEL` | Python logging level; defaults to `INFO`. |

**Important:** the bundled account database contains a known starter credential. Change the password before public deployment. Set a stable `SECRET_KEY` and use HTTPS.

## Deployment

1. Use Python 3.14 for hosted deployments (the Docker image tracks the current 3.14 patch release). Python 3.11+ remains supported by the application for local/Termux environments. `.python-version` selects 3.14 on providers that support it; `runtime.txt` is retained for providers that still use that legacy setting.
2. Install panel dependencies with `pip install -r requirements.txt`. For non-Docker hosts, also install the operating-system runtimes you plan to host (`node`/`npm`, `php-cli`, `go`, and `bash`); the supplied Dockerfile installs these runtimes.
3. Set a stable `SECRET_KEY` and `ADMIN_USERNAME` as needed.
4. Set `COOKIE_SECURE=1` when serving the panel over HTTPS. Set `COOKIE_SECURE=0` only for local HTTP development.
5. Set `TEAM_AKI_DATA_DIR` to a persistent mounted directory. The app stores `data.json`, `servers/`, `shared-python-env/`, the shared package lock, and rotated `app.log` files there. Without this setting, it uses the project directory, which may be ephemeral on some providers.
6. Start with `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 --access-logfile - --error-logfile - --capture-output` (also configured in `Procfile`). Keep one Gunicorn worker: in-memory process supervision is intentionally single-worker, while JSON mutations are protected by a filesystem lock.
7. For Docker-based hosting, build with `docker build -t team-aki .` and run with persistent storage, for example: `docker run -d -p 5000:5000 -e SECRET_KEY='replace-with-a-long-random-secret' -v team-aki-data:/data team-aki`.

## Operational logging

- Application events and HTTP access records are written as structured JSON to `app.log`, with five rotating backups.
- Console output uses readable level coloring where the terminal supports ANSI colors.
- Project process stdout/stderr remains in each project's `servers/<project>/logs.txt` file.
- The administrator diagnostics view combines the recent application log tail with bounded tails from project runtime logs.
- `/api/ping` is a lightweight unauthenticated health endpoint for platform health checks. Duplicate self-pinging keep-alive threads were removed.

## Important isolation warning

This application intentionally launches uploaded project code and exposes an authenticated command console. Uploaded programs run with the same operating-system user privileges as the panel. Likely host credentials are filtered from the child-process environment, and Python package operations use a dedicated persistent shared virtual environment separate from the panel interpreter. Python package versions are shared across all Python projects: incompatible projects that require different versions of the same dependency may conflict. This is still not an OS sandbox and same-user file access remains possible. Run it only for trusted administrators, under a dedicated low-privilege operating-system user, on a host that does not contain unrelated secrets. This is a single-host project runner, **not** a hardened multi-tenant sandbox. Do not give untrusted users access or expose the default password publicly.

## Data and backups

- `data.json` stores account password hashes, settings, and project metadata.
- `servers/<project>/extracted/` stores uploaded project files.
- `shared-python-env/` stores the common Python packages used by every Python project.
- `servers/<project>/logs.txt` stores process stdout/stderr.
- `app.log` and rotated copies store application operations, request activity, and exceptions.
- `space.json` is retained as platform/deployment metadata; the Flask app uses `data.json` for live account/project state.

Back up `data.json`, `servers/`, and `shared-python-env/` together to preserve project files and the shared Python package environment. Include `app.log` only when operational history is required. If the shared environment is not backed up, it will be recreated on the next start and project dependencies will be reinstalled from their manifests.

#!/usr/bin/env python3
"""Root-owned gateway for the Setup Danger Zone uninstall workflow.

The CGI is deliberately not allowed to select a program, path, user, unit name,
or command-line fragment.  It may only submit the four documented booleans and
the confirmation acknowledgements.  This helper must be installed root:root
0755 at /usr/local/libexec/lldpq-uninstall-web.py; the actual uninstaller must
likewise be installed root:root 0755 at the fixed path below.
"""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time


CONFIG_FILE = "/etc/lldpq.conf"
UNINSTALLER = "/usr/local/libexec/lldpq-uninstall.sh"
GATEWAY = "/usr/local/libexec/lldpq-uninstall-web.py"
RUN_DIR = "/run/lldpq-uninstall"
ACTIVE_RECORD = os.path.join(RUN_DIR, "active.json")
LIFECYCLE_LOCK = "/etc/lldpq.lifecycle.lock"
PUBLIC_ACTIVE_MARKER = "/run/lldpq-uninstall.active"
TOKEN_TTL_SECONDS = 300
ORPHANED_STATUS_SECONDS = 120
MAX_REQUEST_BYTES = 16 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_PREVIEW_BYTES = 128 * 1024
MAX_JOURNAL_BYTES = 128 * 1024
STATUS_COMMAND_TIMEOUT = 5
LIFECYCLE_LOCK_TIMEOUT_SECONDS = 3
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
JOURNALCTL = "/usr/bin/journalctl"
SUDO = "/usr/bin/sudo"
ENV = "/usr/bin/env"
ID = "/usr/bin/id"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TOKEN_RE = re.compile(r"^[a-f0-9]{64}$")
JOB_RE = re.compile(r"^[a-f0-9]{32}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
OPTION_KEYS = (
    "keep_data",
    "remove_dhcp",
    "remove_nginx",
    "remove_docker",
)


class GatewayError(RuntimeError):
    """Expected request or host-state error safe to return to an admin."""


class StartAmbiguousError(GatewayError):
    """A start response cannot safely claim the request id was rejected."""


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n")


def read_request(command: str) -> dict:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise GatewayError("Request exceeds the 16 KiB limit")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayError("Request must be one UTF-8 JSON object") from exc
    if not isinstance(request, dict):
        raise GatewayError("Request must be a JSON object")

    allowed = {
        "preview": {"options", "acknowledgements"},
        "start": {"options", "acknowledgements"}
        | {
            "preview_token",
            "preview_fingerprint",
            "confirmation",
            "request_id",
        },
        "status": {"job_id"},
    }[command]
    unknown = set(request) - allowed
    if unknown:
        raise GatewayError("Unknown request field: " + sorted(unknown)[0])
    return request


def parse_options(request: dict) -> dict[str, bool]:
    raw_options = request.get("options")
    if not isinstance(raw_options, dict) or set(raw_options) != set(OPTION_KEYS):
        raise GatewayError("options must contain exactly the four documented uninstall options")
    options: dict[str, bool] = {}
    for key in OPTION_KEYS:
        if type(raw_options[key]) is not bool:
            raise GatewayError(f"{key} must be an explicit JSON boolean")
        options[key] = raw_options[key]
    return options


def parse_acknowledgements(request: dict) -> dict[str, bool]:
    keys = {"ack_disconnect", "ack_data_loss", "ack_shared_services"}
    raw = request.get("acknowledgements")
    if not isinstance(raw, dict) or set(raw) != keys:
        raise GatewayError("acknowledgements must contain exactly the three documented booleans")
    if any(type(raw[key]) is not bool for key in keys):
        raise GatewayError("Every uninstall acknowledgement must be an explicit JSON boolean")
    return {key: raw[key] for key in sorted(keys)}


def refuse_container() -> None:
    if os.path.exists("/.dockerenv"):
        raise GatewayError(
            "Docker deployment: uninstall the LLDPq container and host resources from the Docker host."
        )


def verify_root_owned_program(path: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise GatewayError(f"Required installed helper is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or metadata.st_nlink != 1
    ):
        raise GatewayError(f"Installed helper failed its root-owned file check: {path}")


def read_runtime_user() -> tuple[str, str]:
    try:
        metadata = os.lstat(CONFIG_FILE)
    except OSError as exc:
        raise GatewayError("Runtime configuration is missing") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_CONFIG_BYTES
    ):
        raise GatewayError(
            "Runtime configuration must be one bounded regular file"
        )

    user = ""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as config:
            for raw_line in config:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip() != "LLDPQ_USER":
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                user = value
    except (OSError, UnicodeError) as exc:
        raise GatewayError("Runtime configuration could not be read safely") from exc

    if not USER_RE.fullmatch(user):
        raise GatewayError("Runtime configuration contains an invalid LLDPQ_USER")
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise GatewayError("Configured LLDPq service account does not exist") from exc
    if account.pw_uid == 0:
        raise GatewayError("The web uninstall gateway refuses to run as uid 0")
    try:
        web_group_gid = grp.getgrnam("www-data").gr_gid
    except KeyError as exc:
        raise GatewayError("Required www-data group does not exist") from exc
    config_mode = stat.S_IMODE(metadata.st_mode)
    if (
        metadata.st_uid != account.pw_uid
        or metadata.st_gid != web_group_gid
        or config_mode & 0o007
        or not config_mode & 0o040
        or not config_mode & 0o400
    ):
        raise GatewayError(
            "Runtime configuration ownership/mode does not match LLDPQ_USER:www-data with owner/group read and no world access"
        )
    home = account.pw_dir
    protected_home_roots = (
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    )
    if (
        not home.startswith("/")
        or home == "/"
        or any(ch in home for ch in "\x00\r\n")
        or os.path.realpath(home) != home
        or any(home == root or home.startswith(root + "/") for root in protected_home_roots)
    ):
        raise GatewayError("Configured LLDPq service account has an unsafe home directory")
    try:
        home_metadata = os.lstat(home)
    except OSError as exc:
        raise GatewayError("Configured LLDPq service account home is unavailable") from exc
    if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_uid != account.pw_uid:
        raise GatewayError("Configured LLDPq service account home failed its ownership check")
    shell = account.pw_shell
    if (
        not shell.startswith("/")
        or any(ch in shell for ch in "\x00\r\n")
        or os.path.basename(shell) in {"false", "nologin"}
        or not os.path.isfile(shell)
        or not os.access(shell, os.X_OK)
    ):
        raise GatewayError("Configured LLDPq service account has an unsafe login shell")
    return user, home


def config_identity() -> dict[str, int]:
    # Re-run the complete ownership/account validation immediately before
    # recording/comparing stat identity. LLDPQ_USER owns this file by design;
    # the preview token detects any replacement or edit before start.
    read_runtime_user()
    try:
        metadata = os.lstat(CONFIG_FILE)
    except OSError as exc:
        raise GatewayError("Runtime configuration is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_CONFIG_BYTES
    ):
        raise GatewayError("Runtime configuration failed its ownership check")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nlink": metadata.st_nlink,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def option_argv(options: dict[str, bool], *, preview: bool) -> list[str]:
    argv = [UNINSTALLER, "--dry-run" if preview else "--yes"]
    if options["keep_data"]:
        argv.append("--keep-data")
    if options["remove_dhcp"]:
        argv.append("--remove-dhcp")
    if options["remove_nginx"]:
        argv.append("--remove-nginx")
    if options["remove_docker"]:
        argv.append("--remove-docker")
    return argv


def user_environment(user: str, home: str) -> list[str]:
    return [
        SUDO,
        "-n",
        "-H",
        "-u",
        user,
        ENV,
        "-i",
        f"HOME={home}",
        f"PATH={SAFE_PATH}",
        "LC_ALL=C",
        f"LLDPQ_CONFIG_FILE={CONFIG_FILE}",
    ]


def verify_passwordless_sudo(user: str, home: str) -> None:
    listing = subprocess.run(
        user_environment(user, home) + [SUDO, "-n", "-l"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    policy = (listing.stdout or b"").decode("utf-8", errors="replace")
    has_unrestricted_nopasswd = bool(
        re.search(r"(?m)^\s*\([^)]*\)\s+NOPASSWD:\s*ALL\s*$", policy)
    )
    probe = subprocess.run(
        user_environment(user, home) + [SUDO, "-n", ID, "-u"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if (
        listing.returncode != 0
        or not has_unrestricted_nopasswd
        or probe.returncode != 0
        or (probe.stdout or b"").strip() != b"0"
    ):
        raise GatewayError(
            "The LLDPq service account does not have verified unrestricted NOPASSWD sudo; uninstall was not started."
        )


def ensure_run_dir() -> None:
    try:
        os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
        metadata = os.lstat(RUN_DIR)
    except OSError as exc:
        raise GatewayError("Could not prepare the uninstall confirmation directory") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GatewayError("Uninstall confirmation directory failed its ownership check")


def token_lock():
    ensure_run_dir()
    path = os.path.join(RUN_DIR, ".lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise GatewayError("Uninstall confirmation lock failed its ownership check")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def lifecycle_lock(*, timeout_seconds=LIFECYCLE_LOCK_TIMEOUT_SECONDS):
    try:
        descriptor = os.open(LIFECYCLE_LOCK, os.O_RDWR | os.O_NOFOLLOW)
    except OSError as exc:
        raise GatewayError("The stable LLDPq lifecycle lock is missing or unsafe") from exc
    metadata = os.fstat(descriptor)
    try:
        web_gid = grp.getgrnam("www-data").gr_gid
    except KeyError:
        os.close(descriptor)
        raise GatewayError("Required www-data group does not exist")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != web_gid
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise GatewayError("The stable LLDPq lifecycle lock failed its ownership check")
    if timeout_seconds is None:
        # The already-reserved transient runner may wait: its durable public
        # marker blocks every competing lifecycle operation while it does so.
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    else:
        # CGI callers must never outlive setup-api.sh's bounded subprocess and
        # later consume a preview token after the browser has concluded that
        # no job exists. Keep both pre-reservation start locks well below that
        # outer timeout and fail without creating authority if the host is busy.
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise StartAmbiguousError(
                        "Another LLDPq install, update or uninstall lifecycle operation is active"
                    ) from exc
                time.sleep(0.05)
    # flock follows the opened inode.  The uninstaller removes this pathname
    # while holding the lock, so a waiter must reject an unlinked/replaced old
    # inode after it wakes instead of entering a second lifecycle transaction.
    try:
        current = os.lstat(LIFECYCLE_LOCK)
        opened = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise GatewayError("The stable LLDPq lifecycle lock disappeared while waiting") from exc
    if (
        (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != 0
        or current.st_gid != web_gid
        or stat.S_IMODE(current.st_mode) != 0o660
        or current.st_nlink != 1
    ):
        os.close(descriptor)
        raise GatewayError("The stable LLDPq lifecycle lock changed while waiting")
    return descriptor


def read_public_active_marker():
    if not os.path.lexists(PUBLIC_ACTIVE_MARKER):
        return None
    try:
        descriptor = os.open(PUBLIC_ACTIVE_MARKER, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise GatewayError("Public uninstall marker could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
            or metadata.st_size > 64
        ):
            raise GatewayError("Public uninstall marker failed its ownership check")
        try:
            value = os.read(descriptor, 65).decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise GatewayError("Public uninstall marker is corrupt") from exc
    finally:
        os.close(descriptor)
    if not JOB_RE.fullmatch(value):
        raise GatewayError("Public uninstall marker is corrupt")
    return value


def create_public_active_marker(request_id: str) -> None:
    descriptor = os.open(
        PUBLIC_ACTIVE_MARKER,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.fchmod(descriptor, 0o644)
        os.fchown(descriptor, 0, 0)
        os.write(descriptor, (request_id + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_public_active_marker(request_id: str) -> None:
    current = read_public_active_marker()
    if current is None:
        return
    if current != request_id:
        raise GatewayError("Refusing to remove another uninstall job's public marker")
    os.unlink(PUBLIC_ACTIVE_MARKER)


def setup_job_state_active(home: str) -> bool:
    state = os.path.join(home, ".lldpq-state")
    if os.path.islink(state):
        raise GatewayError("LLDPq state directory is a symlink")
    return any(os.path.lexists(os.path.join(state, name)) for name in ("run.active", "update.active"))


def cleanup_expired_tokens(now: int) -> None:
    try:
        names = os.listdir(RUN_DIR)
    except OSError:
        return
    for name in names:
        if not TOKEN_RE.fullmatch(name):
            continue
        path = os.path.join(RUN_DIR, name)
        try:
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
                continue
            if metadata.st_mtime < now - TOKEN_TTL_SECONDS:
                os.unlink(path)
        except OSError:
            continue


def create_token(options: dict[str, bool], user: str) -> tuple[str, int, str]:
    now = int(time.time())
    expires = now + TOKEN_TTL_SECONDS
    context = {
        "version": 1,
        "expires": expires,
        "options": options,
        "config": config_identity(),
        "user": user,
    }
    lock = token_lock()
    try:
        cleanup_expired_tokens(now)
        public_job_id = read_public_active_marker()
        if public_job_id is not None:
            raise GatewayError(
                "An uninstall job is already scheduled or running (job_id="
                + public_job_id
                + ")"
            )
        if os.path.lexists(ACTIVE_RECORD):
            active_record = _read_root_record(ACTIVE_RECORD)
            active_job_id = active_record.get("request_id")
            detail = active_job_id if isinstance(active_job_id, str) else "unknown"
            raise GatewayError(
                "An uninstall job is already scheduled or running (job_id=" + detail + ")"
            )
        for _ in range(8):
            token = secrets.token_hex(32)
            canonical = json.dumps(context, separators=(",", ":"), sort_keys=True).encode("ascii")
            fingerprint = hashlib.sha256(canonical + b"\x00" + token.encode("ascii")).hexdigest()
            record = dict(context)
            record["fingerprint"] = fingerprint
            encoded = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
            path = os.path.join(RUN_DIR, token)
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
            except FileExistsError:
                continue
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(RUN_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return token, expires, fingerprint
    finally:
        os.close(lock)
    raise GatewayError("Could not allocate an uninstall confirmation token")


def _read_root_record(path: str) -> dict:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise GatewayError("Required uninstall state is missing") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 8192
        ):
            raise GatewayError("Uninstall state failed its ownership check")
        encoded = os.read(descriptor, 8193)
    finally:
        os.close(descriptor)
    try:
        record = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayError("Uninstall state is corrupt") from exc
    if not isinstance(record, dict):
        raise GatewayError("Uninstall state is corrupt")
    return record


def _write_root_record(path: str, record: dict) -> None:
    encoded = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def consume_token(
    token: object,
    fingerprint: object,
    options: dict[str, bool],
    user: str,
    request_id: str,
) -> bool:
    """Consume approval and reserve request_id; return True for an idempotent retry."""
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise GatewayError("Invalid or expired uninstall confirmation token")
    if not isinstance(fingerprint, str) or not TOKEN_RE.fullmatch(fingerprint):
        raise GatewayError("Invalid uninstall preview fingerprint")
    path = os.path.join(RUN_DIR, token)
    job_path = os.path.join(RUN_DIR, "job-" + request_id + ".json")
    lock = token_lock()
    try:
        if os.path.lexists(ACTIVE_RECORD):
            active_record = _read_root_record(ACTIVE_RECORD)
            if active_record.get("request_id") != request_id:
                raise GatewayError("Another uninstall job is already scheduled or running")
        if os.path.lexists(job_path):
            job_record = _read_root_record(job_path)
            if (
                job_record.get("fingerprint") == fingerprint
                and job_record.get("options") == options
                and job_record.get("user") == user
            ):
                return True
            raise GatewayError("request_id is already bound to a different uninstall request")

        try:
            record = _read_root_record(path)
        except GatewayError as exc:
            raise GatewayError("Invalid or expired uninstall confirmation token") from exc

        expires = record.get("expires")
        if type(expires) is not int:
            raise GatewayError("Uninstall confirmation token is corrupt")
        if expires <= int(time.time()):
            raise GatewayError("Uninstall confirmation token expired; generate a new preview")
        if record.get("options") != options:
            raise GatewayError("Uninstall options changed after the preview; generate a new preview")
        if record.get("fingerprint") != fingerprint:
            raise GatewayError("Uninstall preview fingerprint does not match; generate a new preview")
        if record.get("user") != user or record.get("config") != config_identity():
            raise GatewayError("LLDPq configuration changed after the preview; generate a new preview")

        # The directory is root-only and this operation is serialized.  Unlink
        # and reserve the authoritative request id in one lock transaction so
        # retries and concurrent requests cannot start a second unit.
        os.unlink(path)
        job_record = {
            "version": 1,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "options": options,
            "user": user,
            "config": record["config"],
            "created": int(time.time()),
        }
        _write_root_record(job_path, job_record)
        try:
            _write_root_record(ACTIVE_RECORD, job_record)
        except Exception:
            os.unlink(job_path)
            raise
        directory_fd = os.open(RUN_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(lock)
    return False


def remove_job_reservation(request_id: str, *, lifecycle_locked: bool = False) -> None:
    lifecycle_descriptor = None if lifecycle_locked else lifecycle_lock()
    try:
        if os.path.lexists(RUN_DIR):
            lock = token_lock()
            try:
                path = os.path.join(RUN_DIR, "job-" + request_id + ".json")
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                if os.path.lexists(ACTIVE_RECORD):
                    try:
                        active_record = _read_root_record(ACTIVE_RECORD)
                    except GatewayError:
                        active_record = {}
                    if active_record.get("request_id") == request_id:
                        os.unlink(ACTIVE_RECORD)
            finally:
                os.close(lock)
        remove_public_active_marker(request_id)
    finally:
        if lifecycle_descriptor is not None:
            os.close(lifecycle_descriptor)


def load_job_reservation(request_id: str):
    path = os.path.join(RUN_DIR, "job-" + request_id + ".json")
    if not os.path.lexists(path):
        return None
    return _read_root_record(path)


def load_active_reservation():
    if not os.path.lexists(ACTIVE_RECORD):
        return None
    record = _read_root_record(ACTIVE_RECORD)
    request_id = record.get("request_id")
    if not isinstance(request_id, str) or not JOB_RE.fullmatch(request_id):
        raise GatewayError("Active uninstall reservation is corrupt")
    return record


def bounded_text(raw: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(raw) > limit
    if truncated:
        raw = raw[-limit:]
    return raw.decode("utf-8", errors="replace"), truncated


def preview(request: dict) -> dict:
    refuse_container()
    verify_root_owned_program(UNINSTALLER)
    options = parse_options(request)
    parse_acknowledgements(request)
    user, home = read_runtime_user()
    verify_passwordless_sudo(user, home)
    result = subprocess.run(
        user_environment(user, home) + option_argv(options, preview=True),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    output, truncated = bounded_text(result.stdout or b"", MAX_PREVIEW_BYTES)
    if result.returncode != 0:
        raise GatewayError(
            "Uninstall dry-run failed; nothing was changed.\n" + output[-4000:]
        )
    token, expires, fingerprint = create_token(options, user)
    return {
        "success": True,
        "preview_token": token,
        "preview_fingerprint": fingerprint,
        "expires_at": expires,
        "preview": output,
        "preview_truncated": truncated,
        "service_user": user,
    }


def validate_start_acknowledgements(request: dict, options: dict[str, bool]) -> None:
    acknowledgements = parse_acknowledgements(request)
    if request.get("confirmation") != "UNINSTALL":
        raise GatewayError("Type UNINSTALL exactly to confirm")
    if acknowledgements["ack_disconnect"] is not True:
        raise GatewayError("Acknowledge that the web interface will disconnect")
    if not options["keep_data"] and acknowledgements["ack_data_loss"] is not True:
        raise GatewayError("Acknowledge permanent configuration and monitoring-data removal")
    if any(options[key] for key in ("remove_dhcp", "remove_nginx", "remove_docker")) and request[
        "acknowledgements"
    ][
        "ack_shared_services"
    ] is not True:
        raise GatewayError("Acknowledge that selected shared host services and data may be removed")


def run_reserved_uninstall() -> int:
    """Execute only the still-authorized reservation from a transient unit.

    systemd-run acceptance is intrinsically ambiguous if its client times out:
    the D-Bus request may materialize after a later status request observes no
    unit.  Keeping this root-owned guard as the transient service command makes
    the reservation revocable.  Status may retire a definitively missing launch
    while holding the lifecycle lock; a late unit will then acquire the same
    lock, find no matching marker and refuse to spawn the uninstaller.
    """
    job_id = os.environ.get("LLDPQ_UNINSTALL_JOB_ID", "")
    if not JOB_RE.fullmatch(job_id):
        raise GatewayError("Reserved uninstall runner received an invalid job id")

    lifecycle_descriptor = lifecycle_lock(timeout_seconds=None)
    process = None
    try:
        reservation = load_job_reservation(job_id)
        active = load_active_reservation()
        public_job_id = read_public_active_marker()
        if (
            reservation is None
            or active is None
            or active.get("request_id") != job_id
            or public_job_id != job_id
        ):
            raise GatewayError("Reserved uninstall authority is absent or no longer matches")
        options = parse_options({"options": reservation.get("options")})
        user, home = read_runtime_user()
        if (
            reservation.get("user") != user
            or reservation.get("config") != config_identity()
        ):
            raise GatewayError("LLDPq configuration changed before the reserved uninstall launched")
        verify_root_owned_program(UNINSTALLER)
        verify_passwordless_sudo(user, home)
        command = (
            user_environment(user, home)
            + ["LLDPQ_UNINSTALL_JOB_ID=" + job_id]
            + option_argv(options, preview=False)
        )
        # Popen returns only after the child exists.  Keep this gateway process
        # as the systemd service parent until the user-context uninstaller exits;
        # an authoritative service query therefore cannot report the unit
        # missing while destructive work is still running.
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
    finally:
        os.close(lifecycle_descriptor)
    return process.wait()


def start(request: dict) -> dict:
    refuse_container()
    verify_root_owned_program(UNINSTALLER)
    verify_root_owned_program(GATEWAY)
    verify_root_owned_program(SYSTEMD_RUN)
    options = parse_options(request)
    validate_start_acknowledgements(request, options)
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not JOB_RE.fullmatch(request_id):
        raise GatewayError("request_id must be exactly 32 lowercase hexadecimal characters")
    supplied_token = request.get("preview_token")
    supplied_fingerprint = request.get("preview_fingerprint")
    if not isinstance(supplied_token, str) or not TOKEN_RE.fullmatch(supplied_token):
        raise GatewayError("Invalid or expired uninstall confirmation token")
    if not isinstance(supplied_fingerprint, str) or not TOKEN_RE.fullmatch(supplied_fingerprint):
        raise GatewayError("Invalid uninstall preview fingerprint")

    # Fast idempotent response recovery does not depend on /etc/lldpq.conf,
    # which the accepted uninstall intentionally removes later in its run.
    lifecycle_descriptor = lifecycle_lock()
    try:
        existing = load_job_reservation(request_id)
        public_job_id = read_public_active_marker()
        if existing is not None:
            if (
                existing.get("fingerprint") != supplied_fingerprint
                or existing.get("options") != options
                or public_job_id != request_id
            ):
                raise StartAmbiguousError(
                    "request_id is already bound to a different uninstall request"
                )
            unit_base = "lldpq-uninstall-" + request_id
            return {
                "success": True,
                # A durable reservation proves idempotency, but it may have
                # originated from a timed-out systemd-run acknowledgement.
                # Status is the authority for whether that launch materialized.
                "accepted": None,
                "job_id": request_id,
                "unit": unit_base + ".service",
                "starts_in_seconds": 3,
                "message": "Uninstall was already scheduled for this request id.",
            }
    finally:
        os.close(lifecycle_descriptor)

    user, home = read_runtime_user()
    verify_passwordless_sudo(user, home)
    lifecycle_descriptor = lifecycle_lock()
    try:
        public_job_id = read_public_active_marker()
        existing = load_job_reservation(request_id)
        if existing is not None:
            if (
                existing.get("fingerprint") != supplied_fingerprint
                or existing.get("options") != options
                or public_job_id != request_id
            ):
                raise StartAmbiguousError(
                    "request_id is already bound to a different uninstall request"
                )
            already_scheduled = True
        else:
            if public_job_id is not None:
                raise GatewayError("Another uninstall job is already scheduled or running")
            if setup_job_state_active(home):
                raise GatewayError("A run or update job became active before uninstall reservation")
            already_scheduled = consume_token(
                supplied_token,
                supplied_fingerprint,
                options,
                user,
                request_id,
            )
            try:
                create_public_active_marker(request_id)
            except Exception:
                remove_job_reservation(request_id, lifecycle_locked=True)
                raise
    finally:
        os.close(lifecycle_descriptor)

    job_id = request_id
    unit_base = "lldpq-uninstall-" + job_id
    if already_scheduled:
        return {
            "success": True,
            "accepted": None,
            "job_id": job_id,
            "unit": unit_base + ".service",
            "starts_in_seconds": 3,
            "message": "Uninstall was already scheduled for this request id.",
        }
    command = [
        SYSTEMD_RUN,
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=" + unit_base,
        "--on-active=3s",
        "--timer-property=AccuracySec=100ms",
        "--property=WorkingDirectory=" + home,
        "--property=UMask=0077",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        ENV,
        "-i",
        "PATH=" + SAFE_PATH,
        "LC_ALL=C",
        "LLDPQ_UNINSTALL_JOB_ID=" + job_id,
        GATEWAY,
        "_run-reserved",
    ]
    launch_uncertain = False
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # Never infer rejection from an immediate, possibly unobservable
        # systemctl query.  The D-Bus request may already be accepted, so keep
        # both markers fail-closed and let status reconcile it under the shared
        # lifecycle lock.  The transient service's guarded command prevents a
        # later-appearing unit from running after such reconciliation.
        launch_uncertain = True
        result = subprocess.CompletedProcess(command, 0, stdout=b"")
    except OSError as exc:
        remove_job_reservation(job_id)
        raise GatewayError("Could not execute systemd-run") from exc
    if result.returncode != 0:
        remove_job_reservation(job_id)
        detail, _ = bounded_text(result.stdout or b"", 4000)
        raise GatewayError("Could not start the detached uninstall unit: " + detail.strip())
    return {
        "success": True,
        "accepted": None if launch_uncertain else True,
        "job_id": job_id,
        "unit": unit_base + ".service",
        "starts_in_seconds": 3,
        "launch_uncertain": launch_uncertain,
        "message": (
            "Uninstall launch acknowledgement timed out; the reservation remains locked while status verifies it."
            if launch_uncertain
            else "Uninstall scheduled; the web interface will disconnect."
        ),
    }


def systemctl_properties(unit: str) -> dict[str, str]:
    properties = (
        "LoadState",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "ExecMainStartTimestampMonotonic",
    )
    command = [SYSTEMCTL, "show", unit, "--no-pager"]
    for name in properties:
        command.extend(["--property", name])
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=STATUS_COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    values: dict[str, str] = {}
    for line in (result.stdout or b"").decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in properties:
                values[key] = value
    return values


def journal_output(unit: str) -> tuple[bytes, bool]:
    try:
        result = subprocess.run(
            [
                JOURNALCTL,
                "--unit=" + unit,
                "--no-pager",
                "--output=cat",
                "--lines=400",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=STATUS_COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return b"", False
    return result.stdout or b"", result.returncode == 0


def reconcile_missing_launch(job_id: str, unit_base: str):
    """Retire a truly absent launch without racing a late accepted unit.

    The second, authoritative observation is made while holding the lifecycle
    lock also required by ``_run-reserved``.  If the status path wins, it first
    removes the reservation and a late unit refuses to spawn.  If the runner
    wins, it spawns the child before releasing the lock and remains the active
    systemd service until that child exits, so this observer cannot classify
    the launch as missing.
    """
    descriptor = lifecycle_lock()
    try:
        reservation = load_job_reservation(job_id)
        active = load_active_reservation()
        public_job_id = read_public_active_marker()
        if reservation is None:
            return False, None, {}, {}, b"", False
        if (
            active is None
            or active.get("request_id") != job_id
            or public_job_id != job_id
        ):
            raise GatewayError("Private and public uninstall reservations disagree")

        service = systemctl_properties(unit_base + ".service")
        timer = systemctl_properties(unit_base + ".timer")
        journal, journal_observed = journal_output(unit_base + ".service")
        created = reservation.get("created")
        age = max(0, int(time.time()) - created) if type(created) is int else 0
        required_age = ORPHANED_STATUS_SECONDS if journal.strip() else 30
        timer_cannot_fire = timer.get("LoadState") == "not-found" or (
            timer.get("LoadState") not in (None, "not-found")
            and timer.get("ActiveState") in ("inactive", "failed")
            and timer.get("SubState") in ("dead", "failed")
        )
        definitively_missing = (
            service.get("LoadState") == "not-found"
            and timer_cannot_fire
            and journal_observed
        )
        if age <= required_age or not definitively_missing:
            return False, None, service, timer, journal, journal_observed

        result_name = "interrupted-status-missing" if journal.strip() else "launch-state-missing"
        remove_job_reservation(job_id, lifecycle_locked=True)
        return True, result_name, service, timer, journal, journal_observed
    finally:
        os.close(descriptor)


def status(request: dict) -> dict:
    job_id = request.get("job_id")
    if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id):
        raise GatewayError("Invalid uninstall job id")
    unit_base = "lldpq-uninstall-" + job_id
    reservation = load_job_reservation(job_id)
    active_reservation = load_active_reservation()
    private_active_job_id = active_reservation.get("request_id") if active_reservation else None
    public_active_job_id = read_public_active_marker()
    if (
        private_active_job_id
        and public_active_job_id
        and private_active_job_id != public_active_job_id
    ):
        raise GatewayError("Private and public uninstall reservations disagree")
    active_job_id = public_active_job_id or private_active_job_id
    reserved = reservation is not None
    reservation_age = 0
    if reservation is not None and type(reservation.get("created")) is int:
        reservation_age = max(0, int(time.time()) - reservation["created"])

    service: dict[str, str] = {}
    timer: dict[str, str] = {}
    journal = b""
    journal_observed = False
    reconciled = False
    reconciled_result = None
    if reserved and reservation_age > 30:
        # For an old reservation, make the first observation under the same
        # lifecycle lock as the guarded runner.  This is both race-free and
        # keeps the status request within its bounded CGI timeout.
        (
            reconciled,
            reconciled_result,
            observed_service,
            observed_timer,
            observed_journal,
            observed_journal_ok,
        ) = reconcile_missing_launch(job_id, unit_base)
        service = observed_service
        timer = observed_timer
        journal = observed_journal
        journal_observed = observed_journal_ok
        if reconciled:
            reserved = False
            active_job_id = None
    else:
        service = systemctl_properties(unit_base + ".service")
        timer = systemctl_properties(unit_base + ".timer")
        journal, journal_observed = journal_output(unit_base + ".service")
    log, truncated = bounded_text(journal, MAX_JOURNAL_BYTES)

    known = (
        service.get("LoadState") not in (None, "not-found")
        or timer.get("LoadState") not in (None, "not-found")
        or bool(log.strip())
        or reserved
        or reconciled
    )
    if not known:
        raise GatewayError("Uninstall job was not found")

    timer_running = timer.get("ActiveState") in ("active", "activating")
    service_running = service.get("ActiveState") in ("active", "activating", "reloading")
    started = service.get("ExecMainStartTimestampMonotonic", "0") not in ("", "0")
    result_name = service.get("Result", "")
    exit_text = service.get("ExecMainStatus", "")
    exit_status = int(exit_text) if exit_text.isdigit() else None
    marker_matches = re.findall(r"(?m)^__LLDPQ_UNINSTALL_DONE__:([0-9]+)\s*$", log)
    marker_status = int(marker_matches[-1]) if marker_matches else None
    if marker_status is not None:
        exit_status = marker_status
    service_terminal = (
        started
        and not service_running
        and result_name not in ("", "unset")
    )
    inconclusive_reservation = (
        reserved
        and not timer_running
        and not service_running
        and marker_status is None
        and not service_terminal
    )
    # An unobservable manager/journal is not negative evidence.  Keep an
    # inconclusive reservation running/fail-closed for as long as necessary;
    # only reconcile_missing_launch can retire it after bounded authoritative
    # observations under the lifecycle lock.
    running = timer_running or service_running or inconclusive_reservation
    done = marker_status is not None or service_terminal or reconciled
    if reconciled:
        result_name = reconciled_result or "launch-state-missing"
    ok = done and exit_status == 0 and result_name in ("", "success")
    if done and not ok and reserved:
        # A terminal failure must not leave the fail-closed active marker
        # blocking every future dry-run forever.  Only the status observer that
        # has authoritative terminal evidence may retire this request; a new
        # preview/token is then required before another start.
        remove_job_reservation(job_id)
        active_job_id = None
    return {
        "success": True,
        "job_id": job_id,
        "active_job_id": active_job_id,
        "running": running,
        "done": done,
        "ok": ok,
        "result": result_name or None,
        "exit_code": exit_status if done else None,
        "log": log,
        "log_truncated": truncated,
        "disconnect_expected": True,
    }


def main() -> int:
    if os.geteuid() != 0:
        raise GatewayError("The uninstall gateway must run as root")
    if len(sys.argv) == 2 and sys.argv[1] == "_run-reserved":
        try:
            return run_reserved_uninstall()
        except (GatewayError, OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("Reserved uninstall launch refused: " + str(exc)[:4000] + "\n")
            return 125
    if len(sys.argv) != 2 or sys.argv[1] not in {"preview", "start", "status"}:
        raise GatewayError("Usage: lldpq-uninstall-web.py preview|start|status")
    command = sys.argv[1]
    request = read_request(command)
    if command == "preview":
        response = preview(request)
    elif command == "start":
        try:
            response = start(request)
        except StartAmbiguousError as exc:
            emit(
                {
                    "success": False,
                    "accepted": None,
                    "error": str(exc)[:8000],
                }
            )
            return 0
        except (GatewayError, OSError, subprocess.TimeoutExpired) as exc:
            # Every dispatch ambiguity is converted by start() into a durable
            # accepted:null response.  Reaching this handler therefore means
            # systemd-run was authoritatively not accepted (or was never
            # attempted), and the UI may discard its pending request id.
            emit(
                {
                    "success": False,
                    "accepted": False,
                    "error": str(exc)[:8000],
                }
            )
            return 0
    else:
        response = status(request)
    emit(response)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GatewayError as exc:
        emit({"success": False, "error": str(exc)[:8000]})
        raise SystemExit(0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        emit({"success": False, "error": ("Uninstall gateway failed: " + str(exc))[:8000]})
        raise SystemExit(0)

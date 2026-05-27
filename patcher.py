"""
patcher.py
Applies a security advisory to a remote Linux host via SSH.

Supported platforms:
  - redhat (RHEL 7 / 8 / 9)  →  dnf / yum
  - suse   (SLES 12 / 15)    →  zypper

Windows patching via WinRM is not implemented in this version.

Security notes:
  - AutoAddPolicy is used for ease of use on internal networks.
    For production environments with strict security requirements, replace with
    RejectPolicy and pre-register host keys:
        ssh-keyscan <host> >> ~/.ssh/known_hosts
  - SSH key-based auth is strongly preferred over password auth.
  - Passwords are never logged or written to disk by this module.
  - The SSH user must have passwordless sudo for dnf/zypper on the target host.
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

_CONNECT_TIMEOUT = 30    # seconds — SSH handshake deadline
_COMMAND_TIMEOUT = 600   # seconds — allow up to 10 min for large OS updates


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class PatchResult:
    success:     bool
    host:        str
    advisory_id: str
    platform:    str
    output:      str
    error:       str = ""
    exit_code:   int = -1


# ── Internal helpers ──────────────────────────────────────────────────────────

def _patch_command(platform: str, advisory_id: str) -> str:
    """
    Return the shell command that installs a single advisory on the target host.
    Commands write both stdout and stderr to the same stream (2>&1) so the
    caller can capture a single, unified output string.
    """
    if platform == "redhat":
        # dnf (RHEL 8/9) with fallback to yum (RHEL 7)
        return (
            f"sudo dnf update --advisory={advisory_id} -y 2>&1 || "
            f"sudo yum update --advisory={advisory_id} -y 2>&1"
        )
    if platform == "suse":
        return f"sudo zypper --non-interactive patch --bugzilla={advisory_id} 2>&1"
    return ""


# ── Public API ────────────────────────────────────────────────────────────────

def apply_patch_ssh(
    host: str,
    username: str,
    advisory_id: str,
    platform: str,
    ssh_key_path: Optional[str] = None,
    password: Optional[str] = None,
    port: int = 22,
) -> PatchResult:
    """
    SSH into a remote Linux host and apply the specified security advisory.

    Args:
        host:         Hostname or IP address of the target server.
        username:     SSH login user.  Must have passwordless sudo rights for
                      dnf (RHEL) or zypper (SUSE) on the remote host.
        advisory_id:  Advisory identifier — e.g. "RHSA-2024:1234" for RHEL or
                      a CVE/patch ID for SUSE.
        platform:     "redhat" or "suse".
        ssh_key_path: Path to an SSH private key file (e.g. "~/.ssh/id_rsa").
                      Takes priority over password when both are provided.
        password:     SSH password.  Only used when ssh_key_path is not set.
        port:         SSH port (default 22).

    Returns:
        PatchResult dataclass containing success flag, command output, error
        message, and the remote process exit code.
    """
    if not PARAMIKO_AVAILABLE:
        return PatchResult(
            False, host, advisory_id, platform, "",
            "paramiko is not installed — run: pip install paramiko",
        )

    if platform not in ("redhat", "suse"):
        return PatchResult(
            False, host, advisory_id, platform, "",
            f"SSH patching is not supported for platform '{platform}'.",
        )

    cmd = _patch_command(platform, advisory_id)

    try:
        client = paramiko.SSHClient()
        # AutoAddPolicy: auto-accept host keys for internal network ease of use.
        # Replace with paramiko.RejectPolicy() in high-security environments.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_args: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": _CONNECT_TIMEOUT,
        }
        if ssh_key_path:
            connect_args["key_filename"] = os.path.expanduser(ssh_key_path)
        elif password:
            connect_args["password"] = password
        # If neither is provided, paramiko falls back to the SSH agent / default key

        logging.info("[Patcher] Connecting to %s:%s as %s", host, port, username)
        client.connect(**connect_args)

        logging.info("[Patcher] Running patch command for %s", advisory_id)
        _, stdout, stderr = client.exec_command(cmd, timeout=_COMMAND_TIMEOUT)
        output    = stdout.read().decode(errors="replace")
        error     = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()

        success = exit_code == 0
        logging.info("[Patcher] %s on %s → exit_code=%s", advisory_id, host, exit_code)
        return PatchResult(success, host, advisory_id, platform, output, error, exit_code)

    except paramiko.AuthenticationException:
        return PatchResult(
            False, host, advisory_id, platform, "",
            "SSH authentication failed — check username and credentials.",
        )
    except paramiko.SSHException as exc:
        return PatchResult(False, host, advisory_id, platform, "", f"SSH error: {exc}")
    except OSError as exc:
        return PatchResult(False, host, advisory_id, platform, "", f"Connection error: {exc}")
    except Exception as exc:
        logging.exception("[Patcher] Unexpected error patching %s", host)
        return PatchResult(False, host, advisory_id, platform, "", str(exc))

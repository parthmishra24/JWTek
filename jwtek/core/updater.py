import subprocess
import re
from pip import __version__ as pip_version
from . import ui


def _supports_break_system_packages(version: str | None = None) -> bool:
    """Return True if pip version is >= 23.0."""
    if version is None:
        version = pip_version
    match = re.match(r"^(\d+)\.(\d+)", version)
    if not match:
        return False
    major, minor = int(match.group(1)), int(match.group(2))
    return (major, minor) >= (23, 0)


def update_tool(repo_url: str = "https://github.com/parthmishra24/JWTek.git", branch: str = "main") -> None:
    """Update JWTEK from the specified Git repository."""
    ui.info(f"[~] Updating JWTEK from {repo_url}@{branch}...")
    cmd = [
        "python3",
        "-m",
        "pip",
        "install",
        "--upgrade",
    ]
    if _supports_break_system_packages():
        cmd.append("--break-system-packages")
    cmd.append(f"git+{repo_url}@{branch}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            ui.success("[+] JWTEK updated successfully.")
        else:
            ui.error(f"[!] Failed to update JWTEK: {result.stderr}")
    except Exception as exc:
        ui.error(f"[!] Failed to update JWTEK: {exc}")


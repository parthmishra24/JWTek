import subprocess
import sys
from . import ui


def update_tool(repo_url="https://github.com/parthmishra24/JWTek.git", branch="main"):
    """Update JWTEK from the specified Git repository."""
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{repo_url}@{branch}"]
    ui.info(f"[~] Updating JWTEK from {repo_url}@{branch}...")
    try:
        subprocess.check_call(cmd)
        ui.success("[+] JWTEK updated successfully.")
    except Exception as exc:
        ui.error(f"[!] Failed to update JWTEK: {exc}")


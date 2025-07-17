import subprocess
from . import ui


def update_tool(repo_url: str = "github.com/parthmishra24/JWTek", version: str = "latest") -> None:
    """Update JWTEK using Go."""
    ui.info(f"[~] Updating JWTEK from {repo_url}@{version}...")
    cmd = [
        "go",
        "install",
        f"{repo_url}@{version}",
    ]
    try:
        subprocess.check_call(cmd)
        ui.success("[+] JWTEK updated successfully.")
    except Exception as exc:
        ui.error(f"[!] Failed to update JWTEK: {exc}")


import subprocess
from . import ui


def update_tool(repo_url: str = "https://github.com/parthmishra24/JWTek.git", branch: str = "main") -> None:
    """Update JWTEK from the specified Git repository."""
    ui.info(f"[~] Updating JWTEK from {repo_url}@{branch}...")
    cmd = [
        "python3",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--break-system-packages",
        f"git+{repo_url}@{branch}",
    ]
    try:
        subprocess.check_call(cmd)
        ui.success("[+] JWTEK updated successfully.")
    except Exception as exc:
        ui.error(f"[!] Failed to update JWTEK: {exc}")


"""Console UI helpers with optional color output."""

import os
from termcolor import cprint


# Determine if colors should be disabled either via environment variable or
# runtime flag.  The ``JWTEK_NO_COLOR`` env var mirrors the ``--no-color`` CLI
# option added in ``__main__``.  Tests also modify this flag directly.
NO_COLOR = os.environ.get("JWTEK_NO_COLOR") == "1"


def set_no_color(value: bool) -> None:
    """Allow disabling coloured output programmatically."""
    global NO_COLOR
    NO_COLOR = bool(value)


def _cprint(msg: str, color: str = None, attrs=None) -> None:
    """Wrapper around :func:`termcolor.cprint` respecting NO_COLOR."""
    if NO_COLOR:
        print(msg)
    else:
        cprint(msg, color, attrs=attrs)

def section(title: str) -> None:
    """Print a coloured section heading."""
    line = "═" * (len(title) + 4)
    print()
    _cprint(f"╔{line}╗", "cyan")
    _cprint(f"║  {title}  ║", "cyan", attrs=["bold"])
    _cprint(f"╚{line}╝", "cyan")


def info(msg: str) -> None:
    """Display an informational message."""
    _cprint(msg, "cyan")


def success(msg: str) -> None:
    """Display a success message."""
    _cprint(msg, "green")


def warn(msg: str) -> None:
    """Display a warning message."""
    _cprint(msg, "yellow")


def error(msg: str) -> None:
    """Display an error message."""
    _cprint(msg, "red")

"""Console UI helpers with optional color output and quality of life prompts."""

import os
import sys
from termcolor import cprint

try:  # pragma: no cover - platform specific availability
    import readline  # type: ignore
except ImportError:  # pragma: no cover - Windows fallback
    readline = None


def _path_completion_options(text: str, base_dir: str | None = None) -> list[str]:
    """Return filesystem completion options for ``text`` relative to ``base_dir``."""

    cwd = base_dir or os.getcwd()
    if not text:
        text = ""

    expanded = os.path.expanduser(text)
    if os.path.isabs(expanded):
        expanded_abs = expanded
    else:
        expanded_abs = os.path.join(cwd, expanded)

    search_dir: str
    prefix: str
    display_prefix: str

    if os.path.isdir(expanded_abs) and text.endswith(os.sep):
        search_dir = expanded_abs
        prefix = ""
        display_prefix = text
    else:
        search_dir = os.path.dirname(expanded_abs)
        prefix = os.path.basename(expanded_abs)
        display_prefix = os.path.dirname(text)
        if display_prefix:
            display_prefix = display_prefix.rstrip(os.sep) + os.sep

    if not search_dir:
        search_dir = cwd

    try:
        entries = sorted(os.listdir(search_dir))
    except OSError:
        return []

    suggestions: list[str] = []
    for name in entries:
        if prefix and not name.startswith(prefix):
            continue
        full_path = os.path.join(search_dir, name)
        display = f"{display_prefix}{name}" if display_prefix else name
        if os.path.isdir(full_path):
            display = display.rstrip(os.sep) + os.sep
        suggestions.append(display)

    return suggestions


def prompt_path(prompt: str) -> str:
    """Prompt the user for a filesystem path with interactive tab completion."""

    if readline is None or not getattr(sys.stdin, "isatty", lambda: False)():
        return input(prompt)

    def completer(text: str, state: int) -> str | None:
        options = _path_completion_options(text)
        if state < len(options):
            return options[state]
        return None

    previous_completer = readline.get_completer()
    previous_delims = readline.get_completer_delims()

    try:
        readline.set_completer_delims(" \t\n\"'")
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        return input(prompt)
    finally:
        readline.set_completer(previous_completer)
        readline.set_completer_delims(previous_delims)


# Determine if colors should be disabled either via environment variable or
# runtime flag.  The ``JWTEK_NO_COLOR`` env var mirrors the ``-no-color`` CLI
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

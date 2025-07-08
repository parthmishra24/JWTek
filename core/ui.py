from termcolor import cprint

def section(title):
    line = "═" * (len(title) + 4)
    print()
    cprint(f"╔{line}╗", "cyan")
    cprint(f"║  {title}  ║", "cyan", attrs=["bold"])
    cprint(f"╚{line}╝", "cyan")

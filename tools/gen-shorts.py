#!/usr/bin/env python3
"""Generate 10-second TL;DR 'shorts' versions of the PKI demo stories.

Each short is a punchy, honest, reel-style asciinema cast:
  - Fast typing, no pauses
  - One command, one punchline
  - IT humor that anyone who's managed certs will feel in their soul

Output: docs/demos/short-{a..f}.cast
"""

import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "demos"

ESC = "\x1b"
WIDTH = 120
HEIGHT = 24


def clear() -> str:
    return f"{ESC}[2J{ESC}[H"


def move(row: int, col: int) -> str:
    return f"{ESC}[{row};{col}H"


def c(code: str, text: str) -> str:
    return f"{ESC}[{code}m{text}{ESC}[0m"


def bold(text: str) -> str:
    return c("1;37", text)


def cyan(text: str) -> str:
    return c("1;36", text)


def green(text: str) -> str:
    return c("1;32", text)


def red(text: str) -> str:
    return c("1;31", text)


def yellow(text: str) -> str:
    return c("1;33", text)


def dim(text: str) -> str:
    return c("2;37", text)


def gray(text: str) -> str:
    return c("0;90", text)


def prompt() -> str:
    return f"{green('$')} "


def type_cmd(events: list, t: float, cmd: str, speed: float = 0.03) -> float:
    """Simulate fast typing a command character by character."""
    events.append([round(t, 3), "o", prompt()])
    t += 0.05
    for ch in cmd:
        events.append([round(t, 3), "o", ch])
        t += speed
    events.append([round(t, 3), "o", "\r\n"])
    t += 0.1
    return t


def output_line(events: list, t: float, text: str, delay: float = 0.08) -> float:
    """Print an output line."""
    events.append([round(t, 3), "o", text + "\r\n"])
    return t + delay


def center(text: str, width: int = WIDTH) -> str:
    """Center text in terminal width (approximate — ignores ANSI)."""
    # Strip ANSI for length calc
    import re
    visible = re.sub(r'\x1b\[[0-9;]*m', '', text)
    pad = max(0, (width - len(visible)) // 2)
    return " " * pad + text


def write_cast(filename: str, title: str, events: list) -> None:
    header = {
        "version": 2,
        "width": WIDTH,
        "height": HEIGHT,
        "title": title,
    }
    events.sort(key=lambda e: e[0])
    outpath = OUTPUT_DIR / filename
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(json.dumps(header, ensure_ascii=False) + "\n")
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    dur = events[-1][0]
    print(f"  {filename}: {len(events)} events, {dur:.1f}s")


# ─── SHORT A: The Audit ─────────────────────────────────────────────────────
def gen_short_a() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    # Title card
    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Audit"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # The command
    t = type_cmd(ev, t, "pki cert expires --within 30d /etc/ssl/certs/", speed=0.02)
    t += 0.3

    # Output — the horror
    t = output_line(ev, t, "")
    t = output_line(ev, t, f"  {red('EXPIRED')}   api.prod.internal        " + red("died 47 days ago"))
    t += 0.15
    t = output_line(ev, t, f"  {yellow('WARNING')}   mail.corp.example.com    " + yellow("23 days left"))
    t += 0.15
    t = output_line(ev, t, f"  {green('OK')}        payments.example.com     " + green("312 days left"))
    t += 0.5

    # The punchline
    t = output_line(ev, t, "")
    t = output_line(ev, t, dim("  1 dead. 1 dying. 1 fine."))
    t += 0.2
    t = output_line(ev, t, bold("  guess which one had the monitoring."))
    t += 1.5

    # Smash cut to logo
    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — because openssl deserved it"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-a-audit.cast", "TL;DR: The Audit", ev)


# ─── SHORT B: The Renewal ────────────────────────────────────────────────────
def gen_short_b() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Renewal"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # Speed-run style with step counter
    steps = [
        ("pki cert expires --within 30d", f"{yellow('WARNING')}  23 days left"),
        ("pki key gen ec --curve p384", f"{green('OK')}  P-384 key generated"),
        ("pki csr create --san api.prod.internal", f"{green('OK')}  CSR ready, SANs attached"),
        ("pki csr verify api.prod.csr", f"{green('VALID')}  signature checks out"),
        ("pki diff old.pem new.pem", f"{cyan('3 fields changed')}  algorithm upgraded"),
    ]

    for i, (cmd, result) in enumerate(steps):
        step_label = dim(f"[{i+1}/5]") + " "
        ev.append([round(t, 3), "o", step_label + green("$ ") + cmd + "\r\n"])
        t += 0.25
        ev.append([round(t, 3), "o", "      " + result + "\r\n"])
        t += 0.35

    t += 0.3
    t = output_line(ev, t, "")
    t = output_line(ev, t, bold("  cert renewed. no yaml. no tickets. no drama."))
    t += 1.5

    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — renewal speedrun any%"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-b-renewal.cast", "TL;DR: The Renewal", ev)


# ─── SHORT C: The Migration ──────────────────────────────────────────────────
def gen_short_c() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Migration"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # Before
    ev.append([round(t, 3), "o", dim("  before:") + "\r\n"])
    t += 0.2
    t = type_cmd(ev, t, "pki lint *.pem", speed=0.025)
    t += 0.2
    t = output_line(ev, t, f"  {red('ERROR')}   RSA-2048 — " + red("deprecated, migrate to PQC"))
    t = output_line(ev, t, f"  {yellow('WARN')}    SHA-256 + RSA — " + yellow("upgrade path available"))
    t = output_line(ev, t, f"  {green('OK')}      P-384 — " + green("classical approved"))
    t += 0.5

    # After (one command later)
    ev.append([round(t, 3), "o", "\r\n" + dim("  after: dual-algorithm certs") + "\r\n"])
    t += 0.2
    t = type_cmd(ev, t, "pki lint *.pem", speed=0.025)
    t += 0.2
    t = output_line(ev, t, f"  {green('OK')}  {green('OK')}  {green('OK')}  {green('OK')}  {green('OK')}")
    t += 0.4

    t = output_line(ev, t, "")
    t = output_line(ev, t, bold("  RSA? in 2026?"))
    t = output_line(ev, t, bold("  sir this is a quantum neighborhood."))
    t += 1.5

    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — quantum-safe migration path"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-c-migration.cast", "TL;DR: The Migration", ev)


# ─── SHORT D: The Build ──────────────────────────────────────────────────────
def gen_short_d() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Build"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # Show the TOML (abbreviated)
    ev.append([round(t, 3), "o", dim("  hierarchy.toml:") + "\r\n"])
    t += 0.15
    toml_lines = [
        cyan("  [root]"),
        f"  subject = {dim('\"CN=Root CA\"')}",
        f"  algorithm = {green('\"ML-DSA-87\"')}",
        "",
        cyan("  [issuing]"),
        f"  subject = {dim('\"CN=Issuing CA\"')}",
        f"  algorithm = {green('\"ML-DSA-65\"')}",
        f"  parent = {dim('\"root\"')}",
    ]
    for line in toml_lines:
        t = output_line(ev, t, line, delay=0.06)

    t += 0.3
    t = type_cmd(ev, t, "pki hierarchy build hierarchy.toml", speed=0.02)
    t += 0.2

    # Build output
    t = output_line(ev, t, f"  {green('\u2713')} Root CA .......... {green('ML-DSA-87')}")
    t += 0.15
    t = output_line(ev, t, f"  {green('\u2713')} Issuing CA ....... {green('ML-DSA-65')}")
    t += 0.15
    t = output_line(ev, t, f"  {green('\u2713')} Chain verified ... {green('2/2 valid')}")
    t += 0.4

    t = output_line(ev, t, "")
    t = output_line(ev, t, bold("  entire PKI hierarchy."))
    t = output_line(ev, t, bold("  8 lines of TOML."))
    t = output_line(ev, t, bold("  that's it. that's the post."))
    t += 1.5

    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — PKI as code, literally"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-d-build.cast", "TL;DR: The Build", ev)


# ─── SHORT E: The Handoff ────────────────────────────────────────────────────
def gen_short_e() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Handoff"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # Chat format — the handoff conversation
    t = output_line(ev, t, dim("  new dev:") + "  how do i check if the cert is good?")
    t += 0.4
    t = output_line(ev, t, dim("  senior:"))
    t = type_cmd(ev, t, "pki show --lint prod.pem", speed=0.025)
    t += 0.15
    t = output_line(ev, t, f"  {green('A+')}  TLS server cert, P-384, 312 days, SANs valid")
    t += 0.4

    t = output_line(ev, t, "")
    t = output_line(ev, t, dim("  new dev:") + "  what about DNS pinning?")
    t += 0.3
    t = output_line(ev, t, dim("  senior:"))
    t = type_cmd(ev, t, "pki dane prod.pem", speed=0.025)
    t += 0.15
    t = output_line(ev, t, f"  {cyan('TLSA')}  3 1 1 a4b9c8d7e6... " + dim("(ready to paste)"))
    t += 0.4

    t = output_line(ev, t, "")
    t = output_line(ev, t, dim("  new dev:") + "  ...that's it?")
    t = output_line(ev, t, dim("  senior:") + bold("  that's it."))
    t += 1.5

    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — onboarding in 60 seconds"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-e-handoff.cast", "TL;DR: The Handoff", ev)


# ─── SHORT F: The Vision ─────────────────────────────────────────────────────
def gen_short_f() -> None:
    ev = []
    t = 0.0

    ev.append([t, "o", clear()])
    t = 0.3

    ev.append([t, "o", move(2, 1) + center(dim("TL;DR"))])
    t += 0.2
    ev.append([t, "o", move(3, 1) + center(bold("The Vision"))])
    t += 0.8

    ev.append([t, "o", clear()])
    t += 0.2

    # Timeline
    timeline = [
        ("1996", "0;90",  "MD5 + RSA-512",    "seemed fine at the time"),
        ("2004", "0;90",  "SHA-1 + RSA-1024",  "also seemed fine"),
        ("2017", "0;33",  "SHA-256 + RSA-2048", "fine for now"),
        ("2024", "1;32",  "SHA-384 + P-384",    "actually fine"),
        ("2026", "1;36",  "ML-DSA-87",          "quantum-safe"),
        ("2050", "1;35",  "???",                 "we'll be ready"),
    ]

    for year, clr, algo, note in timeline:
        ev.append([round(t, 3), "o",
                    f"  {c(clr, year)}  {c(clr, algo):<42}  {dim(note)}\r\n"])
        t += 0.35

    t += 0.3
    t = output_line(ev, t, "")
    t = output_line(ev, t, bold("  every era said \"this is fine.\""))
    t += 0.3
    t = output_line(ev, t, bold("  we're the first ones building the exit."))
    t += 1.8

    ev.append([t, "o", clear()])
    t += 0.2
    ev.append([t, "o", move(11, 1) + center(cyan("pki") + dim(" — from MD5 to ML-DSA and beyond"))])
    t += 1.5
    ev.append([t, "o", ""])

    write_cast("short-f-vision.cast", "TL;DR: The Vision", ev)


# ─── MAIN ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Generating TL;DR shorts...")
    gen_short_a()
    gen_short_b()
    gen_short_c()
    gen_short_d()
    gen_short_e()
    gen_short_f()
    print("Done! 6 shorts in docs/demos/")

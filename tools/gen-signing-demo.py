#!/usr/bin/env python3
"""Generate PKI-Signing-Service training demo with QN intro.

30s cinematic QN intro → 90s enterprise code signing training → 30s PKI-Client pitch.
Output: docs/demos/signing-service.cast
"""

import json
import math
import random
import re
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "demos" / "signing-service.cast"

ESC = "\x1b"
W = 120
H = 40


# ─── Helpers ──────────────────────────────────────────────────────────────────

events = []


def add(t: float, text: str) -> None:
    events.append([round(t, 3), "o", text])


def clr() -> str:
    return f"{ESC}[2J{ESC}[H"


def mv(row: int, col: int) -> str:
    return f"{ESC}[{row};{col}H"


def c(code: str, text: str) -> str:
    return f"{ESC}[{code}m{text}{ESC}[0m"


def bold(t: str) -> str:
    return c("1;37", t)


def cyan(t: str) -> str:
    return c("1;36", t)


def dim(t: str) -> str:
    return c("2;37", t)


def green(t: str) -> str:
    return c("1;32", t)


def red(t: str) -> str:
    return c("1;31", t)


def yellow(t: str) -> str:
    return c("1;33", t)


def magenta(t: str) -> str:
    return c("1;35", t)


def hide() -> str:
    return f"{ESC}[?25l"


def vis_len(text: str) -> int:
    return len(re.sub(r'\x1b\[[0-9;]*m', '', text))


def ctr(text: str) -> str:
    pad = max(0, (W - vis_len(text)) // 2)
    return " " * pad + text


# ─── QN Block Art ─────────────────────────────────────────────────────────────

QN_ART = [
    "    ██████████████                ██              ██",
    "  ██              ██              ████            ██",
    " ██                ██             ██  ██          ██",
    "██                  ██            ██   ██         ██",
    "██                  ██            ██    ██        ██",
    "██                  ██            ██     ██       ██",
    "██                  ██            ██      ██      ██",
    "██            ██    ██            ██       ██     ██",
    " ██          ████  ██             ██        ██    ██",
    "  ██              ██              ██         ██   ██",
    "    ██████████████                ██          ██  ██",
    "                ██                ██           █████",
]

QN_GRADIENT = [
    "38;5;21",   # deep blue
    "38;5;27",
    "38;5;33",   # blue
    "38;5;39",
    "38;5;45",   # cyan-blue
    "38;5;44",
    "38;5;43",   # teal
    "38;5;49",
    "38;5;50",   # cyan-green
    "38;5;51",   # bright cyan
    "1;36",      # bold cyan
    "1;37",      # white
]


def get_qn_pixels():
    """Return list of (row_offset, col_offset, char) for all non-space pixels."""
    pixels = []
    for r, line in enumerate(QN_ART):
        for ci in range(0, len(line), 2):
            pair = line[ci:ci + 2]
            if pair.strip():
                pixels.append((r, ci, pair))
    return pixels


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — QN INTRO (0–30s)
# ═══════════════════════════════════════════════════════════════════════════════

def phase_intro() -> float:
    t = 0.0

    add(t, hide() + clr())
    t = 1.5

    # ── Noise fill then carve QN from it (0.8–8s) ────────────────────────────
    # Fill screen with random block chars
    random.seed(99)
    noise_chars = "█▓▒░▒▓█░▒"
    noise_colors = ["38;5;17", "38;5;18", "38;5;19", "38;5;23", "38;5;24"]

    frame = ""
    noise_grid = {}
    for row in range(1, H + 1):
        for col in range(1, W + 1, 2):
            ch = random.choice(noise_chars)
            clr_code = random.choice(noise_colors)
            frame += mv(row, col) + c(clr_code, ch)
            noise_grid[(row, col)] = True
    add(t, frame)
    t += 1.5

    # Figure out which screen positions belong to QN
    qn_width = max(len(r) for r in QN_ART)
    qn_start_col = (W - qn_width) // 2
    qn_start_row = (H - len(QN_ART)) // 2 - 4

    qn_positions = set()
    for r, line in enumerate(QN_ART):
        for ci in range(0, len(line), 2):
            pair = line[ci:ci + 2]
            if pair.strip():
                screen_row = qn_start_row + r
                screen_col = qn_start_col + ci
                qn_positions.add((screen_row, screen_col))

    # Progressive reveal: clear noise in expanding rings from center,
    # but KEEP the QN pixels and brighten them
    center_row = qn_start_row + len(QN_ART) // 2
    center_col = qn_start_col + qn_width // 2

    max_dist = math.sqrt((H / 2) ** 2 + (W / 2) ** 2)
    num_rings = 16
    ring_dt = 0.4

    for ring in range(num_rings):
        threshold = (ring + 1) / num_rings * max_dist
        frame = ""
        for row in range(1, H + 1):
            for col in range(1, W + 1, 2):
                dist = math.sqrt((row - center_row) ** 2 + ((col - center_col) / 2) ** 2)
                if dist <= threshold:
                    if (row, col) in qn_positions:
                        # Brighten QN pixel
                        art_row = row - qn_start_row
                        grad = QN_GRADIENT[min(art_row, len(QN_GRADIENT) - 1)]
                        frame += mv(row, col) + c(grad, "██")
                    else:
                        # Clear non-QN pixel
                        frame += mv(row, col) + "  "
        add(t, frame)
        t += ring_dt

    t += 0.3

    # ── QN pulse ───────────────────────────────────────────────────────────────
    pulse_colors = ["1;36", "1;37", "1;35", "1;37", "1;36", "1;37", "1;36"]
    for pulse in pulse_colors:
        frame = ""
        for r, line in enumerate(QN_ART):
            for ci in range(0, len(line), 2):
                pair = line[ci:ci + 2]
                if pair.strip():
                    frame += mv(qn_start_row + r, qn_start_col + ci) + c(pulse, "██")
        add(t, frame)
        t += 0.4

    # Restore gradient
    frame = ""
    for r, line in enumerate(QN_ART):
        grad = QN_GRADIENT[min(r, len(QN_GRADIENT) - 1)]
        for ci in range(0, len(line), 2):
            pair = line[ci:ci + 2]
            if pair.strip():
                frame += mv(qn_start_row + r, qn_start_col + ci) + c(grad, "██")
    add(t, frame)
    t += 0.5

    # ── "QUANTUM NEXUM" reveal (11–15s) ──────────────────────────────────────
    qn_text = "Q U A N T U M     N E X U M"
    text_row = qn_start_row + len(QN_ART) + 2
    text_col = (W - len(qn_text)) // 2

    for i, ch in enumerate(qn_text):
        if ch != ' ':
            add(t, mv(text_row, text_col + i) + c("1;37", ch))
            t += 0.08
    t += 1.2

    # ── Building blocks + code cube (15–24s) ─────────────────────────────────
    # Isometric cube builds from bottom
    cube_row = text_row + 3
    cube_col = (W - 36) // 2

    cube_frames = [
        # Frame 1: foundation
        [
            "      ╔══════════════════════════╗",
        ],
        # Frame 2: walls start
        [
            "      ║                          ║",
            "      ╔══════════════════════════╗",
        ],
        # Frame 3: more wall
        [
            "      ║                          ║",
            "      ║                          ║",
            "      ╔══════════════════════════╗",
        ],
        # Frame 4: top + depth
        [
            "     ╱╔══════════════════════════╗",
            "    ╱ ║                          ║╱",
            "   ╔══════════════════════════════╗",
            "   ║                              ║",
            "   ║                              ║",
            "   ╚══════════════════════════════╝",
        ],
    ]

    for frame_lines in cube_frames:
        f = ""
        for i, line in enumerate(frame_lines):
            f += mv(cube_row + 6 - len(frame_lines) + i, cube_col) + c("38;5;39", line)
        add(t, f)
        t += 0.5

    # Code evolves on the cube face
    code_sequences = [
        ("   sign(hash(file))              ", "1;32"),
        ("   verify(signature, pubkey)     ", "1;36"),
        ("   audit.log(who, what, when)    ", "1;33"),
        ("   timestamp(rfc3161_server)     ", "1;35"),
        ("   enforce(batch_limit: 10)      ", "1;31"),
    ]

    face_row = cube_row + 3
    for code_text, code_clr in code_sequences:
        add(t, mv(face_row, cube_col + 4) + c(code_clr, code_text))
        t += 0.6
        add(t, mv(face_row + 1, cube_col + 4) + c("2;37", code_text.replace("(", " ← ").split("←")[0] + "                    "))
        t += 0.5

    t += 1.0

    # ── "presents" ───────────────────────────────────────────────────────────
    add(t, mv(cube_row + 8, 1) + ctr(dim("p r e s e n t s")))
    t += 3.0

    # ── Transition ─────────────────────────────────────────────────────────────
    add(t, clr())
    t += 1.0

    return t


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — TRAINING MODULE (30–120s)
# ═══════════════════════════════════════════════════════════════════════════════

def section_box(row: int, col: int, width: int, title: str) -> str:
    top = "╔" + "═" * (width - 2) + "╗"
    mid = "║ " + title.center(width - 4) + " ║"
    bot = "╚" + "═" * (width - 2) + "╝"
    return (
        mv(row, col) + c("1;36", top) +
        mv(row + 1, col) + c("1;36", mid) +
        mv(row + 2, col) + c("1;36", bot)
    )


def phase_training(t: float) -> float:
    # ── Title card ────────────────────────────────────────────────────────────
    add(t, mv(15, 1) + ctr(bold("Enterprise Code Signing")))
    t += 0.5
    add(t, mv(17, 1) + ctr(c("0;37", "Best Practices Training Module")))
    t += 0.5
    add(t, mv(19, 1) + ctr(dim("PKI-Signing-Service  ·  QuantumNexum")))
    t += 3.5
    add(t, clr())
    t += 0.3

    # ── Section 1: Batch Signing Limits ──────────────────────────────────────
    add(t, section_box(2, 4, 112, "1  BATCH SIGNING LIMITS"))
    t += 0.6

    bullets_1 = [
        green("✓") + "  Maximum " + bold("10 files") + " per signing request",
        green("✓") + "  Prevents runaway automation from mass-signing",
        green("✓") + "  Each batch gets a unique " + cyan("transaction ID"),
        green("✓") + "  Partial success OK — failed files don't block the batch",
        red("✗") + "  " + red("Never") + " sign unbounded queues — enforce at the API",
    ]

    for i, b in enumerate(bullets_1):
        add(t, mv(6 + i * 2, 8) + b)
        t += 1.2

    # API example
    t += 0.5
    add(t, mv(17, 8) + dim("Example request:"))
    t += 0.3
    api_lines = [
        cyan("POST") + " /api/v1/sign/batch",
        "  {",
        '    "files":     ' + green('["app.exe", "lib.dll", "drv.sys"]') + ",",
        '    "policy":    ' + green('"production"') + ",",
        '    "signer_id": ' + green('"team-platform-01"') + ",",
        '    "timestamp": ' + yellow("true"),
        "  }",
    ]
    for i, line in enumerate(api_lines):
        add(t, mv(18 + i, 10) + line)
        t += 0.25

    t += 0.3
    add(t, mv(26, 8) + yellow("⚠") + dim("  Server rejects if files.len() > 10"))
    t += 3.0
    add(t, clr())
    t += 0.3

    # ── Section 2: Signing Types ─────────────────────────────────────────────
    add(t, section_box(2, 4, 112, "2  SIGNING TYPES"))
    t += 0.6

    add(t, mv(6, 8) + bold("Arbitrary File Signing") + dim("  (hash-based, any file)"))
    t += 0.5
    arb = [
        green("✓") + "  Configs, firmware, containers, scripts, images",
        green("✓") + "  " + cyan("SHA-384") + " digest → sign the hash, not the file",
        green("✓") + "  Detached signature: " + dim("file.bin") + " + " + cyan("file.bin.sig"),
    ]
    for i, b in enumerate(arb):
        add(t, mv(8 + i * 2, 10) + b)
        t += 1.0

    t += 1.2
    add(t, mv(15, 8) + bold("PE / Authenticode") + dim("  (Windows executables)"))
    t += 0.5
    pe = [
        green("✓") + "  .exe  .dll  .sys  .msi  .cab  .appx  .ps1",
        green("✓") + "  Signature embeds " + cyan("inside the PE header"),
        green("✓") + "  Dual-sign: SHA-256 + SHA-384 for backward compat",
        yellow("⚠") + "  " + bold("Timestamping required") + " — certs expire, timestamps don't",
    ]
    for i, b in enumerate(pe):
        add(t, mv(17 + i * 2, 10) + b)
        t += 1.0

    t += 0.8
    add(t, mv(26, 8) + dim("Verify offline:  ") + green("$ ") + cyan("pki verify") + " app.exe --authenticode")
    t += 3.0
    add(t, clr())
    t += 0.3

    # ── Section 3: Service Responsibility ─────────────────────────────────────
    add(t, section_box(2, 4, 112, "3  SERVICE RESPONSIBILITY"))
    t += 0.6

    responsibilities = [
        ("Key Protection",
         "HSM-backed (FIPS 140-3 Level 3). Never exportable.",
         "Keys never leave hardware. Period."),
        ("Approval Workflow",
         "Production signing requires 2-person approval.",
         "No single engineer can sign + deploy."),
        ("Audit Trail",
         "Every operation → immutable, queryable log.",
         "Who signed what, when, which key, which hash."),
        ("Certificate Lifecycle",
         "Signing certs rotate annually. Revocation tested.",
         "Old certs on CRL within 24h of rotation."),
        ("Scope Isolation",
         "Each team gets its own signing cert + policy.",
         "Platform team can't sign mobile binaries."),
    ]

    row = 6
    for title, line1, line2 in responsibilities:
        add(t, mv(row, 8) + cyan("▸ ") + bold(title))
        t += 0.5
        add(t, mv(row + 1, 12) + c("0;37", line1))
        t += 0.4
        add(t, mv(row + 2, 12) + dim(line2))
        t += 1.0
        row += 4

    t += 3.0
    add(t, clr())
    t += 0.3

    # ── Section 4: Preflight Checklist ────────────────────────────────────────
    add(t, section_box(2, 4, 112, "4  BEFORE YOU SHIP — CHECKLIST"))
    t += 0.6

    checks = [
        "Signing key is HSM-backed, not a file on disk",
        "Batch limit enforced at API level (max 10)",
        "PE binaries dual-signed SHA-256 + SHA-384",
        "RFC 3161 timestamp authority configured",
        "Audit log captures: who, what, when, hash",
        "Signing cert scoped to team + environment",
        "Revocation plan documented and tested",
        "Post-quantum migration path identified",
    ]

    for i, text in enumerate(checks):
        add(t, mv(6 + i * 2, 8) + green("☑") + "  " + text)
        t += 0.8

    t += 1.0
    add(t, mv(24, 8) + bold("All green?  ") + green("Ship it."))
    t += 3.5
    add(t, clr())
    t += 0.5

    return t


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — PKI-CLIENT PITCH (120–150s)
# ═══════════════════════════════════════════════════════════════════════════════

def phase_pitch(t: float) -> float:
    # Transition
    add(t, mv(18, 1) + ctr(dim("Built for exactly this.")))
    t += 3.0
    add(t, clr())
    t += 0.3

    # Product header
    add(t, mv(4, 1) + ctr(cyan("PKI-Signing-Service") + bold("  +  ") + cyan("PKI-Client")))
    t += 0.4
    add(t, mv(6, 1) + ctr(dim("Enterprise code signing that enforces every practice above.")))
    t += 1.0

    # Command showcase
    cmds = [
        (green("$ ") + cyan("pki sign") + " app.exe --policy production",
         "Sign PE binary with team-scoped production policy"),
        (green("$ ") + cyan("pki sign") + " --batch manifest.txt --limit 10",
         "Batch sign up to 10 files from a manifest"),
        (green("$ ") + cyan("pki verify") + " app.exe --authenticode --timestamp",
         "Verify Authenticode signature + timestamp offline"),
        (green("$ ") + cyan("pki audit") + " --signer team-platform-01 --last 7d",
         "Query audit trail — who signed what this week"),
        (green("$ ") + cyan("pki hierarchy build") + " signing-ca.toml",
         "Stand up your signing CA hierarchy from TOML"),
    ]

    row = 9
    for cmd, desc in cmds:
        add(t, mv(row, 8) + cmd)
        t += 0.5
        add(t, mv(row + 1, 10) + dim(desc))
        t += 1.0
        row += 3

    t += 3.0
    add(t, clr())
    t += 0.3

    # ── Closing: Suite overview ──────────────────────────────────────────────
    add(t, mv(12, 1) + ctr(bold("The QuantumNexum PKI Suite")))
    t += 0.5
    add(t, mv(14, 1) + ctr(dim("Three tools.  One mission.  Quantum-safe infrastructure.")))
    t += 1.0

    suite = [
        ("PKI-Client",          "Certificate lifecycle CLI — inspect, lint, diff, probe, enroll"),
        ("PKI-Signing-Service", "Enterprise code signing — batch limits, HSM, audit, Authenticode"),
        ("PKI-CA-Engine",       "Certificate Authority as code — declarative TOML, automated issuance"),
    ]

    for i, (name, desc) in enumerate(suite):
        add(t, mv(17 + i * 2, 10) + cyan(f"{name:<24}") + dim(desc))
        t += 0.6

    t += 1.0
    add(t, mv(25, 1) + ctr(c("0;34", "github.com/rayketcham-lab")))
    t += 0.4
    add(t, mv(26, 1) + ctr(dim("Star  ·  Fork  ·  Contribute")))
    t += 5.0
    add(t, "")

    return t


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Generating PKI-Signing-Service training demo...")

    t = phase_intro()
    print(f"  Intro ends at {t:.1f}s")

    t = phase_training(t)
    print(f"  Training ends at {t:.1f}s")

    t = phase_pitch(t)
    print(f"  Pitch ends at {t:.1f}s")

    header = {
        "version": 2,
        "width": W,
        "height": H,
        "title": "Enterprise Code Signing — Best Practices | QuantumNexum",
    }

    events.sort(key=lambda e: e[0])

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(json.dumps(header, ensure_ascii=False) + "\n")
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"\nWritten {len(events)} events to {OUTPUT}")
    print(f"Total duration: {events[-1][0]:.1f}s")

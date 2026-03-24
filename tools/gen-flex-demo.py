#!/usr/bin/env python3
"""Generator for pki-flex-demo.cast — 3-minute cinematic PKI demo."""

import json
import random

ESC = "\033"
OUTPUT_PATH = "/opt/vmdata/system-opt/pki-client/docs/demos/pki-flex-demo.cast"

# ANSI helpers
def c(code: str) -> str:
    return f"{ESC}[{code}m"

RESET = c("0")
BOLD_YELLOW = c("1;33")
BOLD_CYAN = c("1;36")
BOLD_WHITE = c("1;37")
DIM = c("2")
BOLD_GREEN = c("1;32")
YELLOW = c("33")
CYAN = c("36")
RED = c("31")
BOLD_RED = c("1;31")
BOLD_MAGENTA = c("1;35")
SPARKLE_COLOR = c("1;93")

PKI_PROMPT = f"{c('1;36')}pki> {RESET}"

# Block letter definitions (6 rows each)
LETTER_P = [
    "██████╗ ",
    "██╔══██╗",
    "██████╔╝",
    "██╔═══╝ ",
    "██║     ",
    "╚═╝     ",
]

LETTER_K = [
    "██╗  ██╗",
    "██║ ██╔╝",
    "█████╔╝ ",
    "██╔═██╗ ",
    "██║  ██╗",
    "╚═╝  ╚═╝",
]

LETTER_I = [
    "██╗",
    "██║",
    "██║",
    "██║",
    "██║",
    "╚═╝",
]

events = []
_time = 0.0


def t_next(delta: float) -> float:
    global _time
    _time += delta
    return round(_time, 4)


def emit(ts: float, data: str) -> None:
    events.append([round(ts, 4), "o", data])


def emit_at(ts: float, data: str) -> None:
    """Emit at absolute timestamp."""
    emit(ts, data)


def ensure_time(target: float) -> None:
    """Advance internal clock to target if needed."""
    global _time
    if _time < target:
        _time = target


def move_to(row: int, col: int) -> str:
    """Return ANSI cursor-position escape (1-indexed)."""
    return f"{ESC}[{row};{col}H"


def type_string(text: str, start_ts: float, char_delay_min: float = 0.035,
                char_delay_max: float = 0.065) -> float:
    """Emit text character by character. Returns time after last char."""
    ts = start_ts
    for ch in text:
        emit_at(ts, ch)
        delay = random.uniform(char_delay_min, char_delay_max)
        ts = round(ts + delay, 4)
    return ts


def emit_line_by_line(lines: list[str], start_ts: float, line_delay: float = 0.018) -> float:
    """Emit lines one at a time. Returns time after last line."""
    ts = start_ts
    for line in lines:
        emit_at(ts, line + "\r\n")
        ts = round(ts + line_delay, 4)
    return ts


def center_text(text: str, width: int = 120) -> str:
    """Return text padded so it appears centered (ignores ANSI codes for length)."""
    import re
    plain = re.sub(r'\033\[[0-9;]*m', '', text)
    pad = max(0, (width - len(plain)) // 2)
    return " " * pad + text


# ─────────────────────────────────────────────
# ACT 1: FLASHY INTRO (0-12s)
# ─────────────────────────────────────────────

def build_act1() -> None:
    # t=0.0: clear screen
    emit_at(0.0, f"{ESC}[2J{ESC}[H")

    # Letter rendering helper
    # P at row 14, col 47; K at row 14, col 47+8+4=59; I at row 14, col 59+8+4=71
    # (1-indexed terminal coords)
    COL_P = 47
    COL_K = 59
    COL_I = 71
    ROW_START = 14

    def render_letter(letter_rows: list[str], row: int, col: int,
                      color: str, ts: float) -> float:
        for i, row_text in enumerate(letter_rows):
            emit_at(ts, move_to(row + i, col) + color + row_text + RESET)
            ts = round(ts + 0.02, 4)
        return ts

    def sparkles_around(letter_col: int, letter_width: int, ts: float) -> None:
        chars = ["⚡", "·", "*", "⚡", "·"]
        # Row 13 (above) and row 20 (below)
        positions_above = [
            (13, letter_col - 2),
            (13, letter_col + letter_width // 2),
            (13, letter_col + letter_width + 1),
        ]
        positions_below = [
            (20, letter_col - 1),
            (20, letter_col + letter_width // 2 - 1),
            (20, letter_col + letter_width + 2),
        ]
        for r, c_pos in positions_above + positions_below:
            ch = random.choice(chars)
            emit_at(ts, move_to(r, c_pos) + SPARKLE_COLOR + ch + RESET)

    # t=1.0: P appears (yellow) + sparkles
    ts = 1.0
    ts = render_letter(LETTER_P, ROW_START, COL_P, BOLD_YELLOW, ts)
    sparkles_around(COL_P, 8, 1.0)

    # t=1.5: P recolors to cyan
    ts = 1.5
    ts = render_letter(LETTER_P, ROW_START, COL_P, BOLD_CYAN, ts)

    # t=2.0: K appears (yellow) + sparkles
    ts = 2.0
    ts = render_letter(LETTER_K, ROW_START, COL_K, BOLD_YELLOW, ts)
    sparkles_around(COL_K, 8, 2.0)

    # t=2.5: K recolors to cyan
    ts = 2.5
    ts = render_letter(LETTER_K, ROW_START, COL_K, BOLD_CYAN, ts)

    # t=3.0: I appears (yellow) + sparkles
    ts = 3.0
    ts = render_letter(LETTER_I, ROW_START, COL_I, BOLD_YELLOW, ts)
    sparkles_around(COL_I, 3, 3.0)

    # t=3.5: I recolors to cyan
    ts = 3.5
    ts = render_letter(LETTER_I, ROW_START, COL_I, BOLD_CYAN, ts)

    # t=4.5: "C L I E N T" letter by letter, row 21, centered
    # "C L I E N T" = 11 chars. Center at col ~55
    client_word = "C L I E N T"
    plain_len = len(client_word)
    col_start = (120 - plain_len) // 2 + 1
    ts = 4.5
    for i, ch in enumerate(client_word):
        emit_at(ts, move_to(21, col_start + i) + BOLD_WHITE + ch + RESET)
        ts = round(ts + 0.15, 4)

    # t=6.0: hold (nothing to emit, time passes naturally)

    # t=7.0: clear screen, show "QuantumNexum presents" card
    ts = 7.0
    emit_at(ts, f"{ESC}[2J{ESC}[H")

    line1 = f"{DIM}QuantumNexum presents{RESET}"
    line2 = f"{BOLD_CYAN}PKI Client v0.6.9{RESET}"
    line3 = f"{DIM}── Enterprise PKI Operations ──{RESET}"

    for line_idx, line in enumerate([line1, line2, line3]):
        import re
        plain = re.sub(r'\033\[[0-9;]*m', '', line)
        pad = (120 - len(plain)) // 2
        row = 18 + line_idx * 2
        emit_at(round(ts + 0.1 * line_idx, 4),
                move_to(row, pad) + line)

    # t=11.5: clear screen
    emit_at(11.5, f"{ESC}[2J{ESC}[H")


# ─────────────────────────────────────────────
# ACT 2: SSH + PKI SHELL ENTRY (12-25s)
# ─────────────────────────────────────────────

def build_act2() -> None:
    # t=12.0: bash prompt + ssh command
    ts = 12.0
    emit_at(ts, f"\r\n{c('1;32')}qnadmin@workstation:~$ {RESET}")
    ts = round(ts + 0.3, 4)
    ts = type_string("ssh qnadmin@secure.quantumnexum.com", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    # t=14.5: connection banner
    ts = 14.5
    banner_lines = [
        "",
        f"   {c('0;36')}╔══════════════════════════════════════════════════════╗{RESET}",
        f"   {c('0;36')}║{RESET}  {BOLD_WHITE}QuantumNexum Secure Terminal{RESET}                         {c('0;36')}║{RESET}",
        f"   {c('0;36')}║{RESET}  {DIM}Authorized personnel only{RESET}                            {c('0;36')}║{RESET}",
        f"   {c('0;36')}╚══════════════════════════════════════════════════════╝{RESET}",
        "",
        "   Last login: Mon Mar 24 01:19:23 2026 from 192.0.2.10",
        "",
    ]
    ts = emit_line_by_line(banner_lines, ts, 0.12)

    # t=17.0: new bash prompt, type `pki`
    ts = 17.0
    emit_at(ts, f"{c('1;32')}qnadmin@qn-secure:~$ {RESET}")
    ts = round(ts + 0.3, 4)
    ts = type_string("pki", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    # t=18.0: PKI banner
    ts = 18.0
    banner = [
        f"{BOLD_CYAN}",
        f"  ██████╗ ██╗  ██╗██╗",
        f"  ██╔══██╗██║ ██╔╝██║",
        f"  ██████╔╝█████╔╝ ██║",
        f"  ██╔═══╝ ██╔═██╗ ██║",
        f"  ██║     ██║  ██╗██║",
        f"  ╚═╝     ╚═╝  ╚═╝╚═╝",
        f"{RESET}",
        f"  {BOLD_WHITE}PKI - Modern PKI Operations Tool{RESET}",
        "",
        f"  {DIM}Type help for commands, exit to quit{RESET}",
        "",
    ]
    ts = emit_line_by_line(banner, ts, 0.04)

    # t=20.0: pki> prompt
    ts = 20.0
    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 3: HELP + VERSION (25-35s)
# ─────────────────────────────────────────────

def build_act3() -> None:
    ts = 25.0

    # Section breaker
    breaker = f"{DIM}────────────────────────── {BOLD_CYAN}① Getting Started{RESET}{DIM} ──────────────────────────{RESET}"
    emit_at(ts, f"\r\n{breaker}\r\n\r\n")

    # t=26.0: type `help`
    ts = 26.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("help", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    # Help output
    ts = round(ts + 0.05, 4)
    help_lines = [
        f"{BOLD_WHITE}PKI Client - Available Commands{RESET}",
        "",
        f"{BOLD_CYAN}Certificate Operations:{RESET}",
        f"  {BOLD_WHITE}show{RESET}          {DIM}Inspect and display certificate details{RESET}",
        f"  {BOLD_WHITE}verify{RESET}        {DIM}Verify certificate chain and validity{RESET}",
        f"  {BOLD_WHITE}lint{RESET}          {DIM}Lint certificate against RFC/CA-Browser Forum profiles{RESET}",
        f"  {BOLD_WHITE}convert{RESET}       {DIM}Convert between PEM, DER, PFX formats{RESET}",
        "",
        f"{BOLD_CYAN}Key Management:{RESET}",
        f"  {BOLD_WHITE}key gen{RESET}       {DIM}Generate RSA, EC, Ed25519, or PQC keys{RESET}",
        f"  {BOLD_WHITE}key show{RESET}      {DIM}Inspect a private or public key{RESET}",
        f"  {BOLD_WHITE}csr create{RESET}    {DIM}Create a certificate signing request{RESET}",
        f"  {BOLD_WHITE}csr show{RESET}      {DIM}Inspect a CSR{RESET}",
        "",
        f"{BOLD_CYAN}Hierarchy & Enrollment:{RESET}",
        f"  {BOLD_WHITE}pki build{RESET}     {DIM}Build a PKI hierarchy from TOML config{RESET}",
        f"  {BOLD_WHITE}pki preview{RESET}   {DIM}Preview a PKI hierarchy config without building{RESET}",
        f"  {BOLD_WHITE}acme{RESET}          {DIM}ACME protocol operations (RFC 8555){RESET}",
        f"  {BOLD_WHITE}est{RESET}           {DIM}EST enrollment (RFC 7030){RESET}",
        f"  {BOLD_WHITE}scep{RESET}          {DIM}SCEP enrollment (RFC 8894){RESET}",
        "",
        f"{BOLD_CYAN}TLS & Network:{RESET}",
        f"  {BOLD_WHITE}probe{RESET}         {DIM}Probe a TLS endpoint{RESET}",
        f"  {BOLD_WHITE}fetch{RESET}         {DIM}Fetch and inspect a remote certificate{RESET}",
        "",
        f"{BOLD_CYAN}Utility:{RESET}",
        f"  {BOLD_WHITE}version{RESET}       {DIM}Show version and build info{RESET}",
        f"  {BOLD_WHITE}help{RESET}          {DIM}Show this help{RESET}",
        f"  {BOLD_WHITE}exit{RESET}          {DIM}Exit the shell{RESET}",
        "",
    ]
    ts = emit_line_by_line(help_lines, ts, 0.018)

    # Back to prompt
    emit_at(ts, PKI_PROMPT)

    # t=30.0: type `version`
    ts = 30.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("version", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.05, 4)
    version_lines = [
        f"pki 0.6.9 (built 2026-03-24)",
        f"  Features: pqc, fips",
        f"  Algorithms: RSA, EC P-256/P-384, Ed25519, ML-DSA-44/65/87, SLH-DSA",
        f"  Protocols: ACME (RFC 8555), EST (RFC 7030), SCEP (RFC 8894)",
        f"  License: Apache-2.0",
        "",
    ]
    ts = emit_line_by_line(version_lines, ts, 0.04)

    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 4: INSPECT ENTERPRISE CERT (35-80s)
# ─────────────────────────────────────────────

def build_act4() -> None:
    ts = 35.0

    breaker = f"{DIM}────────────────────── {BOLD_CYAN}② Enterprise Certificate Inspection{RESET}{DIM} ──────────────────────{RESET}"
    emit_at(ts, f"\r\n{breaker}\r\n\r\n")

    ts = 36.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("show /etc/pki/certs/alice.engineer.pem", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.1, 4)

    cert_lines = [
        f"Certificate Summary:",
        f"    Type:           End Entity (Unknown)",
        f"    Grade:          {BOLD_GREEN}A{RESET}    Wildcard: No",
        f"    Subject:        {BOLD_WHITE}Alice Engineer + uid=A00100042{RESET}",
        f"    Issuer:         {YELLOW}DC=com, DC=acme, O=CAs, OU=Class3-G3, CN=Acme Corp Medium Assurance CA{RESET} {CYAN}(Acme Corp){RESET}",
        f"    Purpose:        Email/S-MIME",
        "",
        f"    Key:            RSA 2048-bit {YELLOW}OK{RESET}",
        f"    Validity:       1095 days (3 years) (1054 days remaining)",
        f"    Lifetime:       [{BOLD_GREEN}█{RESET}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 3.7%",
        "",
        f"    Status:         {RED}✗ CT{RESET}  {BOLD_GREEN}✓ OCSP{RESET}  {BOLD_GREEN}✓ CRL{RESET}  SANs: 1",
        "",
        f"Certificate:",
        f"    Data:",
        f"        Version: 3 (0x2)",
        f"        Serial Number:",
        f"            5F8A6C30 (0x5f8a6c30)",
        f"        Signature Algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)",
        f"        Issuer: DC=com, DC=acme, O=CAs, OU=Class3-G3, CN=Acme Corp Medium Assurance CA",
        f"        Validity:",
        f"            Not Before: Feb 11 18:22:58 2026 UTC",
        f"            Not After : Feb 10 18:52:16 2029 UTC {CYAN}1054 days{RESET}",
        f"            Lifetime : [{BOLD_GREEN}█{RESET}░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 3.7%",
        f"        Subject: DC=com, DC=acme, O=CAs, OU=Class3-G3, OU=Users, CN=Alice Engineer + uid=A00100042",
        f"        Subject Public Key Info:",
        f"            Algorithm: RSA (2048 bit) {YELLOW}OK{RESET} (1.2.840.113549.1.1.1)",
        f"            Modulus:",
        f"                3082010a0282010100a48d36a798c9895796441c6822e818c0ced20c17d26c7c",
        f"                7610e1126130205bf18d6c6d19de7935705545d2475a5951da42052ff1587492",
        f"            Exponent: 65537 (0x10001)",
        f"        X509v3 Extensions:",
        f"            X509v3 Key Usage (2.5.29.15): {RED}(critical){RESET}",
        f"                Key Encipherment",
        f"            X509v3 Extended Key Usage (2.5.29.37):",
        f"                E-mail Protection",
        f"            X509v3 Subject Alternative Name (2.5.29.17):",
        f"                email:alice.engineer@example.com",
        f"            X509v3 Subject Key Identifier (2.5.29.14):",
        f"                d41f7ad64ca35879789229be240959a7c00036d8",
        f"            X509v3 Authority Key Identifier (2.5.29.35):",
        f"                keyid:97696dfd7e2be5a7f262bd75ea961ee00cc0a946",
        f"            Authority Information Access (1.3.6.1.5.5.7.1.1):",
        f"                OCSP (1.3.6.1.5.5.7.48.1) - URI:{CYAN}http://pki.acme.example.com/ocsp/{RESET}",
        f"                CA Issuers (1.3.6.1.5.5.7.48.2) - URI:{CYAN}http://pki.acme.example.com/G3/aia/Class3-G3_01.p7c{RESET}",
        f"            X509v3 CRL Distribution Points (2.5.29.31):",
        f"                URI:{CYAN}http://pki.acme.example.com/G3/CRLs/Class3-G3_Full.crl{RESET}",
        f"            X509v3 Certificate Policies (2.5.29.32):",
        f"                Policy: 1.3.6.1.4.1.26769.10.1.13",
        f"    {CYAN}Signature Algorithm{RESET}: sha256WithRSAEncryption",
        f"    {CYAN}Signature Value{RESET}:",
        f"        {DIM}07:bc:27:10:87:4c:97:ec:75:ae:f9:8f:1d:a5:e3:e6:8a:e7{RESET}",
        f"        {DIM}aa:66:7f:55:0d:42:76:e7:63:4f:b0:01:b9:7a:3d:33:6e:59{RESET}",
        f"        {DIM}f4:2b:cf:5f:65:1e:14:de:0f:b0:63:92:85:d4:5a:0f:3a:50{RESET}",
        f"        {DIM}a4:02:e8:5f:aa:21:c1:58:3e:e6:6e:2c:28:8d:09:10:0c:d5{RESET}",
        f"        {DIM}4f:f3:1c:ef:6a:1d:c9:b9:67:14:df:54:35:3c:12:1e:20:5b{RESET}",
        f"        {DIM}98:17:33:55:19:b6:b3:f8:d8:a0:9e:f5:58:a1:63:37:cf:2a{RESET}",
        f"        {DIM}60:1f:89:21:bc:92:7a:39:3f:ce:72:f5:d0:fa:e4:68:47:af{RESET}",
        f"        {DIM}99:ae:00:bc:a4:3f:47:75:ab:8e:eb:3d:ff:58:c4:8b:d8:cd{RESET}",
        f"        {DIM}7b:61:43:c5:0c:5e:c7:93:19:73:6d:5a:37:4b:d7:a4:e0:6f{RESET}",
        f"        {DIM}b3:57:79:69:b4:e0:a5:77:d1:35:44:13:f9:db:6a:21:38:ad{RESET}",
        "",
        f"{BOLD_CYAN}Fingerprints{RESET}:",
        f"    SHA-256:        {CYAN}4863eeb183a17520bf7c1938bbfa681e8ca38296910148bb8a37d94e9d3eff1f{RESET}",
        f"    SHA-1:          {DIM}1a0b7bc0ad43672f7dd7bada5790ca4f92f368ee{RESET}",
        f"    SPKI Pin:       {BOLD_GREEN}A4ZCVO800391Xqi3I4nx+IrIkNkuB79ZFVPdPw4meTE={RESET}",
        "",
        f"{BOLD_CYAN}PEM{RESET}:",
        f"{DIM}-----BEGIN CERTIFICATE-----{RESET}",
        f"{DIM}MIIFqjCCBBKgAwIBAgIEX4psMDANBgkqhkiG9w0BAQsFADCBgDETMBEGCgmSJomT{RESET}",
        f"{DIM}8ixkARkWA2NvbTETMBEGCgmSJomT8ixkARkWA3J0eDEMMAoGA1UEChMDQ0FzMRIw{RESET}",
        f"{DIM}EAYDVQQLEwlDbGFzczMtRzMxMjAwBgNVBAMTKVJheXRoZW9uIFRlY2hub2xvZ2ll{RESET}",
        f"{DIM}cyBNZWRpdW0gQXNzdXJhbmNlIENBMB4XDTI2MDIxMTE4MjI1OFoXDTI5MDIxMDE4{RESET}",
        f"{DIM}NTIxNlowgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xEzARBgoJkiaJk/IsZAEZFgNy{RESET}",
        f"{DIM}...{RESET}",
        f"{DIM}6xVS+v/tW+v0ngoGCbg={RESET}",
        f"{DIM}-----END CERTIFICATE-----{RESET}",
        "",
        "",
        f"Certificate Chain:",
        "",
        f"    {DIM}Organizational (inferred)                               AIA Path (fetched){RESET}",
        f"    {DIM}──────────────────────────────────────────────────      ──────────────────────────────────────────────────{RESET}",
        "",
        f"    Acme Root CA                                             Federal Bridge PCA G3",
        f"        {DIM}(inferred){RESET}                                              {CYAN}129 days{RESET} | RSA 2048",
        f"        │                                                       │",
        f"        └─► Class3-G3 CA                                        └─► CertiPath Bridge CA - G3 {YELLOW}(bridge){RESET}",
        f"            {DIM}(inferred){RESET}                                              {CYAN}263 days{RESET} | RSA 4096",
        f"            │                                                       │",
        f"            └─► Acme Corp Medium Assurance CA            └─► Acme Corp Medium Assurance CA",
        f"                {DIM}(inferred){RESET}                                              {CYAN}129 days{RESET} | RSA 3072",
        f"                │                                                       │",
        f"                └─► Alice Engineer + uid=A00100042                     └─► Alice Engineer + uid=A00100042 {BOLD_CYAN}← this cert{RESET}",
        f"                    {CYAN}1054 days{RESET} | RSA 2048                                    {CYAN}1054 days{RESET} | RSA 2048",
        "",
        f"    {YELLOW}⚠ AIA path traverses bridge/cross-certification{RESET}",
        "",
    ]
    ts = emit_line_by_line(cert_lines, ts, 0.018)

    # Hold 3s after chain output — just emit prompt at ts+3
    ts = round(ts + 3.0, 4)
    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 5: KEYGEN + CSR (80-110s)
# ─────────────────────────────────────────────

def build_act5() -> None:
    ts = 80.0

    breaker = f"{DIM}────────────────────── {BOLD_CYAN}③ Key Generation & CSR Creation{RESET}{DIM} ──────────────────────{RESET}"
    emit_at(ts, f"\r\n{breaker}\r\n\r\n")

    ts = 81.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("key gen rsa --bits 4096 -o /home/qnadmin/demo.key", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.1, 4)
    key_lines = [
        f"{BOLD_GREEN}●{RESET} Generating RSA-4096 key...",
        f"{BOLD_GREEN}✓{RESET} Key saved to /home/qnadmin/demo.key (mode 0600)",
        f"  Algorithm: RSA-4096",
        f"  Security:  {BOLD_GREEN}Strong{RESET} (128-bit equivalent)",
        "",
    ]
    ts = emit_line_by_line(key_lines, ts, 0.06)

    # Hold 1.5s then CSR
    ts = round(ts + 1.5, 4)
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    csr_cmd = "csr create --key /home/qnadmin/demo.key --cn demo.quantumnexum.com --san dns:www.demo.quantumnexum.com --org \"QuantumNexum\" --country US -o /home/qnadmin/demo.csr"
    ts = type_string(csr_cmd, ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.1, 4)
    csr_lines = [
        f"{BOLD_GREEN}●{RESET} Creating CSR for demo.quantumnexum.com using RSA-4096 key...",
        f"{BOLD_GREEN}✓{RESET} CSR saved to /home/qnadmin/demo.csr",
        f"  Subject: CN=demo.quantumnexum.com",
        f"  SANs: dns:www.demo.quantumnexum.com",
        "",
        f"Certificate Signing Request:",
        f"  Subject: C=US, O=QuantumNexum, CN=demo.quantumnexum.com",
        f"  Common Name: demo.quantumnexum.com",
        "",
        f"Public Key:",
        f"  Algorithm: RSA",
        f"  Size: 4096 bits",
        "",
        f"Signature:",
        f"  Algorithm: sha256WithRSAEncryption",
        "",
    ]
    ts = emit_line_by_line(csr_lines, ts, 0.045)

    # Hold 2s
    ts = round(ts + 2.0, 4)
    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 6: PQC HIERARCHY BUILD (110-145s)
# ─────────────────────────────────────────────

def build_act6() -> None:
    ts = 110.0

    breaker = f"{DIM}────────────────────── {BOLD_CYAN}④ Post-Quantum PKI Hierarchy{RESET}{DIM} ──────────────────────{RESET}"
    emit_at(ts, f"\r\n{breaker}\r\n\r\n")

    ts = 111.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("pki preview /etc/pki/pqc-hierarchy.toml", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.1, 4)
    preview_lines = [
        f"PKI Hierarchy: {BOLD_WHITE}QuantumNexum PQC Demo{RESET}",
        f"{'=' * 60}",
        "",
        f"[{BOLD_RED}ROOT{RESET}] {BOLD_WHITE}QN Root CA G1{RESET} ({BOLD_MAGENTA}ml-dsa-87{RESET})",
        f"     validity: 20 years, path_length: 1",
        f"└── [{YELLOW}INT{RESET}] {BOLD_WHITE}QN TLS Issuing CA G1{RESET} ({BOLD_MAGENTA}ml-dsa-65{RESET})",
        f"     validity: 5 years, path_length: 0",
        "",
    ]
    ts = emit_line_by_line(preview_lines, ts, 0.06)

    # Hold 2s then build
    ts = round(ts + 2.0, 4)
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("pki build /etc/pki/pqc-hierarchy.toml -o /home/qnadmin/pqc-pki --force", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.15, 4)
    build_lines = [
        f"{BOLD_CYAN}→{RESET} Building hierarchy '{BOLD_WHITE}QuantumNexum PQC Demo{RESET}'...",
        f"{BOLD_GREEN}✓{RESET} Built {BOLD_WHITE}2{RESET} CAs",
        f"{BOLD_GREEN}✓{RESET} Exported {BOLD_WHITE}8{RESET} files to /home/qnadmin/pqc-pki",
        f"  • {BOLD_MAGENTA}root{RESET} (7823 bytes)",
        f"  • {BOLD_MAGENTA}issuing{RESET} (7209 bytes)",
        "",
    ]
    ts = emit_line_by_line(build_lines, ts, 0.08)

    # Hold 2s
    ts = round(ts + 2.0, 4)
    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 7: INSPECT PQC ROOT CA (145-175s)
# ─────────────────────────────────────────────

def build_act7() -> None:
    ts = 145.0

    breaker = f"{DIM}────────────────────── {BOLD_CYAN}⑤ Post-Quantum Certificate Inspection{RESET}{DIM} ──────────────────────{RESET}"
    emit_at(ts, f"\r\n{breaker}\r\n\r\n")

    ts = 146.0
    emit_at(ts, PKI_PROMPT)
    ts = round(ts + 0.2, 4)
    ts = type_string("show /home/qnadmin/pqc-pki/root/root.cert.pem", ts)
    ts = round(ts + 0.1, 4)
    emit_at(ts, "\r\n")

    ts = round(ts + 0.1, 4)
    pqc_lines = [
        f"Certificate Summary:",
        f"    Type:           CA Certificate (Unknown)",
        f"    Trust:          {BOLD_GREEN}Trusted Root{RESET}    Wildcard: No",
        f"    Subject:        {BOLD_WHITE}QN Root CA G1{RESET}",
        f"    Issuer:         {YELLOW}DC=com, DC=quantumnexum, O=QuantumNexum, CN=QN Root CA G1{RESET}",
        f"    Purpose:        CA",
        "",
        f"    Key:            {BOLD_MAGENTA}ML-DSA-87{RESET}",
        f"    Validity:       7305 days (20 years) (7304 days remaining)",
        f"    Lifetime:       [░░░░░░░░░░░░░░░░░░░░] 0.0%",
        "",
        f"    Status:         - CT  ✗ OCSP  ✗ CRL  SANs: 0",
        "",
        f"Certificate:",
        f"    Data:",
        f"        Version: 3 (0x2)",
        f"        Serial Number:",
        f"            1 (0x1)",
        f"        Signature Algorithm: {BOLD_MAGENTA}ML-DSA-87 (2.16.840.1.101.3.4.3.19){RESET}",
        f"        Issuer: DC=com, DC=quantumnexum, O=QuantumNexum, CN=QN Root CA G1",
        f"        Validity:",
        f"            Not Before: Mar 24 01:19:23 2026 UTC",
        f"            Not After : Mar 24 01:24:23 {BOLD_CYAN}2046{RESET} UTC {CYAN}7304 days{RESET}",
        f"            Lifetime : [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0.0%",
        f"        Subject: DC=com, DC=quantumnexum, O=QuantumNexum, CN=QN Root CA G1",
        f"        Subject Public Key Info:",
        f"            Algorithm: {BOLD_MAGENTA}ML-DSA-87{RESET} (2.16.840.1.101.3.4.3.19)",
        f"        X509v3 Extensions:",
        f"            X509v3 Basic Constraints (2.5.29.19): {RED}(critical){RESET}",
        f"                CA:TRUE, pathlen:1",
        f"            X509v3 Key Usage (2.5.29.15): {RED}(critical){RESET}",
        f"                Digital Signature, Certificate Sign, CRL Sign",
        f"            X509v3 Certificate Policies (2.5.29.32):",
        f"                Policy: SPORK Evaluation (1.3.6.1.4.1.56266.1.1.0)",
        f"    {CYAN}Signature Algorithm{RESET}: {BOLD_MAGENTA}ML-DSA-87{RESET}",
        f"    {CYAN}Signature Value{RESET}:",
        f"        {DIM}3a:c1:f8:92:b4:d7:6e:01:55:a3:c8:f0:9d:2b:71:e4:8a:93{RESET}",
        f"        {DIM}d6:15:f7:a2:c3:89:4b:e0:71:2d:a8:f5:63:94:b1:e7:0c:d2{RESET}",
        f"        {DIM}8f:43:a1:b6:e5:72:d9:04:3e:c8:17:5a:f3:b6:91:48:2c:a0{RESET}",
        f"        {DIM}e7:59:14:b3:c6:82:f0:d5:47:a9:31:6e:b4:c8:25:f1:73:9a{RESET}",
        f"        {DIM}... (4627 bytes — ML-DSA-87 signature){RESET}",
        "",
        f"{BOLD_CYAN}Fingerprints{RESET}:",
        f"    SHA-256:        {CYAN}8cfb5471c088603d2501a635972bb894e01aac19c938add4d45d56c5c89490b4{RESET}",
        f"    SHA-1:          {DIM}d3e0d4451f10eecca0b04f6a1704412f984e1001{RESET}",
        f"    SPKI Pin:       {BOLD_GREEN}Fe+nPJGxYv66cZbouBe3xUABkG9Se0L2MuDuU+/yzy0={RESET}",
        "",
        f"{BOLD_CYAN}PEM{RESET}:",
        f"{DIM}-----BEGIN CERTIFICATE-----{RESET}",
        f"{DIM}MIIdbTCCCx2gAwIBAgIBATANBgsrBgEEAQKccwMTATBdMRYwFAYKCZImiZPyLGQB{RESET}",
        f"{DIM}GRYGcG9ydGFsMRkwFwYKCZImiZPyLGQBGRYJcG9ydGFsLWNhMRIwEAYDVQQKEwlR{RESET}",
        f"{DIM}dWFudHVtTmV4dW0xFDASBgNVBAMTC1FOIFJvb3QgQ0EgRzEwHhcNMjYwMzI0MDEx{RESET}",
        f"{DIM}...{RESET}",
        f"{DIM}-----END CERTIFICATE-----{RESET}",
        "",
        f"Certificate Chain:",
        "",
        f"    QN Root CA G1 {DIM}(Self-signed){RESET}",
        f"        Valid: {CYAN}7304 days{RESET} | {BOLD_MAGENTA}ML-DSA-87{RESET}",
        "",
    ]
    ts = emit_line_by_line(pqc_lines, ts, 0.018)

    # Hold 3s
    ts = round(ts + 3.0, 4)
    emit_at(ts, PKI_PROMPT)


# ─────────────────────────────────────────────
# ACT 8: OUTRO (175-185s)
# ─────────────────────────────────────────────

def build_act8() -> None:
    ts = 175.0
    emit_at(ts, f"{ESC}[2J{ESC}[H")

    import re

    def centered_row(text: str, row: int, width: int = 120) -> tuple[int, int, str]:
        plain = re.sub(r'\033\[[0-9;]*m', '', text)
        col = max(1, (width - len(plain)) // 2 + 1)
        return row, col, text

    outro_items = [
        (15, f"{c('0;36')}─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─{RESET}"),
        (17, f"{BOLD_WHITE}Q U A N T U M   N E X U M{RESET}"),
        (19, f"{c('0;36')}─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─╮╭─{RESET}"),
        (22, f"{DIM}forging quantum trust, one link at a time{RESET}"),
        (24, f"{DIM}pki v0.6.9 │ Apache-2.0 │ quantumnexum.com{RESET}"),
    ]

    for i, (row, text) in enumerate(outro_items):
        r, col, content = centered_row(text, row)
        emit_at(round(ts + 0.2 * i, 4), move_to(r, col) + content)

    # Hold 5 seconds, then empty output to end
    ts = 180.0
    emit_at(ts, "")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    random.seed(42)

    build_act1()
    build_act2()
    build_act3()
    build_act4()
    build_act5()
    build_act6()
    build_act7()
    build_act8()

    # Sort by timestamp (should already be sorted, but be safe)
    events.sort(key=lambda e: e[0])

    # Ensure strict monotonicity
    for i in range(1, len(events)):
        if events[i][0] <= events[i - 1][0]:
            events[i][0] = round(events[i - 1][0] + 0.001, 4)

    header = {
        "version": 2,
        "width": 120,
        "height": 40,
        "timestamp": 1742774400,
        "title": "PKI Client \u2014 Enterprise Demo",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Written {len(events)} events to {OUTPUT_PATH}")
    total_time = events[-1][0] if events else 0
    print(f"Total duration: {total_time:.1f}s")


if __name__ == "__main__":
    main()

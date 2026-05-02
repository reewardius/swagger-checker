#!/usr/bin/env python3
"""
JS Security Analyzer
Fetches JS files from a URL list and scans for hardcoded secrets,
JWT artifacts, auth endpoints, cloud keys, and other sensitive patterns.

Usage:
    python js_analyzer.py urls.txt [--json report.json] [--concurrency 15] [--severity HIGH]
"""

import re
import sys
import asyncio
import aiohttp
import json
import argparse
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional
from tqdm import tqdm

# ─── Severity levels ──────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# ─── Pattern definitions ──────────────────────────────────────────────────────
# Each entry: (severity, category, pattern)

PATTERNS: list[tuple[str, str, str]] = [

    # ── Passwords ─────────────────────────────────────────────────────────────
    # Require word boundary before keyword + value must not look like a JS identifier
    # (no camelCase like "PasswordFlow", no function names like "resetPassword")
    (CRITICAL, "Password / Field Assignment",
     r'(?<![A-Za-z])(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'),

    # DSN must have a real hostname after @, not minified JS
    (CRITICAL, "Password / In URL DSN",
     r'https?://[A-Za-z0-9._%-]{2,}:([^@\s"\'`]{4,})@[A-Za-z0-9._-]{4,}'),

    # ── Usernames / Logins ────────────────────────────────────────────────────
    # Only match username/user_name, not bare "user" or "login" — too noisy in minified JS
    (HIGH, "Username / Field Assignment",
     r'(?<![A-Za-z])(?:username|user_name)\s*[=:]\s*["\']([^"\']{4,})["\']'),

    # ── Secrets & keys ────────────────────────────────────────────────────────
    (CRITICAL, "Secret / Generic Field",
     r'(?:secret|client[_-]?secret|app[_-]?secret|consumer[_-]?secret|shared[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'),

    (CRITICAL, "Secret / Private Key Field",
     r'(?:private[_-]?key|privateKey|priv[_-]?key)\s*[=:]\s*["\']([^"\']{10,})["\']'),

    (CRITICAL, "Secret / PEM Block",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),

    (CRITICAL, "Secret / JWT Signing Key",
     r'(?:jwt[_-]?secret|jwtSecret|jwt[_-]?key|signing[_-]?secret)\s*[=:]\s*["\']([^"\']{6,})["\']'),

    (HIGH, "Secret / Base64 Encoded Value",
     r'(?:secret|key|password|credential)\s*[=:]\s*["\']([A-Za-z0-9+/]{32,}={0,2})["\']'),

    # ── API Keys ──────────────────────────────────────────────────────────────
    (CRITICAL, "API Key / Generic",
     r'(?:api[_-]?key|apikey|access[_-]?key|x-api-key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),

    (HIGH, "API Key / Bearer Token Hardcoded",
     r'[Bb]earer\s+([A-Za-z0-9_\-\.~+/]{20,})'),

    (HIGH, "API Key / Token Field",
     r'(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),

    # ── Database connection strings ───────────────────────────────────────────
    (CRITICAL, "Database / Connection String with Credentials",
     r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)://[^:]+:[^@\s"\'`]{4,}@[^\s"\'`]+'),

    (HIGH, "Database / Password Field",
     r'(?:db[_-]?pass(?:word)?|database[_-]?pass(?:word)?)\s*[=:]\s*["\']([^"\']{4,})["\']'),

    (HIGH, "Database / Connection String (no creds)",
     r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp)://[^\s"\'`]{8,}'),

    # ── Cloud providers ───────────────────────────────────────────────────────
    (CRITICAL, "Cloud / AWS Access Key ID",
     r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),

    (CRITICAL, "Cloud / AWS Secret Access Key",
     r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']'),

    (CRITICAL, "Cloud / GitHub Access Token",
     r'gh[pousr]_[A-Za-z0-9]{36,}'),

    (CRITICAL, "Cloud / Stripe Secret Key",
     r'sk_(?:live|test)_[A-Za-z0-9]{24,}'),

    (HIGH, "Cloud / GCP or Firebase API Key",
     r'AIza[0-9A-Za-z\-_]{35}'),

    (HIGH, "Cloud / GCP Service Account JSON",
     r'"type"\s*:\s*"service_account"'),

    (HIGH, "Cloud / Azure Storage Key or SAS",
     r'(?:AccountKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+/=]{20,}'),

    (HIGH, "Cloud / Slack Token",
     r'xox[baprs]-[0-9A-Za-z\-]{10,}'),

    (HIGH, "Cloud / Slack Webhook",
     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),

    (HIGH, "Cloud / SendGrid API Key",
     r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}'),

    (HIGH, "Cloud / Twilio Auth Token",
     r'(?:twilio[_-]?auth[_-]?token)\s*[=:]\s*["\']([a-f0-9]{32})["\']'),

    (HIGH, "Cloud / NPM Auth Token",
     r'npm_[A-Za-z0-9]{36,}'),

    (HIGH, "Cloud / Telegram Bot Token",
     r'\d{9,11}:[A-Za-z0-9_\-]{35}'),

    (HIGH, "Cloud / Shopify Access Token",
     r'shpat_[A-Za-z0-9]{32}'),

    (HIGH, "Cloud / Mailgun API Key",
     r'key-[0-9a-f]{32}'),

]


# ─── False-positive filter ────────────────────────────────────────────────────

IGNORE_SUBSTRINGS = {
    'undefined', 'null', 'true', 'false', 'none', 'empty', 'placeholder',
    'your_password', 'your_secret', 'your_api_key', 'changeme', 'change_me',
    'example', 'test', 'demo', 'sample', 'dummy', 'fake', 'mock',
    'xxxxxxxx', '********', '{{', '${', '__', 'insert_', 'replace_',
    'todo', 'fixme', 'fill_in', '<your', '[your', 'n/a',
    # Field name echoes — value IS the field name, not a real credential
    'password', 'passwd', 'pwd', 'username', 'user_name', 'secret', 'token',
    'new_password', 'old_password', 'confirm_password', 'repeat_password',
    # i18n / Sentry placeholders
    '%filtered%', '%s', '%(', 'redacted', 'censored', 'hidden',
}

# Unicode escape sequences that decode to common UI label words
# e.g. \u041f\u0430\u0440\u043e\u043b\u044c = "Пароль" (Password in Ukrainian)
UNICODE_LABEL_WORDS = {
    # Ukrainian / Russian
    '\u041f\u0430\u0440\u043e\u043b\u044c',  # Пароль
    '\u043f\u0430\u0440\u043e\u043b\u044c',  # пароль
    '\u041b\u043e\u0433\u0438\u043d',         # Логин
    '\u043b\u043e\u0433\u0438\u043d',         # логин
    '\u041f\u043e\u0447\u0442\u0430',         # Почта
}

def is_trivial(value: str) -> bool:
    v = value.strip()

    if len(v) < 4:
        return True

    # All same/near-same chars: "aaaa", "0000", "abab"
    if len(set(v.lower())) <= 2:
        return True

    # Known ignore list
    if any(ign in v.lower() for ign in IGNORE_SUBSTRINGS):
        return True

    # Unicode UI labels (e.g. "Пароль" as a form label)
    if v in UNICODE_LABEL_WORDS:
        return True

    # Pure unicode escape string — likely a UI label, not a credential
    if re.match(r'^(\\u[0-9a-fA-F]{4})+$', v):
        return True

    # Looks like a JS identifier / function name
    if re.match(r'^[A-Z][A-Za-z]{3,}$', v):    # PascalCase: "PasswordFlow"
        return True
    if re.match(r'^[a-z]+[A-Z][A-Za-z]+$', v):  # camelCase: "resetPassword"
        return True
    if re.match(r'^[a-z_]+$', v):               # snake_case single word: "password", "token"
        return True

    return False


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    category: str
    match: str
    line_number: int
    line_content: str


@dataclass
class FileResult:
    url: str
    status: str          # ok | error | skip
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze_content(content: str, min_severity: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    min_order = SEVERITY_ORDER[min_severity]

    for severity, category, pattern in PATTERNS:
        if SEVERITY_ORDER[severity] > min_order:
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue

        for line_num, line in enumerate(lines, start=1):
            for m in compiled.finditer(line):
                value = m.group(1) if m.lastindex else m.group(0)
                if is_trivial(value):
                    continue
                findings.append(Finding(
                    severity=severity,
                    category=category,
                    match=value[:250],
                    line_number=line_num,
                    line_content=line.strip()[:350],
                ))

    # Deduplicate on (category, match)
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.category, f.match)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line_number))
    return unique


# ─── HTTP fetch ───────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    "Accept-Encoding": "gzip, deflate",
}

async def fetch_and_analyze(
    session: aiohttp.ClientSession,
    url: str,
    min_severity: str,
) -> FileResult:
    url = url.strip()
    if not url or url.startswith("#"):
        return FileResult(url=url, status="skip")

    if not urlparse(url).scheme:
        url = "https://" + url

    try:
        async with session.get(url, headers=HEADERS,
                               timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                return FileResult(url=url, status="error",
                                  error=f"HTTP {resp.status}")
            text = await resp.text(errors="replace")

        findings = analyze_content(text, min_severity)
        return FileResult(url=url, status="ok", findings=findings)

    except asyncio.TimeoutError:
        return FileResult(url=url, status="error", error="Timeout")
    except Exception as e:
        return FileResult(url=url, status="error", error=str(e))


# ─── Output ───────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    CRITICAL: "\033[91m",
    HIGH:     "\033[93m",
    MEDIUM:   "\033[94m",
    LOW:      "\033[96m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[92m"
DIM   = "\033[2m"

SEVERITY_ICON = {
    CRITICAL: "🔴",
    HIGH:     "🟠",
    MEDIUM:   "🟡",
    LOW:      "🔵",
}


def print_results(results: list[FileResult]):
    count_clean  = 0
    count_errors = 0
    count_hits   = 0
    total_findings = 0

    for res in results:
        if res.status == "skip":
            continue
        if res.status == "error":
            count_errors += 1
            continue
        if not res.findings:
            count_clean += 1
            continue

        count_hits += 1
        total_findings += len(res.findings)

        print(f"\n{'═'*72}")
        print(f"{BOLD}  {res.url}{RESET}")
        print(f"  {SEVERITY_COLOR[CRITICAL]}{BOLD}⚠  {len(res.findings)} finding(s){RESET}")

        grouped: dict[str, list[Finding]] = {}
        for f in res.findings:
            grouped.setdefault(f.category, []).append(f)

        for category, items in grouped.items():
            sev = items[0].severity
            col = SEVERITY_COLOR[sev]
            icon = SEVERITY_ICON[sev]
            print(f"\n  {col}{BOLD}{icon} [{sev}] {category}{RESET}")
            for item in items:
                print(f"    {DIM}line {item.line_number}{RESET}")
                print(f"      Value   : {col}{BOLD}{item.match}{RESET}")
                print(f"      Context : {DIM}{item.line_content}{RESET}")

    # Summary
    total = count_clean + count_errors + count_hits
    print(f"\n{'═'*72}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"{'─'*72}")
    print(f"  Files scanned     : {total}")
    print(f"  {GREEN}✓ Clean           : {count_clean}{RESET}")
    print(f"  {SEVERITY_COLOR[CRITICAL]}⚠ With findings  : {count_hits}  ({total_findings} total){RESET}")
    print(f"  {DIM}✗ Fetch errors    : {count_errors}{RESET}")
    print(f"{'═'*72}")


def save_json(results: list[FileResult], path: str):
    out = []
    for r in results:
        if r.status == "skip":
            continue
        out.append({
            "url":      r.url,
            "status":   r.status,
            "error":    r.error,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "match":    f.match,
                    "line":     f.line_number,
                    "context":  f.line_content,
                }
                for f in r.findings
            ],
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print(f"\n  JSON report saved → {path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Scan JS files from a URL list for secrets, JWT artifacts, and sensitive patterns."
    )
    parser.add_argument("input",
                        help="Text file with one URL per line")
    parser.add_argument("--json", metavar="FILE",
                        help="Save results to a JSON report")
    parser.add_argument("--concurrency", type=int, default=10,
                        help="Parallel HTTP requests (default: 10)")
    parser.add_argument("--severity",
                        choices=[CRITICAL, HIGH, MEDIUM, LOW],
                        default=LOW,
                        help="Minimum severity to report (default: LOW — show everything)")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as fh:
            urls = list(dict.fromkeys(
                l.strip() for l in fh if l.strip() and not l.startswith("#")
            ))
    except FileNotFoundError:
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    print(f"\n  JS Security Analyzer")
    print(f"{'─'*40}")
    print(f"  URLs loaded   : {len(urls)}")
    print(f"  Concurrency   : {args.concurrency}")
    print(f"  Min severity  : {args.severity}")
    print(f"  Patterns      : {len(PATTERNS)}\n")

    sem = asyncio.Semaphore(args.concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=args.concurrency)
    results: list[FileResult] = []

    async def guarded_fetch(session: aiohttp.ClientSession, url: str):
        async with sem:
            r = await fetch_and_analyze(session, url, args.severity)
            if r.findings:
                # tqdm.write() prints above the progress bar without breaking it
                lines = [f"\n{'═'*72}",
                         f"  {BOLD}{r.url}{RESET}",
                         f"  {SEVERITY_COLOR[CRITICAL]}{BOLD}⚠  {len(r.findings)} finding(s){RESET}"]

                grouped: dict[str, list[Finding]] = {}
                for f in r.findings:
                    grouped.setdefault(f.category, []).append(f)

                for category, items in grouped.items():
                    sev   = items[0].severity
                    col   = SEVERITY_COLOR[sev]
                    icon  = SEVERITY_ICON[sev]
                    lines.append(f"\n  {col}{BOLD}{icon} [{sev}] {category}{RESET}")
                    for item in items:
                        lines.append(f"    {DIM}line {item.line_number}{RESET}")
                        lines.append(f"      Value   : {col}{BOLD}{item.match}{RESET}")
                        lines.append(f"      Context : {DIM}{item.line_content}{RESET}")

                tqdm.write("\n".join(lines))
                pbar.set_postfix_str(
                    f"last hit: {url.split('/')[-1][:30]} ({len(r.findings)})"
                )
            pbar.update(1)
            return r

    async with aiohttp.ClientSession(connector=connector) as session:
        with tqdm(
            total=len(urls),
            desc="Scanning",
            unit="file",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}",
            colour="cyan",
        ) as pbar:
            tasks = [guarded_fetch(session, u) for u in urls]
            results = await asyncio.gather(*tasks)

    # Findings already printed in real-time — only show summary now
    count_clean    = sum(1 for r in results if r.status == "ok"    and not r.findings)
    count_errors   = sum(1 for r in results if r.status == "error")
    count_hits     = sum(1 for r in results if r.status == "ok"    and r.findings)
    total_findings = sum(len(r.findings) for r in results)

    print(f"\n{'═'*72}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"{'─'*72}")
    print(f"  Files scanned     : {len(urls)}")
    print(f"  {GREEN}✓ Clean           : {count_clean}{RESET}")
    print(f"  {SEVERITY_COLOR[CRITICAL]}⚠ With findings  : {count_hits}  ({total_findings} total){RESET}")
    print(f"  {DIM}✗ Fetch errors    : {count_errors}{RESET}")
    print(f"{'═'*72}")

    if args.json:
        save_json(results, args.json)


if __name__ == "__main__":
    asyncio.run(main())

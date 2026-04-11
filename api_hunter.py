#!/usr/bin/env python3
"""
api_hunter.py — Extract and probe API endpoints from JS files on websites.
               Sends results via AWS SES with the output file as an attachment.

Usage:
    python api_hunter.py -u https://example.com
    python api_hunter.py -u https://example.com -u https://other.com
    python api_hunter.py -i targets.txt
    python api_hunter.py -i foo.txt -i bar.txt
    python api_hunter.py -u https://example.com -o results.txt -t 20 --timeout 10

    # With email notification:
    python api_hunter.py -u https://example.com \\
        --email-sender sender@example.com \\
        --email-recipient recipient@example.com \\
        --github-token ghp_... \\
        --aws-region eu-central-1
"""

import argparse
import asyncio
import re
import subprocess
import sys
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime

import aiohttp

# ── Patterns to find API paths in JS ──────────────────────────────────────────
API_PATTERNS = [
    # .get("/api/...") .post("/api/...") .put(...) .delete(...) .patch(...)
    r'\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
    # fetch("/api/...") axios("/api/...") axios.get("/api/...")
    r'(?:fetch|axios(?:\.\w+)?)\(\s*["\']([^"\']+)["\']',
    # url: "/api/..." path: "/api/..."
    r'(?:url|path|endpoint)\s*:\s*["\']([^"\']+)["\']',
    # "/api/..." or '/api/...' standalone strings
    r'["\'](/(?:api|v\d+|rest|graphql|gql|service|services|data|internal|external|backend|rpc|webhook|ws|socket)[^"\'?\s]*)["\']',
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in API_PATTERNS]

# ── Helpers ────────────────────────────────────────────────────────────────────

def run_getjs(targets: List[str]) -> List[str]:
    """Run getJS for each target URL and collect unique JS URLs."""
    js_urls = set()
    for target in targets:
        print(f"[*] getJS → {target}")
        try:
            result = subprocess.run(
                ["getJS", "-url", target, "--complete"],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    js_urls.add(line)
        except FileNotFoundError:
            print("[!] getJS not found. Install it: go install github.com/003random/getJS@latest")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"[!] getJS timed out for {target}")
    return list(js_urls)


def run_getjs_files(input_files: List[str]) -> List[str]:
    """Run getJS with -input for file-based target lists."""
    js_urls = set()
    args = ["getJS", "--complete"]
    for f in input_files:
        args += ["-input", f]
    print(f"[*] getJS with input files: {input_files}")
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                js_urls.add(line)
    except FileNotFoundError:
        print("[!] getJS not found.")
        sys.exit(1)
    return list(js_urls)


def extract_api_paths(js_content: str) -> Set[str]:
    """Extract API-like paths from JS source."""
    paths = set()
    for pattern in COMPILED:
        for match in pattern.finditer(js_content):
            path = match.group(1).strip()
            # Must look like an API path (not a full URL, not too short)
            if len(path) > 3 and not path.startswith("http") and "/" in path:
                paths.add(path)
    return paths


def build_endpoint_url(js_url: str, api_path: str) -> str:
    """Combine JS file origin with an API path."""
    parsed = urlparse(js_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return urljoin(base, api_path)


async def fetch_js(session: aiohttp.ClientSession, url: str, timeout: int) -> Optional[str]:
    """Download a JS file and return its content."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except Exception as e:
        print(f"    [!] JS fetch error {url}: {e}")
    return None


async def probe_endpoint(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    method: str = "GET",
) -> Tuple[str, bool]:
    """
    Probe an API endpoint.
    Returns (url, True) if:
      - status == 200
      - content-type is application/json or text/plain
      - body length > 0
    """
    try:
        fn = getattr(session, method.lower())
        async with fn(url, timeout=aiohttp.ClientTimeout(total=timeout),
                      allow_redirects=True) as resp:
            if resp.status != 200:
                return url, False
            ct = resp.headers.get("Content-Type", "")
            if not any(t in ct for t in ("application/json", "text/plain")):
                return url, False
            body = await resp.read()
            if len(body) == 0:
                return url, False
            print(f"    [+] HIT  {resp.status} {ct.split(';')[0].strip():<25} {url}")
            return url, True
    except Exception:
        return url, False


async def process_js_urls(
    js_urls: List[str],
    concurrency: int,
    timeout: int,
    output_file: str,
    methods: List[str],
) -> int:
    """Process JS URLs, probe endpoints and write results. Returns count of confirmed endpoints."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
    }

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    confirmed: Set[str] = set()

    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        # Step 1: download all JS files
        print(f"\n[*] Downloading {len(js_urls)} JS file(s)…")
        js_semaphore = asyncio.Semaphore(concurrency)

        async def bounded_fetch(url):
            async with js_semaphore:
                return url, await fetch_js(session, url, timeout)

        js_tasks = [bounded_fetch(u) for u in js_urls]
        js_results = await asyncio.gather(*js_tasks)

        # Step 2: extract API paths
        endpoint_map: Dict[str, str] = {}  # endpoint_url → js_url
        for js_url, content in js_results:
            if not content:
                continue
            paths = extract_api_paths(content)
            print(f"    [{len(paths):>4} paths] {js_url}")
            for path in paths:
                ep = build_endpoint_url(js_url, path)
                endpoint_map[ep] = js_url

        print(f"\n[*] Unique endpoints to probe: {len(endpoint_map)}")
        if not endpoint_map:
            print("[!] No API endpoints found.")
            return 0

        # Step 3: probe endpoints
        print(f"[*] Probing with methods: {methods} (concurrency={concurrency})\n")
        probe_semaphore = asyncio.Semaphore(concurrency)

        async def bounded_probe(ep, method):
            async with probe_semaphore:
                return await probe_endpoint(session, ep, timeout, method)

        probe_tasks = [
            bounded_probe(ep, method)
            for ep in endpoint_map
            for method in methods
        ]
        probe_results = await asyncio.gather(*probe_tasks)

        for ep_url, ok in probe_results:
            if ok:
                confirmed.add(ep_url)

    # Step 4: append results to file
    if confirmed:
        out = Path(output_file)
        with out.open("a") as f:
            for url in sorted(confirmed):
                f.write(url + "\n")
        print(f"\n[✓] {len(confirmed)} confirmed endpoint(s) appended → {out.resolve()}")
    else:
        print("\n[-] No live endpoints found for this target.")

    return len(confirmed)


# ── Email / SES ────────────────────────────────────────────────────────────────

def send_email(
    subject: str,
    body_text: str,
    sender: str,
    recipient: str,
    aws_region: str,
    attachment_path: Optional[str] = None,
) -> bool:
    """Send email via AWS SES, optionally with a file attachment."""
    try:
        import boto3
    except ImportError:
        print("[!] boto3 not installed. Run: pip install boto3")
        return False

    try:
        ses_client = boto3.client("ses", region_name=aws_region)

        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject

        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        # Attach results file if it exists and has content
        if attachment_path:
            attach_path = Path(attachment_path)
            if attach_path.exists() and attach_path.stat().st_size > 0:
                with attach_path.open("rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{attach_path.name}"',
                )
                msg.attach(part)
                print(f"[*] Attaching results file: {attach_path.name} "
                      f"({attach_path.stat().st_size} bytes)")
            else:
                print(f"[!] Attachment skipped: file not found or empty ({attachment_path})")

        response = ses_client.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={"Data": msg.as_string()},
        )
        print(f"\n✅ Email sent! MessageId: {response['MessageId']}")
        return True

    except Exception as e:
        print(f"\n❌ Error sending email: {e}")
        return False


def build_email_body(
    targets: List[str],
    total_confirmed: int,
    output_file: str,
    duration: float,
    timestamp: str,
) -> Tuple[str, str]:
    """Build email subject and body. Returns (subject, body)."""
    subject = (
        f"API Hunter — {total_confirmed} endpoint(s) found"
        if total_confirmed > 0
        else "API Hunter — No endpoints found"
    )

    body = f"API Hunter scan complete.\n"
    body += f"Confirmed live endpoints: {total_confirmed}\n"

    if total_confirmed > 0:
        body += "The full results file is attached to this email.\n"
    else:
        body += "No live API endpoints were found during this scan.\n"

    return subject, body


# ── Entry point ────────────────────────────────────────────────────────────────

def load_targets(urls: Optional[List[str]], inputs: Optional[List[str]]) -> List[str]:
    """Read all target URLs from -u args and/or -i files."""
    targets = []
    if urls:
        targets += urls
    if inputs:
        for filepath in inputs:
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            targets.append(line)
            except FileNotFoundError:
                print(f"[!] Input file not found: {filepath}")
                sys.exit(1)
    # deduplicate, preserve order
    seen = set()
    result = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Discover and probe API endpoints found in JS files."
    )
    # ── Scan options ──────────────────────────────────────────────────────────
    parser.add_argument("-u", "--url", action="append", dest="urls",
                        metavar="URL", help="Target URL (repeatable)")
    parser.add_argument("-i", "--input", action="append", dest="inputs",
                        metavar="FILE", help="File with target URLs (repeatable)")
    parser.add_argument("-o", "--output", default="200_get.txt",
                        help="Output file for confirmed endpoints (default: 200_get.txt)")
    parser.add_argument("-t", "--threads", type=int, default=15,
                        help="Concurrency level (default: 15)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--methods", default="GET",
                        help="Comma-separated HTTP methods to try, e.g. GET,POST (default: GET)")

    # ── Email / SES options ───────────────────────────────────────────────────
    email_group = parser.add_argument_group(
        "email",
        "Optional: send results via AWS SES after scan completes"
    )
    email_group.add_argument("--email-sender", metavar="EMAIL",
                             help="Sender email address (must be verified in SES)")
    email_group.add_argument("--email-recipient", metavar="EMAIL",
                             help="Recipient email address")
    email_group.add_argument("--aws-region", default="eu-central-1",
                             help="AWS region for SES (default: eu-central-1)")

    args = parser.parse_args()

    if not args.urls and not args.inputs:
        parser.print_help()
        sys.exit(1)

    # Validate email args: either both provided or neither
    email_enabled = bool(args.email_sender or args.email_recipient)
    if email_enabled and not (args.email_sender and args.email_recipient):
        parser.error("--email-sender and --email-recipient must both be provided.")

    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    targets = load_targets(args.urls, args.inputs)
    if not targets:
        print("[!] No targets found. Exiting.")
        sys.exit(0)

    # Clear output file once at startup
    out_path = Path(args.output)
    out_path.write_text("")
    print(f"[*] Output file cleared: {out_path.resolve()}")
    print(f"[*] {len(targets)} target(s) to process")

    start_time = datetime.now()
    timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
    total_confirmed = 0

    for i, target in enumerate(targets, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(targets)}] {target}")
        print(f"{'='*60}")

        js_urls = run_getjs([target])
        js_urls = list(set(js_urls))
        print(f"[*] JS files found: {len(js_urls)}")

        if not js_urls:
            print("[!] No JS files found, skipping.")
            continue

        count = asyncio.run(process_js_urls(
            js_urls=js_urls,
            concurrency=args.threads,
            timeout=args.timeout,
            output_file=args.output,
            methods=methods,
        ))
        total_confirmed += count

    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Done. Results in: {out_path.resolve()}")
    print(f"[*] Total confirmed endpoints: {total_confirmed} | Duration: {duration:.1f}s")

    # ── Send email if configured ──────────────────────────────────────────────
    if email_enabled:
        print(f"\n[*] Sending email report to {args.email_recipient}…")
        subject, body = build_email_body(
            targets=targets,
            total_confirmed=total_confirmed,
            output_file=str(out_path.resolve()),
            duration=duration,
            timestamp=timestamp,
        )
        send_email(
            subject=subject,
            body_text=body,
            sender=args.email_sender,
            recipient=args.email_recipient,
            aws_region=args.aws_region,
            attachment_path=args.output,
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
api_hunter.py — Extract and probe API endpoints from JS files and their source maps.

Examples:
    python api_hunter.py -u https://example.com
    python api_hunter.py -i targets.txt -o results.txt -t 20 --timeout 10
    python api_hunter.py -u https://example.com -H "Authorization: Bearer TOKEN" --cookie "sid=abc"
    python api_hunter.py -u https://example.com --no-probe --jsonl endpoints.jsonl
    python api_hunter.py -u https://example.com --methods GET,POST --allow-unsafe-methods
    python api_hunter.py -u https://example.com --no-sourcemaps        # skip .map analysis
    python api_hunter.py -u https://example.com --scope                # probe only the target's domain
"""

import argparse
import asyncio
import base64
import json
import logging
import re
import shutil
import uuid
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse, urlunparse

import aiohttp

log = logging.getLogger("api_hunter")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
MAX_JS_BYTES = 5 * 1024 * 1024
MAX_MAP_BYTES = 30 * 1024 * 1024
MAX_PROBE_BYTES = 64 * 1024
OK_CONTENT_TYPES = ("application/json", "text/plain")
BASE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
}

# ── Endpoint extraction ───────────────────────────────────────────────────────

Q = r"[\"'`]"                   # any quote, including backtick (template literals)
NOT_Q = r"[^\"'`]"
API_PREFIX = (r"(?:api|v\d+|rest|graphql|gql|service|services|data|internal|"
              r"external|backend|rpc|webhook|ws|socket)")
API_PATH = rf"/{API_PREFIX}(?:/[^\"'`\s]*)?"   # /api, /api/x/y, /v1/users
ANY_STRING = rf"{Q}({NOT_Q}+){Q}"               # group(1) = string content

PATH_PATTERNS = [
    # obj.get("...") .post("...") .request("...")
    rf"\.(?:get|post|put|delete|patch|head|options|request)\(\s*{ANY_STRING}",
    # fetch("...") fetch(`...`) axios("...") axios.get("...")
    rf"(?:fetch|axios(?:\.\w+)?)\(\s*{ANY_STRING}",
    # xhr.open("GET", "...")
    rf"\.open\(\s*{Q}[A-Za-z]+{Q}\s*,\s*{ANY_STRING}",
    # new URL("...", base)
    rf"new\s+URL\(\s*{ANY_STRING}",
    # url: "..." path: "..." endpoint: "..." href / baseURL / action
    rf"(?:url|path|endpoint|href|baseURL|action)\s*:\s*{ANY_STRING}",
    # standalone "/api/..." or the start of a template literal `/api/...`
    rf"{Q}({API_PATH}){Q}",
    # "base" + "/api/..."  or  base + "/api/..."
    rf"\+\s*{Q}({API_PATH}){Q}",
    # `${base}/api/...`  (interpolation followed directly by an API path)
    r"\}(" + API_PATH + r")",
]
COMPILED_PATHS = [re.compile(p, re.IGNORECASE) for p in PATH_PATTERNS]
ABS_URL_RE = re.compile(rf"{Q}(https?://{NOT_Q}+){Q}", re.IGNORECASE)

# ${expr}, {expr}, <expr>, or :param as a whole segment (not "orders:search")
PLACEHOLDER_RE = re.compile(r"\$\{[^}]*\}|\{[^}]*\}|<[^>]+>|(?<=/):[A-Za-z_]\w*(?=[/?]|$)")
# Things that cannot appear in a URL path from JS source
BAD_CHARS_RE = re.compile(r"[\s<>\\]")
MIME_RE = re.compile(r"^(?:application|text|image|audio|video|multipart|font|model)/", re.I)
STATIC_EXT = (
    ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".map", ".html", ".htm",
    ".mp4", ".pdf",
)

# ── Source maps ───────────────────────────────────────────────────────────────

# "//# sourceMappingURL=x.map" and the older "//@ sourceMappingURL=x.map" / "/*# ... */"
SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]+)")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def normalize_path(raw: str) -> Optional[Tuple[str, bool]]:
    """
    Normalize one candidate string from JS source.
    Returns (path_with_query, templated) or None if it does not look like a path.
    Relative paths ("users/list") get a leading "/" and are resolved later
    against each origin. templated=True means the path has placeholders.
    """
    p = raw.strip()
    if not p or BAD_CHARS_RE.search(p) or "://" in p or p.startswith("//"):
        return None
    if MIME_RE.match(p):                       # "application/json" etc.
        return None
    if not p.startswith("/"):
        p = "/" + p

    path, has_query, query = p.partition("?")
    path = path.split("#", 1)[0]
    path = PLACEHOLDER_RE.sub("{param}", path)
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")                # /api/users/ -> /api/users
    if len(path) < 4 or path.lower().endswith(STATIC_EXT):
        return None

    full = path
    if has_query and query.split("#", 1)[0]:
        full += "?" + PLACEHOLDER_RE.sub("{param}", query.split("#", 1)[0])
    return full, "{" in full


def normalize_absolute(raw: str) -> Optional[Tuple[str, bool]]:
    """Normalize an absolute URL from JS. Kept only if its path looks like an API."""
    cleaned = PLACEHOLDER_RE.sub("{param}", raw.strip())
    try:
        parsed = urlparse(cleaned)
        parsed.port  # raises ValueError for an invalid port
    except ValueError:
        return None                       # e.g. "https://[${host}]/api" -> bracketed garbage
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if "{" in parsed.netloc or "}" in parsed.netloc:
        return None                       # placeholder in the host: cannot be probed
    if not re.search(rf"/{API_PREFIX}(?:/|$)", parsed.path, re.IGNORECASE):
        return None
    norm = normalize_path(parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    if not norm:
        return None
    path_q, templated = norm
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path_q}", templated


def extract_endpoints(js_content: str, origins: Iterable[str]) -> Dict[str, bool]:
    """
    Return {url: templated} for endpoints found in source text.
    Relative paths are resolved against every origin in `origins`.
    """
    origins = [o.rstrip("/") for o in origins]
    found: Dict[str, bool] = {}

    def add(url: str, templated: bool) -> None:
        found[url] = found.get(url, False) or templated

    for rx in COMPILED_PATHS:
        for m in rx.finditer(js_content):
            norm = normalize_path(m.group(1))
            if norm:
                path_q, templated = norm
                for origin in origins:
                    add(origin + path_q, templated)

    for m in ABS_URL_RE.finditer(js_content):
        norm = normalize_absolute(m.group(1))
        if norm:
            add(*norm)

    return found


def find_sourcemap_ref(js_content: str, js_url: str) -> Optional[str]:
    """Absolute URL (or data: URI) of the source map a JS file points to."""
    matches = SOURCEMAP_RE.findall(js_content)
    if not matches:
        return None
    ref = matches[-1].strip()
    if ref.startswith("data:"):
        return ref
    return urljoin(js_url, ref)


def decode_data_uri(uri: str) -> Optional[str]:
    header, sep, payload = uri.partition(",")
    if not sep:
        return None
    if header.endswith(";base64"):
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except ValueError:
            return None
    return unquote(payload)


def parse_sourcemap(text: str) -> List[Tuple[str, Optional[str]]]:
    """Return [(source_name, sourcesContent or None)] for a source map (incl. indexed maps)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("source map is not a JSON object")
    if isinstance(data.get("sections"), list):           # indexed map
        out: List[Tuple[str, Optional[str]]] = []
        for sec in data["sections"]:
            if isinstance(sec, dict) and isinstance(sec.get("map"), dict):
                out += _parse_map_dict(sec["map"])
        return out
    return _parse_map_dict(data)


def _parse_map_dict(data: dict) -> List[Tuple[str, Optional[str]]]:
    root = data.get("sourceRoot") or ""
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out: List[Tuple[str, Optional[str]]] = []
    for i, src in enumerate(sources):
        if not isinstance(src, str):
            continue
        name = f"{root.rstrip('/')}/{src}" if root else src
        content = contents[i] if i < len(contents) else None
        out.append((name, content if isinstance(content, str) else None))
    return out


def source_fetch_url(map_url: str, name: str) -> Optional[str]:
    """
    Turn a source name into a fetchable http(s) URL, or None.
    Names like "webpack:///src/a.ts" are not served over HTTP and are skipped.
    """
    if name.startswith(("http://", "https://")):
        candidate = name
    elif SCHEME_RE.match(name):
        return None
    else:
        candidate = urljoin(map_url, name)
    return candidate if urlparse(candidate).scheme in ("http", "https") else None


# ── Scope and auth ────────────────────────────────────────────────────────────

MULTI_PART_SLD = {"co", "com", "net", "org", "gov", "edu", "ac"}


def registrable_domain(host: str) -> str:
    """
    Approximate eTLD+1: example.com for app.example.com, bbc.co.uk for news.bbc.co.uk.
    IP addresses are returned as is.
    """
    host = host.lower().strip(".")
    if not host or ":" in host or re.fullmatch(r"[\d.]+", host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in MULTI_PART_SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def in_scope(url: str, target_host: str) -> bool:
    """True if url is on the same registrable domain as the target (sibling subdomains included)."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    return host == target_host or registrable_domain(host) == registrable_domain(target_host)


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# Hosts whose JS is never downloaded or scanned (vendor analytics/CDN scripts)
DEFAULT_SKIP_HOSTS = [
    "cloudflare.com", "cloudflareinsights.com", "cloudflare.net",
    "cloudflarestorage.com", "cloudflare-dns.com",
]


def is_skipped_host(url: str, skip_hosts: Iterable[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == s or host.endswith("." + s) for s in skip_hosts)


def build_auth_headers(header_args: Optional[List[str]],
                       cookie_args: Optional[List[str]]) -> Dict[str, str]:
    """Build headers from -H 'Name: value' and --cookie 'a=b; c=d' arguments."""
    headers: Dict[str, str] = {}
    cookies: List[str] = []

    for raw in header_args or []:
        if re.search(r"[\r\n]", raw):
            raise ValueError("В заголовке не должно быть переводов строк")
        if ":" not in raw:
            raise ValueError(f"Некорректный заголовок (нужен 'Name: value'): {raw!r}")
        name, value = (s.strip() for s in raw.split(":", 1))
        if not name:
            raise ValueError(f"Пустое имя заголовка: {raw!r}")
        if name.lower() == "cookie":
            cookies.append(value)            # merged into one Cookie header below
        else:
            headers[name] = value

    cookies.extend(cookie_args or [])
    parts = [c.strip().strip(";").strip() for c in cookies]
    cookie_str = "; ".join(p for p in parts if p)
    if cookie_str:
        headers["Cookie"] = cookie_str
    return headers


# ── Network helpers ───────────────────────────────────────────────────────────

@dataclass
class Doc:
    """A piece of source text to scan: a JS file, or a file from a source map."""
    js_url: str                 # JS file this doc belongs to (for output)
    via: str                    # "" for the JS itself, else "<map> :: <source>"
    content: str
    origins: List[str]


@dataclass
class Endpoint:
    url: str
    templated: bool
    source_js: str
    via: str = ""


@dataclass
class Hit:
    method: str                 # "-" in --no-probe mode
    status: Optional[int]
    content_type: str
    length: int
    url: str
    source_js: str
    templated: bool
    via: str = ""


async def request_following(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: int,
    auth: Dict[str, str],
    target_host: str,
    handler: Callable[[aiohttp.ClientResponse], Awaitable[Optional[object]]],
    scope_enforced: bool,
) -> Optional[object]:
    """
    Send a request and follow redirects manually, checking every hop.
    - Auth headers go only to hosts in the target's scope.
    - With scope_enforced, a redirect to another host is not followed.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        on_target = in_scope(current, target_host)
        if scope_enforced and not on_target:
            return None
        headers = auth if (auth and on_target) else None
        async with session.request(
            method, current,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers=headers,
            allow_redirects=False,
        ) as resp:
            if resp.status in REDIRECT_CODES:
                location = resp.headers.get("Location")
                if not location:
                    return None
                current = urljoin(current, location)
                continue
            return await handler(resp)
    return None


def run_getjs(target: str) -> List[str]:
    """Run getJS for one target and return unique JS URLs."""
    log.info("getJS → %s", target)
    try:
        result = subprocess.run(
            ["getJS", "-url", target, "--complete"],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        log.warning("getJS timed out for %s", target)
        return []
    if result.returncode != 0 and not result.stdout.strip():
        log.warning("getJS failed for %s: %s", target, result.stderr.strip()[:200])
    return sorted({
        line.strip() for line in result.stdout.splitlines()
        if line.strip().startswith("http")
    })


async def read_capped(resp: aiohttp.ClientResponse, max_bytes: int) -> Tuple[bytes, bool]:
    """
    Read the whole body, up to max_bytes. Note: resp.content.read(n) may return
    fewer than n bytes (one network chunk), so it must not be used for full reads.
    Returns (data, truncated).
    """
    buf = bytearray()
    async for chunk in resp.content.iter_chunked(64 * 1024):
        buf += chunk
        if len(buf) > max_bytes:
            return bytes(buf[:max_bytes]), True
    return bytes(buf), False


async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int,
                     auth: Dict[str, str], target_host: str, scope_enforced: bool,
                     max_bytes: int) -> Optional[str]:
    """Download a text resource (redirects followed, size-limited)."""
    async def handler(resp: aiohttp.ClientResponse) -> Optional[str]:
        if resp.status != 200:
            log.debug("%s returned %s", url, resp.status)
            return None
        raw, truncated = await read_capped(resp, max_bytes)
        if truncated:
            log.warning("Too large, truncated at %d bytes: %s", max_bytes, url)
        return raw.decode("utf-8", errors="replace")

    try:
        return await request_following(session, "GET", url, timeout, auth,
                                       target_host, handler, scope_enforced)
    except Exception as e:
        log.warning("Fetch error %s: %s", url, e)
        return None


async def probe(session: aiohttp.ClientSession, ep: Endpoint, method: str,
                timeout: int, auth: Dict[str, str], delay: float,
                target_host: str, scope_enforced: bool) -> Optional[Hit]:
    """Return a Hit if the endpoint answers 200 with JSON/text content."""
    if delay:
        await asyncio.sleep(delay)

    async def handler(resp: aiohttp.ClientResponse) -> Optional[Hit]:
        if resp.status != 200:
            return None
        ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if not (ct in OK_CONTENT_TYPES or ct.endswith("+json")):
            return None

        if method == "HEAD":
            cl = resp.headers.get("Content-Length")
            length = int(cl) if cl and cl.isdigit() else -1   # -1 = unknown
            if length == 0:
                return None
        else:
            body = await resp.content.read(MAX_PROBE_BYTES)
            length = len(body)
            if length == 0:
                return None

        log.info("    [+] HIT %s %-18s %s%s", method, ct, ep.url,
                 "  (templated)" if ep.templated else "")
        return Hit(method, resp.status, ct, length, ep.url, ep.source_js,
                   ep.templated, ep.via)

    try:
        return await request_following(session, method, ep.url, timeout, auth,
                                       target_host, handler, scope_enforced)
    except Exception as e:
        log.debug("probe error %s %s: %s", method, ep.url, e)
        return None


def origins_for(js_url: str, origin: str, target_host: str, scope_enforced: bool) -> List[str]:
    """Origins used to resolve relative paths found in a JS file."""
    origins = {origin}
    js_origin = origin_of(js_url)
    if js_origin != origin and (not scope_enforced or in_scope(js_origin, target_host)):
        origins.add(js_origin)
    return sorted(origins)


WEBPACK_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:/*")


def candidate_source_urls(name: str, map_url: str, js_url: str) -> List[str]:
    """
    Для имён вида webpack:///./src/App/app.tsx самой адреса нет, но файл иногда
    лежит в корне сайта или рядом с картой. Возвращает до 3 кандидатов.
    Пути node_modules пропускаются.
    """
    path = WEBPACK_PREFIX_RE.sub("", name).split("?", 1)[0].split("#", 1)[0]
    while path.startswith(("./", "../")):
        path = path.split("/", 1)[1] if "/" in path else ""
    path = path.lstrip("/")
    if not path or "node_modules" in path.split("/"):
        return []
    candidates = [f"{origin_of(js_url)}/{path}", urljoin(map_url, path)]
    return list(dict.fromkeys(
        c for c in candidates if urlparse(c).scheme in ("http", "https")))[:3]


async def load_sourcemap_docs(
    session: aiohttp.ClientSession,
    ref: str,
    js_url: str,
    origins: List[str],
    target_host: str,
    auth: Dict[str, str],
    scope_enforced: bool,
    args: argparse.Namespace,
) -> List[Doc]:
    """Read a source map and return Docs for its sources (sourcesContent or fetched files)."""
    if ref.startswith("data:"):
        text = decode_data_uri(ref)
    else:
        text = await fetch_text(session, ref, args.timeout, auth, target_host,
                                False, MAX_MAP_BYTES)
    if not text:
        log.info("  [map] not available: %s", ref)
        return []

    try:
        entries = parse_sourcemap(text)
    except (ValueError, TypeError) as e:
        log.info("  [map] invalid source map %s: %s", ref, e)
        return []

    docs: List[Doc] = []
    to_fetch: List[Tuple[List[str], str]] = []
    map_url = ref if not ref.startswith("data:") else js_url
    for name, content in entries:
        via = f"{ref} :: {name}"
        if content:
            docs.append(Doc(js_url, via, content, origins))
            continue
        url = source_fetch_url(map_url, name)
        if url:
            to_fetch.append(([url], via))
            continue
        candidates = candidate_source_urls(name, map_url, js_url)   # webpack:/// и т.п.
        if candidates:
            to_fetch.append((candidates, via))

    if len(to_fetch) > args.max_sources:
        log.info("  [map] %d source files, fetching first %d (--max-sources)",
                 len(to_fetch), args.max_sources)
        to_fetch = to_fetch[:args.max_sources]

    log.info("  [map] %s: %d source(s) embedded, %d to fetch",
             ref, len(docs), len(to_fetch))

    sem = asyncio.Semaphore(args.threads)

    async def get(urls: List[str], via: str):
        async with sem:
            for url in urls:
                text = await fetch_text(session, url, args.timeout, auth, target_host,
                                        False, MAX_JS_BYTES)
                if not text:
                    continue
                if text.lstrip()[:20].lower().startswith(("<!doctype", "<html")):
                    continue                      # SPA fallback page, not source code
                return via, text
            return via, None

    for via, text in await asyncio.gather(*(get(u, v) for u, v in to_fetch)):
        if text:
            docs.append(Doc(js_url, via, text, origins))
    return docs


# ─── Cloud storage: Firebase / S3 / GCS / Azure Blob ──────────────────────────
# Облачные ресурсы из JS и source maps. Проверки без авторизации (чужие креды
# никуда не уходят): LIST и READ всегда, WRITE только с --check-cloud-write.

FIREBASE_RE = re.compile(
    r"https://([a-z0-9][a-z0-9-]{0,61}\.firebaseio\.com"
    r"|[a-z0-9][a-z0-9-]{0,61}\.[a-z0-9-]{1,40}\.firebasedatabase\.app)(?![a-z0-9-])",
    re.IGNORECASE)
S3_VHOST_RE = re.compile(
    r"https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)(?![a-z0-9-])"
    r"(?:/([^\s\"'`<>?#]*))?", re.IGNORECASE)
S3_PATH_RE = re.compile(
    r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"(?:/([^\s\"'`<>?#]*))?", re.IGNORECASE)
GCS_PATH_RE = re.compile(
    r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])"
    r"(?:/([^\s\"'`<>?#]*))?", re.IGNORECASE)
GCS_VHOST_RE = re.compile(
    r"https?://([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com(?![a-z0-9-])"
    r"(?:/([^\s\"'`<>?#]*))?", re.IGNORECASE)
AZURE_RE = re.compile(
    r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])"
    r"(?:/([^\s\"'`<>?#]*))?", re.IGNORECASE)
CLOUD_WRITE_OK = {"s3": (200,), "gcs": (200,), "azure": (201,), "firebase": (200,)}


def _clean_key(key: Optional[str]) -> Optional[str]:
    """Ключ объекта из JS. Шаблоны вида ${x} или {x} — не ключ, пропускаем."""
    if not key or re.search(r"[{}$]", key):
        return None
    return key.strip("/") or None


def extract_cloud_resources(content: str) -> List[Tuple[str, str, Optional[str]]]:
    """Возвращает [(kind, root, key)]. root — базовый URL, к нему дописываются пути."""
    out: List[Tuple[str, str, Optional[str]]] = []
    for m in FIREBASE_RE.finditer(content):
        out.append(("firebase", f"https://{m.group(1)}", None))
    for m in S3_VHOST_RE.finditer(content):
        out.append(("s3", f"https://{m.group(1)}", _clean_key(m.group(2))))  # host уже с регионом
    for m in S3_PATH_RE.finditer(content):
        out.append(("s3", f"https://s3.amazonaws.com/{m.group(1)}", _clean_key(m.group(2))))
    for m in GCS_PATH_RE.finditer(content):
        out.append(("gcs", f"https://storage.googleapis.com/{m.group(1)}", _clean_key(m.group(2))))
    for m in GCS_VHOST_RE.finditer(content):
        out.append(("gcs", f"https://{m.group(1)}.storage.googleapis.com", _clean_key(m.group(2))))
    for m in AZURE_RE.finditer(content):
        out.append(("azure", f"https://{m.group(1)}.blob.core.windows.net/{m.group(2)}",
                    _clean_key(m.group(3))))
    return out


def _data_ok(status: Optional[int], body: bytes) -> bool:
    """200 с содержимым, а не пустой ответ, null или XML/JSON-ошибка."""
    if status != 200:
        return False
    stripped = body.strip()
    if not stripped or stripped == b"null":
        return False
    return not stripped.startswith((b"<Error>", b'{"error"'))


async def _cloud_req(session: aiohttp.ClientSession, method: str, url: str, timeout: int,
                     body: Optional[bytes] = None,
                     headers: Optional[Dict[str, str]] = None) -> Optional[Tuple[int, str, bytes]]:
    try:
        async with session.request(method, url, data=body, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False) as resp:
            data = await resp.content.read(MAX_PROBE_BYTES)
            ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            return resp.status, ct, data
    except Exception as e:
        log.debug("cloud %s %s: %s", method, url, e)
        return None


async def _cloud_write_probe(session: aiohttp.ClientSession, kind: str, root: str, source_js: str,
                             via: str, timeout: int) -> List[Hit]:
    """Пишет тестовый объект с уникальным именем и сразу удаляет его."""
    probe_id = uuid.uuid4().hex
    headers: Dict[str, str] = {}
    if kind == "firebase":
        url = f"{root}/easm_probe/{probe_id}.json"
        body = b'"easm-write-probe"'
        headers["Content-Type"] = "application/json"
    else:
        url = f"{root}/easm-write-probe-{probe_id}.txt"
        body = b"easm write probe (authorized check, deleted right after)"
        headers["Content-Type"] = "text/plain"
        if kind == "azure":
            headers["x-ms-blob-type"] = "BlockBlob"

    got = await _cloud_req(session, "PUT", url, timeout, body=body, headers=headers)
    if not got or got[0] not in CLOUD_WRITE_OK[kind]:
        return []
    hit = Hit("WRITE", got[0], got[1], len(body), url, source_js, False, via)
    log.info("    [+] HIT WRITE %s", url)

    deleted = await _cloud_req(session, "DELETE", url, timeout)
    if not deleted or deleted[0] not in (200, 202, 204):
        status = deleted[0] if deleted else "нет ответа"
        log.warning("    [!] тестовый объект НЕ удалён, удали вручную: %s (ответ: %s)", url, status)
    return [hit]


async def check_cloud_root(session: aiohttp.ClientSession, kind: str, root: str, keys: List[str],
                           source_js: str, via: str, timeout: int, check_write: bool) -> List[Hit]:
    hits: List[Hit] = []

    # LIST и READ по корню (без авторизации)
    if kind == "firebase":
        list_url, list_ok = f"{root}/.json?shallow=true", _data_ok
        read_targets = [(f"{root}/.json", _data_ok)]
    elif kind == "azure":
        list_url, list_ok = f"{root}?restype=container&comp=list", \
            (lambda st, b: st == 200 and b"<EnumerationResults" in b)
        read_targets = []
    else:  # s3, gcs
        list_url, list_ok = f"{root}/?max-keys=10", \
            (lambda st, b: st == 200 and b"<ListBucketResult" in b)
        read_targets = []

    for key in keys:
        read_targets.append((f"{root}/{key}", _data_ok))

    got = await _cloud_req(session, "GET", list_url, timeout)
    if got and list_ok(got[0], got[2]):
        log.info("    [+] HIT LIST %s", list_url)
        hits.append(Hit("LIST", got[0], got[1], len(got[2]), list_url, source_js, False, via))

    for url, ok in read_targets:
        got = await _cloud_req(session, "GET", url, timeout)
        if got and ok(got[0], got[2]):
            log.info("    [+] HIT READ %s", url)
            hits.append(Hit("READ", got[0], got[1], len(got[2]), url, source_js, False, via))

    if check_write:
        hits += await _cloud_write_probe(session, kind, root, source_js, via, timeout)
    return hits


def collect_cloud_roots(docs: List["Doc"]) -> Dict[Tuple[str, str], Dict[str, object]]:
    """Группирует облачные ресурсы по (kind, root): ключи объектов и первый источник."""
    roots: Dict[Tuple[str, str], Dict[str, object]] = {}
    for doc in docs:
        try:
            found = extract_cloud_resources(doc.content)
        except Exception as e:
            log.warning("  cloud extraction failed for %s: %s", doc.js_url, e)
            continue
        for kind, root, key in found:
            g = roots.setdefault((kind, root), {"keys": [], "source": doc.js_url, "via": doc.via})
            if key and key not in g["keys"]:
                g["keys"].append(key)
    return roots


async def run_cloud_checks(session: aiohttp.ClientSession, roots: Dict, args: argparse.Namespace) -> List[Hit]:
    sem = asyncio.Semaphore(args.threads)

    async def one(item):
        (kind, root), g = item
        async with sem:
            return await check_cloud_root(session, kind, root, g["keys"], g["source"], g["via"],
                                          args.timeout, args.check_cloud_write)

    results = await asyncio.gather(*(one(item) for item in roots.items()))
    return [h for hs in results for h in hs]


async def process_target(target: str, js_urls: List[str], args: argparse.Namespace) -> List[Hit]:
    origin = origin_of(target)
    target_host = (urlparse(target).hostname or "").lower()
    auth: Dict[str, str] = args.auth
    scope_enforced = args.scope

    connector = aiohttp.TCPConnector(limit=args.threads, ssl=args.verify_tls)
    # Default cookie jar: cookies set by the site are sent back to it later.
    # aiohttp keeps them per domain, so they do not go to other hosts.
    async with aiohttp.ClientSession(headers=BASE_HEADERS, connector=connector) as session:
        # 0. drop JS from excluded hosts (e.g. Cloudflare beacon)
        skip_hosts = getattr(args, "skip_hosts", DEFAULT_SKIP_HOSTS)
        for u in js_urls:
            if is_skipped_host(u, skip_hosts):
                log.info("  skipped (excluded host): %s", u)
        js_urls = [u for u in js_urls if not is_skipped_host(u, skip_hosts)]

        # 1. download JS
        sem = asyncio.Semaphore(args.threads)

        async def fetch(u: str):
            async with sem:
                # JS is downloaded passively from any host (no auth goes off-target);
                # scope only limits which origins endpoints are probed on.
                return u, await fetch_text(session, u, args.timeout, auth, target_host,
                                           False, MAX_JS_BYTES)

        log.info("Downloading %d JS file(s)…", len(js_urls))
        js_results = await asyncio.gather(*(fetch(u) for u in js_urls))

        # 2. build the list of documents to scan: JS files and, optionally, their source maps
        docs: List[Doc] = []
        maps_seen: Set[str] = set()
        for js_url, content in js_results:
            if not content:
                continue
            origins = origins_for(js_url, origin, target_host, scope_enforced)
            docs.append(Doc(js_url, "", content, origins))

            if args.no_sourcemaps:
                continue
            ref = find_sourcemap_ref(content, js_url)
            if not ref or ref in maps_seen:
                continue
            if not ref.startswith("data:") and is_skipped_host(ref, skip_hosts):
                log.info("  skipped map (excluded host): %s", ref)
                continue
            maps_seen.add(ref)
            log.info("  [map] %s → %s", js_url, ref if not ref.startswith("data:") else "data: URI")
            docs += await load_sourcemap_docs(session, ref, js_url, origins, target_host,
                                              auth, scope_enforced, args)

        # 2b. корень домена (/): HTML нужен только для поиска облачных ресурсов
        html_docs: List[Doc] = []
        if not args.no_cloud:
            root_url = origin + "/"
            html = await fetch_text(session, root_url, args.timeout, auth, target_host,
                                    scope_enforced, MAX_JS_BYTES)
            if html:
                html_docs.append(Doc(root_url, "html /", html, [origin]))

        # 3. extract endpoints from every document
        endpoints: Dict[str, Endpoint] = {}
        for doc in docs:
            try:
                found = extract_endpoints(doc.content, doc.origins)
            except Exception as e:      # one bad file must not stop the whole scan
                log.warning("  extraction failed for %s (%s): %s", doc.js_url, doc.via or "js", e)
                continue
            label = f"  (via {doc.via})" if doc.via else ""
            log.info("  [%4d] %s%s", len(found), doc.js_url, label)
            for url, templated in found.items():
                ep = endpoints.get(url)
                if ep is None:
                    endpoints[url] = Endpoint(url, templated, doc.js_url, doc.via)
                else:
                    ep.templated = ep.templated or templated

        # 4. scope filter
        all_eps = sorted(endpoints.values(), key=lambda e: e.url)
        scoped = [ep for ep in all_eps
                  if not scope_enforced or in_scope(ep.url, target_host)]
        log.info("Endpoints: %d total, %d in scope, %d out of scope",
                 len(all_eps), len(scoped), len(all_eps) - len(scoped))
        for ep in all_eps:
            if scope_enforced and not in_scope(ep.url, target_host):
                log.debug("  out of scope, not probed: %s (from %s)", ep.url, ep.source_js)

        # облачные ресурсы из тех же документов (Firebase, S3, GCS, Azure)
        cloud_roots: Dict = {} if args.no_cloud else collect_cloud_roots(docs + html_docs)
        if cloud_roots:
            log.info("Cloud resources: %d root(s)", len(cloud_roots))

        if args.no_probe:
            return ([Hit("-", None, "", 0, ep.url, ep.source_js, ep.templated, ep.via)
                     for ep in scoped]
                    + [Hit("-", None, "", 0, root, g["source"], False, g["via"])
                       for (kind, root), g in cloud_roots.items()])

        cloud_hits: List[Hit] = []
        if cloud_roots:
            cloud_hits = await run_cloud_checks(session, cloud_roots, args)

        # 5. probe (templated paths skipped unless --probe-templated)
        to_probe = [ep for ep in scoped if not (args.skip_templated and ep.templated)]
        if len(to_probe) < len(scoped):
            log.info("Skipped %d templated path(s) (--skip-templated)", len(scoped) - len(to_probe))
        if not to_probe:
            return cloud_hits

        plan = [(ep, m) for ep in to_probe for m in args.methods]
        log.info("Probing %d request(s) with methods %s", len(plan), ",".join(args.methods))

        psem = asyncio.Semaphore(args.threads)

        async def check(ep: Endpoint, m: str):
            async with psem:
                return await probe(session, ep, m, args.timeout, auth, args.delay,
                                   target_host, scope_enforced)

        results = await asyncio.gather(*(check(ep, m) for ep, m in plan))
        return [h for h in results if h] + cloud_hits


# ── Output ────────────────────────────────────────────────────────────────────

class ResultWriter:
    """Writes results incrementally, dedups by (method, url) across all targets."""

    def __init__(self, txt_path: Path, jsonl_path: Optional[Path]):
        self.txt = txt_path
        self.jsonl = jsonl_path
        self.seen: Set[Tuple[str, str]] = set()
        self.urls_written: Set[str] = set()

    def write(self, hits: Iterable[Hit]) -> int:
        new: List[Hit] = []
        for h in hits:
            key = (h.method, h.url)
            if key not in self.seen:
                self.seen.add(key)
                new.append(h)
        if not new:
            return 0

        with self.txt.open("a") as f:           # plain URL list, one per line
            for h in new:
                if h.url not in self.urls_written:
                    f.write(h.url + "\n")
                    self.urls_written.add(h.url)

        if self.jsonl:
            with self.jsonl.open("a", encoding="utf-8") as f:
                for h in new:
                    f.write(json.dumps(asdict(h), ensure_ascii=False) + "\n")
        return len(new)


# ── Email / SES ───────────────────────────────────────────────────────────────

def send_email(subject: str, body_text: str, sender: str, recipient: str,
               aws_region: str, attachment_path: Optional[str] = None) -> bool:
    try:
        import boto3
    except ImportError:
        log.error("boto3 not installed. Run: pip install boto3")
        return False

    try:
        ses = boto3.client("ses", region_name=aws_region)
        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        if attachment_path:
            p = Path(attachment_path)
            if p.exists() and p.stat().st_size > 0:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(p.read_bytes())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f'attachment; filename="{p.name}"')
                msg.attach(part)
                log.info("Attaching %s (%d bytes)", p.name, p.stat().st_size)
            else:
                log.info("Attachment skipped: file missing or empty (%s)", attachment_path)

        resp = ses.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={"Data": msg.as_string()},
        )
        log.info("Email sent. MessageId: %s", resp["MessageId"])
        return True
    except Exception as e:
        log.error("Error sending email: %s", e)
        return False


def build_email_body(total: int, targets: int, duration: float) -> Tuple[str, str]:
    subject = (f"API Hunter — {total} result(s)" if total
               else "API Hunter — nothing found")
    body = (
        "API Hunter scan complete.\n"
        f"Targets: {targets}\n"
        f"Results: {total}\n"
        f"Duration: {duration:.1f}s\n"
        + ("The results file is attached.\n" if total else "No results were found.\n")
    )
    return subject, body


# ── CLI ───────────────────────────────────────────────────────────────────────

def load_targets(urls: Optional[List[str]], inputs: Optional[List[str]]) -> List[str]:
    raw: List[str] = list(urls or [])
    for filepath in inputs or []:
        try:
            with open(filepath, encoding="utf-8") as f:
                raw += [ln.strip() for ln in f
                        if ln.strip() and not ln.strip().startswith("#")]
        except FileNotFoundError:
            log.error("Input file not found: %s", filepath)
            sys.exit(1)

    seen: Set[str] = set()
    targets: List[str] = []
    for t in raw:
        if "://" not in t:
            t = "https://" + t
        if t not in seen:
            seen.add(t)
            targets.append(t)
    return targets


def setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Discover and probe API endpoints in JS files and source maps.")

    scan = p.add_argument_group("scan")
    scan.add_argument("-u", "--url", action="append", dest="urls", metavar="URL",
                      help="Target URL (repeatable)")
    scan.add_argument("-i", "--input", action="append", dest="inputs", metavar="FILE",
                      help="File with target URLs (repeatable)")
    scan.add_argument("-o", "--output", default="200_get.txt",
                      help="Plain list of confirmed URLs (default: 200_get.txt)")
    scan.add_argument("--jsonl", metavar="FILE",
                      help="Detailed results as JSON lines (method, status, type, source JS, via)")
    scan.add_argument("--append", action="store_true",
                      help="Do not clear output files before the run")
    scan.add_argument("-t", "--threads", type=int, default=15, help="Concurrency (default: 15)")
    scan.add_argument("--timeout", type=int, default=10, help="HTTP timeout, seconds (default: 10)")
    scan.add_argument("--delay", type=float, default=0.0,
                      help="Pause before each probe request, seconds (default: 0)")
    scan.add_argument("--no-probe", action="store_true",
                      help="Only extract endpoints, do not send requests to them")
    scan.add_argument("--skip-templated", action="store_true",
                      help="Do not probe paths with placeholders like {id} (probed by default)")
    scan.add_argument("--no-sourcemaps", action="store_true",
                      help="Do not look for sourceMappingURL / .map files")
    scan.add_argument("--skip-host", action="append", dest="skip_hosts", metavar="DOMAIN",
                      help="Do not download JS/maps from this domain or its subdomains "
                           "(repeatable). Cloudflare domains are excluded by default")
    scan.add_argument("--max-sources", type=int, default=200,
                      help="Max source files fetched per source map when sourcesContent is absent "
                           "(default: 200)")
    scan.add_argument("--scope", action="store_true",
                      help="Probe only endpoints on the target's registrable domain "
                           "(off by default, as in the original). Auth headers are always "
                           "sent only to the target's hosts")
    scan.add_argument("--methods", default="GET",
                      help="Comma-separated methods to try (default: GET)")
    scan.add_argument("--allow-unsafe-methods", action="store_true",
                      help="Allow POST/PUT/PATCH/DELETE, which may change data on the server")
    scan.add_argument("--verify-tls", action="store_true",
                      help="Verify TLS certificates (off by default)")

    auth = p.add_argument_group("auth", "Credentials are sent only to hosts in the target scope")
    auth.add_argument("-H", "--header", action="append", dest="headers", metavar="'Name: value'",
                      help="Extra request header (repeatable)")
    auth.add_argument("--cookie", action="append", dest="cookies", metavar="'name=value; ...'",
                      help="Cookie string (repeatable)")

    email = p.add_argument_group("email", "Optional: send results via AWS SES")
    email.add_argument("--email-sender", metavar="EMAIL",
                       help="Sender address (must be verified in SES)")
    email.add_argument("--email-recipient", metavar="EMAIL", help="Recipient address")
    email.add_argument("--aws-region", default="eu-central-1",
                       help="AWS region for SES (default: eu-central-1)")

    cloud = p.add_argument_group("cloud", "Firebase / S3 / GCS / Azure Blob checks (no auth sent)")
    cloud.add_argument("--no-cloud", action="store_true",
                       help="Do not extract or check cloud storage resources")
    cloud.add_argument("--check-cloud-write", "-check-cloud-write", action="store_true", dest="check_cloud_write",
                       help="Also test WRITE: PUT a unique probe object and DELETE it right after. "
                            "Changes data on the target storage, use only where authorized")

    p.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    p.add_argument("-q", "--quiet", action="store_true", help="Only warnings and errors")

    args = p.parse_args()

    if not args.urls and not args.inputs:
        p.print_help()
        sys.exit(1)
    if bool(args.email_sender) != bool(args.email_recipient):
        p.error("--email-sender and --email-recipient must be provided together.")

    args.methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    unsafe = set(args.methods) - SAFE_METHODS
    if unsafe and not args.allow_unsafe_methods:
        p.error(f"Methods {', '.join(sorted(unsafe))} can change data on the server. "
                "Add --allow-unsafe-methods if the target is authorized for this.")

    args.skip_hosts = DEFAULT_SKIP_HOSTS + [h.lower().strip(".") for h in (args.skip_hosts or [])]

    try:
        args.auth = build_auth_headers(args.headers, args.cookies)
    except ValueError as e:
        p.error(str(e))

    return args


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose, args.quiet)

    if shutil.which("getJS") is None:
        log.error("getJS not found. Install: go install github.com/003random/getJS@latest")
        sys.exit(1)

    targets = load_targets(args.urls, args.inputs)
    if not targets:
        log.warning("No targets found.")
        return

    out_path = Path(args.output)
    jsonl_path = Path(args.jsonl) if args.jsonl else None
    if not args.append:
        out_path.write_text("")
        if jsonl_path:
            jsonl_path.write_text("")
    writer = ResultWriter(out_path, jsonl_path)

    if args.auth:
        log.info("Auth headers go only to target hosts: %s (values hidden)",
                 ", ".join(args.auth))
    if not args.scope:
        log.info("Endpoints are probed on any host (use --scope to limit to the target's domain)")
    mode = "extract only" if args.no_probe else f"extract + probe ({','.join(args.methods)})"
    maps = "off" if args.no_sourcemaps else "on"
    log.info("%d target(s), mode: %s, source maps: %s", len(targets), mode, maps)

    start = datetime.now()
    total = 0
    try:
        for i, target in enumerate(targets, 1):
            log.info("\n[%d/%d] %s", i, len(targets), target)
            js_urls = run_getjs(target)
            log.info("JS files found: %d", len(js_urls))
            if not js_urls:
                continue
            hits = asyncio.run(process_target(target, js_urls, args))
            total += writer.write(hits)   # saved after each target
    except KeyboardInterrupt:
        log.warning("Interrupted. Results gathered so far are saved.")

    duration = (datetime.now() - start).total_seconds()
    log.info("\nDone in %.1fs. New results: %d → %s", duration, total, out_path.resolve())

    if args.email_sender:
        log.info("Sending email to %s…", args.email_recipient)
        subject, body = build_email_body(total, len(targets), duration)
        send_email(subject, body, args.email_sender, args.email_recipient,
                   args.aws_region, attachment_path=str(out_path))


if __name__ == "__main__":
    main()

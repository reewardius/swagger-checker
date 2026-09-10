#!/usr/bin/env python3
"""
JS Security Analyzer — Full Pipeline
=====================================
Запуск (готовый список URL/хостов):
    python3 js_analyzer.py scan --urls alive_http_services_advanced.txt

Запуск (только корневые домены — поддомены собираются автоматически через
SecurityTrails):
    python3 js_analyzer.py scan -f root.txt

Что происходит автоматически:
  0. subdomains → (только с -f/--roots) для каждого домена из файла
               запрашивает поддомены через SecurityTrails API
  1. getJS   → собирает все JS-ссылки с хостов (из -f/--roots или --urls)
  2. merge   → объединяет оригинальные URL + JS-ссылки (дедупликация)
               сохраняет объединённый список в <input>_scan_targets.txt
  3. scan    → сканирует все URL на секреты / sensitive patterns
  4. excel   → генерирует отчёт findings.xlsx
  5. email   → отправляет отчёт через AWS SES

Дополнительные опции:
    -f, --roots FILE     Файл с корневыми доменами — поддомены собираются
                          автоматически через SecurityTrails (вместо --urls)
    -k, --st-api-key KEY API-ключ SecurityTrails (или переменная ST_API_KEY)
    --children-only       SecurityTrails: только прямые поддомены (без вложенных)
    --concurrency N       Параллельных HTTP запросов (default: 10)
    --severity LEVEL      Минимальный severity: CRITICAL/HIGH/MEDIUM/LOW (default: LOW)
    --getjs-threads N     Потоки для getJS (default: 50)
    --no-getjs            Пропустить этап getJS, сканировать только исходный список
    --no-email            Не отправлять письмо
    --excel FILE          Путь к Excel-отчёту (default: findings.xlsx)
    --json FILE           Дополнительно сохранить JSON-отчёт
    --email-domains D1,D2 Искать email на указанных доменах (по умолчанию выключено)

Dependencies:
    pip install aiohttp tqdm openpyxl boto3 requests
    go install github.com/003random/getJS@latest
"""

import re
import sys
import time
import asyncio
import aiohttp
import requests
import json
import base64
import argparse
import subprocess
import tempfile
import os
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional
from tqdm import tqdm

# ─── Config ───────────────────────────────────────────────────────────────────

SES_SENDER    = "appsec@fozzy.ua"
SES_RECIPIENT = "dmytr.lysenko@temabit.com"
SES_REGION    = "eu-central-1"

SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"

# ─── Severity levels ──────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

SEVERITY_COLOR = {
    CRITICAL: "\033[91m",
    HIGH:     "\033[93m",
    MEDIUM:   "\033[94m",
    LOW:      "\033[96m",
}
SEVERITY_ICON = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵"}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[92m"
DIM   = "\033[2m"

# ─── Patterns ─────────────────────────────────────────────────────────────────

PATTERNS: list[tuple[str, str, str]] = [
    # Passwords
    (CRITICAL, "Password / In URL DSN",
     r'https?://[A-Za-z0-9._%-]{2,}:([^@\s"\'`]{4,})@[A-Za-z0-9._-]{4,}'),
    (CRITICAL, "Password / Field Assignment",
     r'(?<![A-Za-z])(?:password|passwd|pwd|user[_-]?pass(?:word)?)\s*[=:]\s*["\']([^"\']{4,})["\']'),

    # Usernames
    (HIGH, "Username / Field Assignment",
     r'(?<![A-Za-z])(?:username|user_name)\s*[=:]\s*["\']([^"\']{4,})["\']'),

    # Secrets
    (CRITICAL, "Secret / Generic Field",
     r'(?:secret|client[_-]?secret|app[_-]?secret|consumer[_-]?secret|shared[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    (CRITICAL, "Secret / Private Key Field",
     r'(?:private[_-]?key|privateKey|priv[_-]?key)\s*[=:]\s*["\']([^"\']{10,})["\']'),
    (CRITICAL, "Secret / PEM Block",
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    (CRITICAL, "Secret / PGP Private Key Block",
     r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    (CRITICAL, "Secret / JWT Signing Key",
     r'(?:jwt[_-]?secret|jwtSecret|jwt[_-]?key|signing[_-]?secret)\s*[=:]\s*["\']([^"\']{6,})["\']'),
    (HIGH, "Secret / Base64 Encoded Value",
     r'(?:secret|key|password|credential)\s*[=:]\s*["\']([A-Za-z0-9+/]{32,}={0,2})["\']'),

    # API Keys
    (CRITICAL, "API Key / Generic",
     r'(?:api[_-]?key|apikey|access[_-]?key|x-api-key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
    (HIGH, "API Key / Bearer Token Hardcoded",
     r'[Bb]earer\s+([A-Za-z0-9_\-\.~+/]{20,})'),
    (HIGH, "API Key / Token Field",
     r'(?:auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
    (HIGH, "API Key / Raw JWT Token",
     r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),

    # Databases
    (CRITICAL, "Database / Connection String with Credentials",
     r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)://[^:]+:[^@\s"\'`]{4,}@[^\s"\'`]+'),
    (HIGH, "Database / Password Field",
     r'(?:db[_-]?pass(?:word)?|database[_-]?pass(?:word)?)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    (HIGH, "Database / Connection String (no creds)",
     r'(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp)://[^\s"\'`]{8,}'),

    # Cloud
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

    # Git / CI hosting
    (CRITICAL, "Cloud / GitHub Fine-Grained PAT",
     r'github_pat_[A-Za-z0-9_]{82}'),
    (CRITICAL, "Cloud / GitLab Personal Access Token",
     r'glpat-[A-Za-z0-9\-_]{20}'),
    (HIGH, "Cloud / Terraform Cloud Token",
     r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}'),
    (HIGH, "Cloud / Postman API Key",
     r'PMAK-[a-f0-9]{24}-[a-f0-9]{34}'),

    # OAuth / identity secrets
    (CRITICAL, "Cloud / Google OAuth Client Secret",
     r'GOCSPX-[A-Za-z0-9_-]{28}'),
    (HIGH, "Cloud / Google OAuth Refresh Token",
     r'\b1//[0-9A-Za-z_-]{35,}\b'),
    (HIGH, "Cloud / Facebook Graph API Token",
     r'(?:access[_-]?token|fb[_-]?access[_-]?token|facebook[_-]?access[_-]?token|'
     r'page[_-]?access[_-]?token|graph[_-]?api[_-]?token)\s*[=:]\s*'
     r'["\'](EAA[A-Za-z0-9]{50,})["\']'),
    (HIGH, "Cloud / Okta API Token",
     r'(?<![A-Za-z0-9])00[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-])'),
    (HIGH, "Cloud / HashiCorp Vault Token",
     r'\bhvs\.[A-Za-z0-9]{90,100}\b'),

    # SaaS dev-tool tokens
    (HIGH, "Cloud / Notion Integration Token",
     r'secret_[A-Za-z0-9]{43}'),
    (HIGH, "Cloud / Sentry Auth Token",
     r'sntrys_[A-Za-z0-9_+/=]{60,}'),
    (HIGH, "Cloud / Linear API Key",
     r'lin_api_[A-Za-z0-9]{40}'),
    (HIGH, "Cloud / Twitter(X) Bearer Token",
     r'(?:bearer[_-]?token|twitter[_-]?bearer|x[_-]?bearer[_-]?token)\s*[=:]\s*'
     r'["\'](AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,})["\']'),

    # AI providers
    (CRITICAL, "AI / OpenAI API Key",
     r'sk-proj-[A-Za-z0-9_-]{20,}'),
    (CRITICAL, "AI / Anthropic API Key",
     r'sk-ant-[A-Za-z0-9_-]{20,}'),

    # Infra / registries
    (CRITICAL, "Cloud / DigitalOcean Personal Access Token",
     r'dop_v1_[a-f0-9]{64}'),
    (HIGH, "Cloud / Docker Hub Access Token",
     r'dckr_pat_[A-Za-z0-9_-]{27,}'),
    (HIGH, "Cloud / PyPI API Token",
     r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'),
    (HIGH, "Cloud / New Relic License Key",
     r'NRAK-[A-Z0-9]{27}'),

    # Payments
    (CRITICAL, "Payment / PayPal-Braintree Access Token",
     r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
    (CRITICAL, "Payment / Square Access Token",
     r'sq0atp-[A-Za-z0-9_-]{22}'),
    (CRITICAL, "Payment / Square OAuth Secret",
     r'sq0csp-[A-Za-z0-9_-]{43}'),

    # Communications
    (HIGH, "Cloud / Discord Bot Token",
     r'\b[MN][A-Za-z\d_-]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}\b'),
]

# ─── Email / internal-domain patterns (opt-in via --email-domains) ────────────
# Не добавляются в PATTERNS по умолчанию — активны только когда пользователь
# явно передал --email-domains. Категория всегда начинается с "Email / ",
# это используется в analyze_content() чтобы обойти is_trivial() (email
# адреса содержат точки/@ и без этого попадут под фильтр минифицированного JS).

EMAIL_SEVERITY = MEDIUM
EXTRA_PATTERNS: list[tuple[str, str, str]] = []
EMAIL_DOMAINS: list[str] = []  # для вывода в статистике (EXTRA_PATTERNS всегда содержит 1 объединённый regex)

def build_email_patterns(domains: list[str]) -> list[tuple[str, str, str]]:
    """
    Один regex на ВСЕ домены (альтернация), а не по паттерну на каждый домен —
    иначе с ростом числа доменов сканирование линейно замедляется, т.к. каждый
    паттерн — это отдельный полный проход по содержимому файла.
    Конкретный домен, под который подошло совпадение, извлекается из самого
    совпадения (после @) на этапе анализа — категория присваивается динамически.
    """
    clean = [d.strip().lstrip("@") for d in domains if d.strip()]
    if not clean:
        return []
    alternation = "|".join(re.escape(d) for d in clean)
    pattern = r'[A-Za-z0-9._%+-]+@(?:' + alternation + r')\b'
    return [(EMAIL_SEVERITY, "Email / Internal Domain", pattern)]

# ─── False-positive filter ────────────────────────────────────────────────────

# Общая проверка "это значение целиком выглядит как JWT" — используется и
# в is_trivial() (чтобы не отбрасывать JWT как минифицированный JS-код),
# и в analyze_content() (чтобы generic-паттроны типа "Token Field" / "Bearer
# Token" не дублировали находку, которую уже покрывает "Raw JWT Token").
_JWT_FULL_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')

IGNORE_SUBSTRINGS = {
    'undefined', 'null', 'true', 'false', 'none', 'empty', 'placeholder',
    'your_password', 'your_secret', 'your_api_key', 'changeme', 'change_me',
    'example', 'test', 'demo', 'sample', 'dummy', 'fake', 'mock',
    'xxxxxxxx', '********', '{{', '${', '__', 'insert_', 'replace_',
    'todo', 'fixme', 'fill_in', '<your', '[your', 'n/a',
    'password', 'passwd', 'pwd', 'username', 'user_name', 'secret', 'token',
    'new_password', 'old_password', 'confirm_password', 'repeat_password',
    '%filtered%', '%s', '%(', 'redacted', 'censored', 'hidden',
}

UNICODE_LABEL_WORDS = {
    '\u041f\u0430\u0440\u043e\u043b\u044c', '\u043f\u0430\u0440\u043e\u043b\u044c',
    '\u041b\u043e\u0433\u0438\u043d',        '\u043b\u043e\u0433\u0438\u043d',
    '\u041f\u043e\u0447\u0442\u0430',
}

def is_trivial(value: str) -> bool:
    v = value.strip()
    if len(v) < 4: return True
    if len(set(v.lower())) <= 2: return True

    # ── Known real-secret prefixes — bypass all other checks ─────────────────
    SAFE_PREFIXES = (
        'AKIA', 'sk_live_', 'sk_test_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
        'SG.', 'xox', 'npm_', 'shpat_', 'AIza', 'key-',
        'sk-proj-', 'sk-ant-', 'dop_v1_', 'dckr_pat_', 'pypi-AgEIcHlwaS5vcmc',
        'NRAK-', 'sq0atp-', 'sq0csp-',
        'github_pat_', 'glpat-', 'PMAK-', 'GOCSPX-', 'secret_', 'sntrys_',
        'lin_api_', 'EAA', 'AAAAAAAAAAAAAAAAAAAAA',
    )
    if any(v.startswith(p) for p in SAFE_PREFIXES): return False
    # Raw JWT (header.payload.signature, header/payload are base64 JSON → start with "eyJ")
    if _JWT_FULL_RE.match(v): return False
    # Discord bot token (contains dots, would otherwise hit the JS-expression filter below)
    if re.match(r'^[MN][A-Za-z\d_-]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}$', v): return False
    # PayPal/Braintree access token (contains $, fixed structure)
    if re.match(r'^access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}$', v): return False
    # DB connection strings with credentials — always keep
    if re.match(r'^[a-z+]+://\S+:\S+@\S+', v): return False
    # HashiCorp Vault token (contains a dot right after "hvs", would otherwise
    # hit the JS-expression filter below)
    if re.match(r'^hvs\.[A-Za-z0-9]{90,100}$', v): return False
    # Terraform Cloud/Enterprise token (contains ".atlasv1.", same reason)
    if re.match(r'^[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}$', v): return False

    if any(ign in v.lower() for ign in IGNORE_SUBSTRINGS): return True
    if v in UNICODE_LABEL_WORDS: return True
    if re.match(r'^(\\u[0-9a-fA-F]{4})+$', v): return True
    if re.match(r'^[A-Z][A-Za-z]{3,}$', v): return True
    if re.match(r'^[a-z]+[A-Z][A-Za-z]+$', v): return True
    if re.match(r'^[a-z_]+$', v): return True

    # ── Minified JS false-positive filters ───────────────────────────────────
    # JS punctuation that cannot appear in a real credential
    if re.search(r'[(){}\[\];!?]', v): return True
    # JS expressions: word.word(), ternary ?word
    if re.search(r'\w\.\w|\w\(|\?\w', v): return True
    # High ratio of chars that don't appear in real secrets
    special = re.sub(r'[-_.+/=A-Za-z0-9]', '', v)
    if len(v) > 0 and len(special) / len(v) > 0.3: return True

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

# Раньше PATTERNS/EXTRA_PATTERNS компилировались заново для КАЖДОГО скачанного
# файла внутри analyze_content — при сотнях JS-файлов это сотни лишних
# re.compile() на каждый паттерн. Теперь компилируем один раз и переиспользуем.
_COMPILED_PATTERNS_CACHE: Optional[list[tuple[str, str, "re.Pattern"]]] = None

def precompile_patterns() -> None:
    global _COMPILED_PATTERNS_CACHE
    compiled = []
    for severity, category, pattern in PATTERNS + EXTRA_PATTERNS:
        try:
            compiled.append((severity, category, re.compile(pattern, re.IGNORECASE)))
        except re.error:
            continue
    _COMPILED_PATTERNS_CACHE = compiled

def get_compiled_patterns() -> list[tuple[str, str, "re.Pattern"]]:
    if _COMPILED_PATTERNS_CACHE is None:
        precompile_patterns()
    return _COMPILED_PATTERNS_CACHE

# ── JWT payload decode-and-rescan ───────────────────────────────────────────
# Секреты/email внутри JWT claims (upn, email, custom claims) не видны как
# обычный текст в исходнике — только после base64url-декодирования payload
# части токена. Поэтому каждый найденный JWT дополнительно декодируется и
# его payload прогоняется через ВСЕ активные паттерны (включая --email-domains).

_JWT_STRUCTURE_RE = re.compile(
    r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
)

def _b64url_decode(segment: str) -> Optional[str]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="ignore")
    except Exception:
        return None

def scan_jwt_payloads(content: str, min_order: int) -> list[Finding]:
    extra: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for m in _JWT_STRUCTURE_RE.finditer(line):
            parts = m.group(0).split(".")
            if len(parts) < 2:
                continue
            decoded = _b64url_decode(parts[1])
            if not decoded or '"' not in decoded:
                continue
            for severity, category, compiled in get_compiled_patterns():
                if SEVERITY_ORDER[severity] > min_order:
                    continue
                is_email_pattern = category == "Email / Internal Domain"
                for dm in compiled.finditer(decoded):
                    value = dm.group(1) if dm.lastindex else dm.group(0)
                    if not is_email_pattern and is_trivial(value):
                        continue
                    finding_category = category
                    if is_email_pattern and "@" in value:
                        finding_category = f"Email / {value.rsplit('@', 1)[-1]}"
                    extra.append(Finding(
                        severity=severity,
                        category=f"{finding_category} (в JWT payload)",
                        match=value[:250],
                        line_number=line_num,
                        line_content=line.strip()[:350],
                    ))
    return extra

# ── HTTP Basic Auth header decode-and-rescan ────────────────────────────────
# "Authorization: Basic <base64>" кодирует "user:password" — сам base64-блок
# не матчится ни одним generic-паттерном (нет разделителей), поэтому его
# нужно отдельно найти по контексту заголовка, декодировать и, если внутри
# действительно есть "user:pass", зарепортить как находку.

_BASIC_AUTH_RE = re.compile(
    r'(?:Authorization|authorization)["\']?[)\]]?\s*[:=,]\s*["\']?Basic\s+([A-Za-z0-9+/]{8,}={0,2})'
)

def scan_basic_auth(content: str) -> list[Finding]:
    extra: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for m in _BASIC_AUTH_RE.finditer(line):
            token = m.group(1)
            padded = token + "=" * (-len(token) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            except Exception:
                continue
            # Настоящий Basic Auth — это "user:pass"; без ':' это, скорее
            # всего, случайно похожий на base64 мусор, а не реальный заголовок.
            if ":" not in decoded or is_trivial(decoded.split(":", 1)[1]):
                continue
            extra.append(Finding(
                severity=CRITICAL,
                category="Password / HTTP Basic Auth Header (decoded)",
                match=decoded[:250],
                line_number=line_num,
                line_content=line.strip()[:350],
            ))
    return extra

def analyze_content(content: str, min_severity: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    min_order = SEVERITY_ORDER[min_severity]

    for severity, category, compiled in get_compiled_patterns():
        if SEVERITY_ORDER[severity] > min_order:
            continue
        is_email_pattern = category == "Email / Internal Domain"
        is_jwt_pattern   = category == "API Key / Raw JWT Token"
        for line_num, line in enumerate(lines, start=1):
            for m in compiled.finditer(line):
                value = m.group(1) if m.lastindex else m.group(0)
                # Значение целиком выглядит как JWT — пусть его репортит только
                # специализированное правило "Raw JWT Token", а не generic
                # правила (Token Field, Bearer Token, API Key), иначе дублирование.
                if not is_jwt_pattern and _JWT_FULL_RE.match(value):
                    continue
                # is_trivial() эвристики заточены под "похоже на секрет";
                # email-адреса (точки, @) под них не подходят и не должны фильтроваться.
                if not is_email_pattern and is_trivial(value):
                    continue
                finding_category = category
                if is_email_pattern and "@" in value:
                    finding_category = f"Email / {value.rsplit('@', 1)[-1]}"
                findings.append(Finding(
                    severity=severity,
                    category=finding_category,
                    match=value[:250],
                    line_number=line_num,
                    line_content=line.strip()[:350],
                ))

    findings.extend(scan_jwt_payloads(content, min_order))
    findings.extend(scan_basic_auth(content))

    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.category, f.match)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line_number))
    return unique

# ─── URL normalization ─────────────────────────────────────────────────────────

def normalize_url(raw: str) -> str:
    """Ensure URL has scheme and at least '/' as path so the root is scanned.

    Also required before handing hosts to getJS: it parses -input lines with
    Go's raw url.Parse() and does NOT add a scheme itself — a bare hostname
    like "www.example.com" parses "successfully" into a malformed URL, then
    silently fails at request time ("unsupported protocol scheme"), and that
    failure is swallowed unless getJS is run with -verbose. So any host list
    that didn't already come with a scheme (e.g. raw SecurityTrails output)
    must be normalized through this function before it reaches getJS.
    """
    raw = raw.strip()
    if not urlparse(raw).scheme:
        raw = "https://" + raw
    p = urlparse(raw)
    # If no path at all, default to /
    if not p.path:
        raw = p._replace(path="/").geturl()
    return raw

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
                return FileResult(url=url, status="error", error=f"HTTP {resp.status}")
            text = await resp.text(errors="replace")
        findings = analyze_content(text, min_severity)
        return FileResult(url=url, status="ok", findings=findings)
    except asyncio.TimeoutError:
        return FileResult(url=url, status="error", error="Timeout")
    except Exception as e:
        return FileResult(url=url, status="error", error=str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — SecurityTrails: root domains → subdomains
# ═══════════════════════════════════════════════════════════════════════════════

def get_subdomains(domain: str, api_key: str, children_only: bool = False) -> list[str]:
    """
    Запрашивает поддомены для указанного домена через SecurityTrails API.
    https://docs.securitytrails.com/reference/domain-subdomains

    :param domain: основной домен, например 'example.com'
    :param api_key: API-ключ SecurityTrails
    :param children_only: True — только прямые поддомены (без вложенных)
    :return: список полных доменных имён (subdomain + '.' + domain)
    """
    headers = {
        "Accept": "application/json",
        "APIKEY": api_key,
    }
    params = {"children_only": str(children_only).lower()}

    resp = requests.get(
        SECURITYTRAILS_API_URL.format(domain=domain),
        headers=headers,
        params=params,
        timeout=15,
    )

    if resp.status_code == 429:
        # Превышен лимит запросов — ждём и пробуем ещё раз
        retry_after = int(resp.headers.get("Retry-After", 5))
        print(f"  {SEVERITY_COLOR[MEDIUM]}[!] Rate limit на {domain}, повтор через {retry_after} сек...{RESET}")
        time.sleep(retry_after)
        return get_subdomains(domain, api_key, children_only)

    resp.raise_for_status()
    data = resp.json()

    subdomains = data.get("subdomains", [])
    return [f"{s}.{domain}" if s else domain for s in subdomains]

def step_subdomains(roots_file: str, api_key: str, children_only: bool, save_path: str) -> list[str]:
    """
    Читает корневые домены из roots_file, для каждого запрашивает поддомены
    через SecurityTrails, объединяет и дедуплицирует результат.
    Сохраняет полный список в save_path для аудита.
    """
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [1/6] SecurityTrails — enumerating subdomains{RESET}")
    print(f"{'─'*72}")

    try:
        with open(roots_file, encoding="utf-8") as fh:
            roots = list(dict.fromkeys(
                l.strip() for l in fh if l.strip() and not l.strip().startswith("#")
            ))
    except OSError as e:
        print(f"  {SEVERITY_COLOR[CRITICAL]}✗  Не удалось прочитать {roots_file}: {e}{RESET}")
        return []

    if not roots:
        print(f"  {SEVERITY_COLOR[CRITICAL]}✗  Файл с корневыми доменами пуст.{RESET}")
        return []

    print(f"  Root domains: {len(roots)}")
    print(f"  Children only: {children_only}\n")

    all_subdomains: list[str] = []
    for domain in roots:
        try:
            found = get_subdomains(domain, api_key, children_only)
        except requests.HTTPError as e:
            print(f"  {SEVERITY_COLOR[HIGH]}⚠  {domain}: HTTP ошибка — {e}{RESET}")
            continue
        except requests.RequestException as e:
            print(f"  {SEVERITY_COLOR[HIGH]}⚠  {domain}: ошибка запроса — {e}{RESET}")
            continue

        print(f"  {GREEN}✓  {domain}: {len(found)} поддомен(ов){RESET}")
        all_subdomains.extend(found)

    # Дедупликация с сохранением порядка
    all_subdomains = list(dict.fromkeys(all_subdomains))

    # SecurityTrails отдаёт голые хостнеймы без схемы (www.example.com).
    # getJS парсит -input построчно через Go url.Parse() и НЕ добавляет схему
    # сам — без http(s):// он тихо ничего не найдёт (см. normalize_url()).
    # Поэтому сохраняем и возвращаем уже нормализованный список.
    normalized = list(dict.fromkeys(normalize_url(s) for s in all_subdomains))

    with open(save_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(normalized))

    print(f"\n  {GREEN}✓  {len(normalized)} уникальных поддоменов{RESET}")
    print(f"  Saved to     : {save_path}")
    return normalized

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — getJS
# ═══════════════════════════════════════════════════════════════════════════════

def step_getjs(input_file: str, threads: int = 50) -> list[str]:
    """
    Запускает getJS против всех хостов из input_file.
    Возвращает список собранных JS URL.
    Требуется: go install github.com/003random/getJS@latest
    """
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [2/6] getJS — collecting JS file URLs{RESET}")
    print(f"{'─'*72}")
    print(f"  Input  : {input_file}")
    print(f"  Threads: {threads}")

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="getjs_out_")
    os.close(tmp_fd)

    cmd = ["getJS", "-input", input_file, "-output", tmp_path,
           "-complete", "-threads", str(threads)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print(f"  {SEVERITY_COLOR[CRITICAL]}✗  'getJS' not found in PATH.{RESET}")
        print("     Install: go install github.com/003random/getJS@latest")
        os.unlink(tmp_path)
        return []
    except subprocess.TimeoutExpired:
        print(f"  {SEVERITY_COLOR[CRITICAL]}✗  getJS timed out (10 min).{RESET}")
        os.unlink(tmp_path)
        return []

    if proc.returncode != 0 and proc.stderr:
        print(f"  {SEVERITY_COLOR[HIGH]}⚠  getJS stderr: {proc.stderr[:300]}{RESET}")

    js_urls: list[str] = []
    try:
        with open(tmp_path, encoding="utf-8", errors="replace") as fh:
            js_urls = [l.strip() for l in fh if l.strip() and l.strip().startswith("http")]
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    print(f"  {GREEN}✓  {len(js_urls)} JS URLs discovered{RESET}")
    return js_urls

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Merge & deduplicate
# ═══════════════════════════════════════════════════════════════════════════════

def step_merge(original_urls: list[str], js_urls: list[str], save_path: str) -> list[str]:
    """
    Объединяет оригинальные URL + JS-ссылки, дедуплицирует.
    Сохраняет результат в save_path для аудита.
    """
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [3/6] Merge — combining URL lists{RESET}")
    print(f"{'─'*72}")

    combined = list(dict.fromkeys(original_urls + js_urls))

    with open(save_path, "w", encoding="utf-8") as fh:
        for u in combined:
            fh.write(u + "\n")

    print(f"  Original URLs : {len(original_urls)}")
    print(f"  JS URLs       : {len(js_urls)}")
    print(f"  {GREEN}Combined (dedup): {len(combined)}{RESET}")
    print(f"  Saved to      : {save_path}")
    return combined

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Scan
# ═══════════════════════════════════════════════════════════════════════════════

async def step_scan(urls: list[str], concurrency: int, severity: str) -> list[FileResult]:
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [4/6] Scan — searching for secrets{RESET}")
    print(f"{'─'*72}")
    print(f"  URLs    : {len(urls)}")
    print(f"  Threads : {concurrency}")
    print(f"  Min sev : {severity}")
    print(f"  Patterns: {len(PATTERNS) + len(EXTRA_PATTERNS)}"
          f"{f' (+ email: {len(EMAIL_DOMAINS)} domain(s) — ' + ', '.join(EMAIL_DOMAINS) + ')' if EMAIL_DOMAINS else ''}\n")

    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

    async def guarded_fetch(session: aiohttp.ClientSession, url: str, pbar: tqdm):
        async with sem:
            r = await fetch_and_analyze(session, url, severity)
            if r.findings:
                lines = [
                    f"\n{'═'*72}",
                    f"  {BOLD}{r.url}{RESET}",
                    f"  {SEVERITY_COLOR[CRITICAL]}{BOLD}⚠  {len(r.findings)} finding(s){RESET}",
                ]
                grouped: dict[str, list[Finding]] = {}
                for f in r.findings:
                    grouped.setdefault(f.category, []).append(f)
                for category, items in grouped.items():
                    sev  = items[0].severity
                    col  = SEVERITY_COLOR[sev]
                    icon = SEVERITY_ICON[sev]
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
            total=len(urls), desc="Scanning", unit="file",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}",
            colour="cyan",
        ) as pbar:
            tasks = [guarded_fetch(session, u, pbar) for u in urls]
            results = await asyncio.gather(*tasks)

    return list(results)

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Excel report
# ═══════════════════════════════════════════════════════════════════════════════

def step_excel(results: list[FileResult], path: str) -> bool:
    """
    Генерирует Excel-отчёт.
    Лист "Findings": URL | Severity | Category | Value | Line
    Лист "Summary":  scan metadata + счётчики по severity
    """
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [5/6] Excel — generating report{RESET}")
    print(f"{'─'*72}")

    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("  openpyxl not installed. Run: pip install openpyxl")
        return False

    FILL = {
        CRITICAL: "FFB3B3",
        HIGH:     "FFD9A0",
        MEDIUM:   "FFF3A3",
        LOW:      "B3D9FF",
    }
    FILL_HDR   = "1F3864"
    FILL_TOTAL = "2E4A7A"
    F_HDR      = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
    F_DATA     = Font(name="Calibri", size=10)
    F_TOT      = Font(name="Calibri", bold=True, color="FFFFFF", size=10)
    F_META_LBL = Font(name="Calibri", bold=True, size=10)
    F_META_VAL = Font(name="Calibri", size=10)
    WRAP       = Alignment(wrap_text=True, vertical="top")
    CENTER     = Alignment(horizontal="center", vertical="center")
    THIN       = Side(style="thin", color="CCCCCC")
    BORDER     = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

    wb = openpyxl.Workbook()

    # ── Sheet 1: Findings ─────────────────────────────────────────────────────
    ws = wb.active
    ws.title = "Findings"

    col_cfg = [
        ("URL",      58),
        ("Severity", 11),
        ("Category", 40),
        ("Value",    62),
        ("Line",      6),
    ]
    for ci, (hdr, w) in enumerate(col_cfg, 1):
        cell = ws.cell(row=1, column=ci, value=hdr)
        cell.font      = F_HDR
        cell.fill      = PatternFill("solid", fgColor=FILL_HDR)
        cell.alignment = CENTER
        cell.border    = BORDER
        ws.column_dimensions[get_column_letter(ci)].width = w
    ws.row_dimensions[1].height = 22
    ws.freeze_panes = "A2"

    # Deduplicate by (url, value): if same value appears in multiple patterns,
    # keep only the one with the highest severity.
    seen: dict[tuple, tuple] = {}  # (url, value) -> (sev, cat, line)
    for res in sorted(results, key=lambda r: r.url):
        if res.status != "ok" or not res.findings:
            continue
        for f in res.findings:
            key = (res.url, f.match)
            existing = seen.get(key)
            if existing is None or SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing[0]]:
                seen[key] = (f.severity, f.category, f.line_number)

    # Sort: url asc, then severity asc (CRITICAL first)
    deduped = sorted(
        [(url, val, sev, cat, line) for (url, val), (sev, cat, line) in seen.items()],
        key=lambda x: (x[0], SEVERITY_ORDER[x[2]])
    )

    data_row = 2
    for url, val, sev, cat, line in deduped:
        fill_hex = FILL.get(sev, "FFFFFF")
        for ci, value in enumerate([url, sev, cat, val, line], 1):
            cell = ws.cell(row=data_row, column=ci, value=value)
            cell.font      = F_DATA
            cell.fill      = PatternFill("solid", fgColor=fill_hex)
            cell.border    = BORDER
            cell.alignment = CENTER if ci in (2, 5) else WRAP
        data_row += 1

    if data_row > 2:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(col_cfg))}{data_row - 1}"

    # ── Sheet 2: Summary ──────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Summary")
    ws2.column_dimensions["A"].width = 28
    ws2.column_dimensions["B"].width = 18
    ws2.column_dimensions["C"].width = 18

    # Count from deduplicated rows so Summary matches Findings sheet
    sev_counts: dict[str, int] = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    sev_urls:   dict[str, set] = {CRITICAL: set(), HIGH: set(), MEDIUM: set(), LOW: set()}
    for url, val, sev, cat, line in deduped:
        sev_counts[sev] += 1
        sev_urls[sev].add(url)

    total_findings = sum(sev_counts.values())
    total_urls_hit = len({r.url for r in results if r.status == "ok" and r.findings})
    count_clean    = sum(1 for r in results if r.status == "ok" and not r.findings)
    count_errors   = sum(1 for r in results if r.status == "error")

    # Metadata block
    meta = [
        ("Scan date",          datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Total URLs scanned", len([r for r in results if r.status != "skip"])),
        ("Clean (no findings)",count_clean),
        ("URLs with findings", total_urls_hit),
        ("Fetch errors",       count_errors),
    ]
    for i, (lbl, val) in enumerate(meta, 1):
        lc = ws2.cell(row=i, column=1, value=lbl)
        vc = ws2.cell(row=i, column=2, value=val)
        lc.font = F_META_LBL
        vc.font = F_META_VAL
        lc.border = vc.border = BORDER

    # Severity breakdown table
    hdr_row = len(meta) + 2
    for ci, hdr in enumerate(["Severity", "Findings", "URLs affected"], 1):
        cell = ws2.cell(row=hdr_row, column=ci, value=hdr)
        cell.font      = F_HDR
        cell.fill      = PatternFill("solid", fgColor=FILL_HDR)
        cell.alignment = CENTER
        cell.border    = BORDER

    for i, sev in enumerate([CRITICAL, HIGH, MEDIUM, LOW], 1):
        r = hdr_row + i
        for ci, val in enumerate([sev, sev_counts[sev], len(sev_urls[sev])], 1):
            cell = ws2.cell(row=r, column=ci, value=val)
            cell.font      = F_DATA
            cell.fill      = PatternFill("solid", fgColor=FILL.get(sev, "FFFFFF"))
            cell.alignment = CENTER
            cell.border    = BORDER

    # Total row
    tot_row = hdr_row + 5
    for ci, val in enumerate(["TOTAL", total_findings, total_urls_hit], 1):
        cell = ws2.cell(row=tot_row, column=ci, value=val)
        cell.font      = F_TOT
        cell.fill      = PatternFill("solid", fgColor=FILL_TOTAL)
        cell.alignment = CENTER
        cell.border    = BORDER

    wb.save(path)
    print(f"  {GREEN}✓  Excel saved → {path}{RESET}")
    print(f"  Findings: {data_row - 2} rows | {total_findings} findings across {total_urls_hit} URLs")
    return True

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — AWS SES email
# ═══════════════════════════════════════════════════════════════════════════════

def step_email(results: list[FileResult], excel_path: Optional[str] = None, json_path: Optional[str] = None):
    """
    Отправляет HTML-отчёт на SES_RECIPIENT через AWS SES.
    Прикрепляет Excel и/или JSON если файлы существуют.
    Требуется: pip install boto3 + настроенные AWS credentials
    """
    print(f"\n{'═'*72}")
    print(f"{BOLD}  [6/6] Email — sending via AWS SES{RESET}")
    print(f"{'─'*72}")
    print(f"  From   : {SES_SENDER}")
    print(f"  To     : {SES_RECIPIENT}")
    print(f"  Region : {SES_REGION}")

    try:
        import boto3
    except ImportError:
        print("  boto3 not installed. Run: pip install boto3")
        return

    hits    = [r for r in results if r.status == "ok" and r.findings]
    errors  = [r for r in results if r.status == "error"]
    clean   = [r for r in results if r.status == "ok" and not r.findings]
    total_f = sum(len(r.findings) for r in hits)

    sev_counts: dict[str, int] = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for r in hits:
        for f in r.findings:
            sev_counts[f.severity] += 1

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Plain text ────────────────────────────────────────────────────────────
    body_text = (
        f"Summary\n\n"
        f"  Files scanned     : {len(results)}\n"
        f"  \u2713 Clean           : {len(clean)}\n"
        f"  \u26a0 With findings  : {len(hits)}  ({total_f} total)\n\n"
        f"Full details are in the attached Excel file (findings.xlsx)."
    )


    # ── MIME assembly ─────────────────────────────────────────────────────────
    import email.mime.multipart as M
    import email.mime.text       as MT
    import email.mime.base       as MB
    import email.encoders        as ENC

    msg = M.MIMEMultipart("mixed")
    msg["Subject"] = f"JS Secrets Results - {datetime.now().strftime('%d.%m.%Y')}"
    msg["From"] = SES_SENDER
    msg["To"]   = SES_RECIPIENT

    msg.attach(MT.MIMEText(body_text, "plain", "utf-8"))

    for fpath, mime_t, fname in [
        (excel_path, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "findings.xlsx"),
        (json_path,  "application/json", "findings.json"),
    ]:
        if fpath and os.path.isfile(fpath):
            with open(fpath, "rb") as fh:
                part = MB.MIMEBase("application", "octet-stream")
                part.set_payload(fh.read())
            ENC.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
            part.add_header("Content-Type", mime_t)
            msg.attach(part)
            size_kb = os.path.getsize(fpath) // 1024
            print(f"  Attachment: {fname}  ({size_kb} KB)")

    # ── Send ──────────────────────────────────────────────────────────────────
    try:
        client = boto3.client("ses", region_name=SES_REGION)
        resp   = client.send_raw_email(
            Source       = SES_SENDER,
            Destinations = [SES_RECIPIENT],
            RawMessage   = {"Data": msg.as_bytes()},
        )
        print(f"  {GREEN}✓  Email sent{RESET}")
        print(f"  MessageId: {resp['MessageId']}")
    except Exception as e:
        msg_str = str(e)
        if "credential" in msg_str.lower() or "NoCredentials" in type(e).__name__:
            print(f"  {SEVERITY_COLOR[CRITICAL]}✗  No AWS credentials.{RESET}")
            print("     Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY")
            print("     or configure ~/.aws/credentials")
        else:
            print(f"  {SEVERITY_COLOR[CRITICAL]}✗  SES error: {e}{RESET}")

# ─── JSON export (optional) ───────────────────────────────────────────────────

def save_json(results: list[FileResult], path: str):
    out = []
    for r in results:
        if r.status == "skip":
            continue
        out.append({
            "url": r.url, "status": r.status, "error": r.error,
            "findings": [
                {"severity": f.severity, "category": f.category,
                 "match": f.match, "line": f.line_number, "context": f.line_content}
                for f in r.findings
            ],
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print(f"  JSON saved → {path}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "JS Security Analyzer — Full auto-pipeline\n"
            "  scan -f root.txt    →  SecurityTrails → getJS → merge → scan → Excel → SES email\n"
            "  scan --urls file.txt →  getJS → merge → scan → Excel → SES email"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser(
        "scan",
        help="Запустить полный пайплайн (subdomains → getJS → merge → scan → excel → email)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src = scan_p.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--roots", metavar="FILE",
                      help="Файл с корневыми доменами (один на строку) — поддомены "
                           "собираются автоматически через SecurityTrails")
    src.add_argument("--urls", metavar="FILE",
                      help="Файл с уже готовым списком URL / хостов (один на строку) — "
                           "SecurityTrails не используется")

    scan_p.add_argument("-k", "--st-api-key", default=None,
                        help="API-ключ SecurityTrails (нужен только с -f/--roots; "
                             "или задайте переменную окружения ST_API_KEY)")
    scan_p.add_argument("--children-only", action="store_true",
                        help="SecurityTrails: только прямые поддомены (без вложенных)")
    scan_p.add_argument("--concurrency", type=int, default=10,
                        help="Параллельных HTTP запросов (default: 10)")
    scan_p.add_argument("--severity", choices=[CRITICAL, HIGH, MEDIUM, LOW], default=LOW,
                        help="Минимальный severity (default: LOW)")
    scan_p.add_argument("--getjs-threads", type=int, default=50,
                        help="Потоки для getJS (default: 50)")
    scan_p.add_argument("--no-getjs", action="store_true",
                        help="Пропустить getJS, сканировать только исходный список")
    scan_p.add_argument("--no-email", action="store_true",
                        help="Не отправлять письмо через SES")
    scan_p.add_argument("--excel", metavar="FILE", default="findings.xlsx",
                        help="Путь к Excel-отчёту (default: findings.xlsx)")
    scan_p.add_argument("--json", metavar="FILE",
                        help="Дополнительно сохранить JSON-отчёт")
    scan_p.add_argument("--email-domains", metavar="DOMAINS",
                        help="Опционально: искать email-адреса на указанных доменах "
                             "(через запятую, напр. temabit.com,foodtech.team). "
                             "По умолчанию поиск email отключён.")

    return parser

async def main():
    args = build_arg_parser().parse_args()

    if args.email_domains:
        domains = [d for d in args.email_domains.split(",") if d.strip()]
        EXTRA_PATTERNS.extend(build_email_patterns(domains))
        EMAIL_DOMAINS.extend(d.strip().lstrip("@") for d in domains)
        print(f"  [i] Email search enabled for domains: {', '.join(domains)}")

    precompile_patterns()  # один раз, до начала конкурентного сканирования

    # ── Source of the initial host/URL list: -f/--roots (SecurityTrails) or --urls ──
    if args.roots:
        st_api_key = args.st_api_key or os.environ.get("ST_API_KEY")
        if not st_api_key:
            print("[!] Укажите API-ключ SecurityTrails через -k/--st-api-key "
                  "или переменную окружения ST_API_KEY", file=sys.stderr)
            sys.exit(1)

        base = os.path.splitext(args.roots)[0]
        subdomains_path = f"{base}_subdomains.txt"
        # step_subdomains() уже нормализует хосты (добавляет схему) — см.
        # комментарий у normalize_url() про то, почему это обязательно для getJS.
        original_urls = step_subdomains(args.roots, st_api_key, args.children_only, subdomains_path)
        if not original_urls:
            print("[!] SecurityTrails не вернул ни одного поддомена.")
            sys.exit(1)
        input_label = args.roots
        input_for_getjs = subdomains_path
    else:
        try:
            with open(args.urls, encoding="utf-8") as fh:
                original_urls = list(dict.fromkeys(
                    normalize_url(l) for l in fh if l.strip() and not l.startswith("#")
                ))
        except FileNotFoundError:
            print(f"[!] Файл не найден: {args.urls}")
            sys.exit(1)
        input_label = args.urls
        input_for_getjs = args.urls
        print(f"\n  {'─'*70}")
        print(f"  [1/6] SecurityTrails — {DIM}skipped (no -f/--roots){RESET}")

    if not original_urls:
        print("[!] Список хостов пуст.")
        sys.exit(1)

    print(f"\n  {'═'*70}")
    print(f"  {BOLD}JS Security Analyzer — Full Pipeline{RESET}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Input   : {input_label}  ({len(original_urls)} hosts)")
    print(f"  Output  : {args.excel}")
    print(f"  Email   : {'disabled (--no-email)' if args.no_email else SES_RECIPIENT}")
    print(f"  {'═'*70}")

    # ── Step 2: getJS ─────────────────────────────────────────────────────────
    js_urls: list[str] = []
    if not args.no_getjs:
        js_urls = step_getjs(input_for_getjs, threads=args.getjs_threads)
    else:
        print(f"\n  [2/6] getJS — {DIM}skipped (--no-getjs){RESET}")

    # ── Step 3: merge ─────────────────────────────────────────────────────────
    base        = os.path.splitext(input_label)[0]
    merged_path = f"{base}_scan_targets.txt"
    scan_urls   = step_merge(original_urls, js_urls, merged_path)

    # ── Step 4: scan ──────────────────────────────────────────────────────────
    results = await step_scan(scan_urls, args.concurrency, args.severity)

    # Summary
    count_clean    = sum(1 for r in results if r.status == "ok" and not r.findings)
    count_errors   = sum(1 for r in results if r.status == "error")
    count_hits     = sum(1 for r in results if r.status == "ok" and r.findings)
    total_findings = sum(len(r.findings) for r in results)

    print(f"\n{'═'*72}")
    print(f"{BOLD}  Scan Summary{RESET}")
    print(f"{'─'*72}")
    print(f"  Scanned          : {len(scan_urls)}")
    print(f"  {GREEN}✓ Clean          : {count_clean}{RESET}")
    print(f"  {SEVERITY_COLOR[CRITICAL]}⚠ With findings : {count_hits}  ({total_findings} total){RESET}")
    print(f"  {DIM}✗ Fetch errors   : {count_errors}{RESET}")

    # ── Step 5: Excel ─────────────────────────────────────────────────────────
    excel_ok = step_excel(results, args.excel)

    # ── Optional: JSON ────────────────────────────────────────────────────────
    if args.json:
        save_json(results, args.json)

    # ── Step 6: email ─────────────────────────────────────────────────────────
    if not args.no_email:
        step_email(
            results,
            excel_path = args.excel if excel_ok else None,
            json_path  = args.json  if args.json  else None,
        )
    else:
        print(f"\n  [6/6] Email — {DIM}skipped (--no-email){RESET}")

    print(f"\n{'═'*72}")
    print(f"{BOLD}  Done. {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{'═'*72}\n")


if __name__ == "__main__":
    asyncio.run(main())

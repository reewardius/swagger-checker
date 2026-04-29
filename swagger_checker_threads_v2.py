import requests
import json
import urllib3
import re
import argparse
import threading
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
        start_marker = '"swaggerDoc":'
        start_idx = js_content.find(start_marker) + len(start_marker)
        
        if start_idx == len(start_marker) - 1:
            return None
        
        while start_idx < len(js_content) and js_content[start_idx].isspace():
            start_idx += 1
        
        if js_content[start_idx] != '{':
            return None
        
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
        
        swagger_json_str = js_content[start_idx:end_idx].strip()
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
    
    js_urls.extend([
        f"{base_url}/swagger/swagger-ui-init.js",
        f"{base_url}/api/swagger/swagger-ui-init.js", 
        f"{base_url}/swagger-ui-init.js"
    ])
    
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
                
                if data and 'paths' in data and (data.get('swagger') or data.get('openapi')):
                    thread_safe_print(f"[SUCCESS] Найдена спецификация!")
                    thread_safe_print(f"[INFO] API версия: {data.get('swagger') or data.get('openapi')}")
                    thread_safe_print(f"[INFO] Найдено эндпоинтов: {len(data.get('paths', {}))}")
                    
                    for endpoint in data.get("paths", {}):
                        methods = list(data["paths"][endpoint].keys())
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

def load_direct_spec(spec_url):
    """Загружает и парсит прямую ссылку на JSON-спецификацию"""
    endpoints = []
    base_url = get_base_from_url(spec_url)
    
    thread_safe_print(f"\n[INFO] Загружаем спецификацию напрямую: {spec_url}")
    try:
        response = requests.get(spec_url, headers=HEADERS, verify=False, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data and 'paths' in data and (data.get('swagger') or data.get('openapi')):
                thread_safe_print(f"[SUCCESS] Найдена спецификация!")
                thread_safe_print(f"[INFO] API версия: {data.get('swagger') or data.get('openapi')}")
                thread_safe_print(f"[INFO] Найдено эндпоинтов: {len(data.get('paths', {}))}")

                # Определяем базовый URL для эндпоинтов из поля servers (OpenAPI 3.x)
                servers = data.get('servers', [])
                if servers and isinstance(servers, list):
                    api_base = servers[0].get('url', base_url).rstrip('/')
                    if api_base.startswith('/'):
                        api_base = base_url + api_base
                else:
                    api_base = base_url

                for endpoint in data.get("paths", {}):
                    methods = list(data["paths"][endpoint].keys())
                    http_methods = [m.lower() for m in methods if m.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']]
                    if http_methods:
                        endpoints.append((api_base + endpoint, http_methods))
            else:
                thread_safe_print(f"[SKIP] Не является Swagger спецификацией: {spec_url}")
        else:
            thread_safe_print(f"[{response.status_code}] {spec_url}")
    except Exception as e:
        thread_safe_print(f"[ERR] {spec_url} → {e}")
    
    return endpoints

def is_direct_spec_url(url):
    """Определяет, является ли URL прямой ссылкой на JSON-спецификацию"""
    lower = url.lower()
    return (
        lower.endswith('.json') or
        lower.endswith('/api-docs') or
        'swagger.json' in lower or
        'openapi.json' in lower or
        'api-docs' in lower
    )

def check_single_endpoint(url_methods_pair):
    """Проверяет один эндпоинт на доступность с JSON ответом"""
    url, methods = url_methods_pair
    valid_endpoints = []
    
    if "get" in methods:
        urls_to_check = [url]
        
        if has_id_parameter(url):
            id_variants = generate_id_variants(url)
            urls_to_check.extend(id_variants)
            thread_safe_print(f"\n[ID PARAM] Найден ID параметр в: {url}")
            thread_safe_print(f"[ID PARAM] Проверяем варианты: {id_variants}")
        
        for check_url in urls_to_check:
            try:
                response = requests.get(check_url, headers=HEADERS, verify=False, timeout=10)
                
                if response.status_code == 200:
                    if is_json_response(response):
                        if has_non_empty_body(response):
                            valid_endpoints.append(check_url)
                            thread_safe_print(f"[✓ SUCCESS] {check_url}")
                        else:
                            thread_safe_print(f"[✗ EMPTY] {check_url} (JSON пустой)")
                    else:
                        content_type = response.headers.get('content-type', 'unknown')
                        thread_safe_print(f"[✗ NOT JSON] {check_url} (Content-Type: {content_type})")
                else:
                    thread_safe_print(f"[{response.status_code}] {check_url}")
                    
            except Exception as e:
                if "timeout" not in str(e).lower():
                    thread_safe_print(f"[ERR] {check_url} → {e}")
    
    return valid_endpoints

def check_endpoints_threaded(endpoints, max_threads=5):
    """Проверяет эндпоинты на доступность с JSON ответом (многопоточно)"""
    valid_get_endpoints = []
    
    thread_safe_print(f"\n[INFO] Начинаем проверку {len(endpoints)} эндпоинтов в {max_threads} потоках...")
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_endpoint = {
            executor.submit(check_single_endpoint, endpoint): endpoint 
            for endpoint in endpoints
        }
        
        for future in as_completed(future_to_endpoint):
            endpoint = future_to_endpoint[future]
            try:
                result = future.result()
                valid_get_endpoints.extend(result)
            except Exception as e:
                thread_safe_print(f"[ERR] Ошибка при обработке {endpoint}: {e}")
    
    thread_safe_print(f"\n[RESULT] Найдено {len(valid_get_endpoints)} валидных GET эндпоинтов с JSON ответом")
    return valid_get_endpoints

def check_endpoints_single(endpoints):
    """Проверяет эндпоинты на доступность с JSON ответом (однопоточно)"""
    valid_get_endpoints = []
    
    print(f"\n[INFO] Начинаем проверку {len(endpoints)} эндпоинтов (однопоточно)...")
    
    for url, methods in endpoints:
        if "get" in methods:
            urls_to_check = [url]
            
            if has_id_parameter(url):
                id_variants = generate_id_variants(url)
                urls_to_check.extend(id_variants)
                print(f"\n[ID PARAM] Найден ID параметр в: {url}")
                print(f"[ID PARAM] Проверяем варианты: {id_variants}")
            
            for check_url in urls_to_check:
                try:
                    response = requests.get(check_url, headers=HEADERS, verify=False, timeout=10)
                    
                    if response.status_code == 200:
                        if is_json_response(response):
                            if has_non_empty_body(response):
                                valid_get_endpoints.append(check_url)
                                print(f"[✓ SUCCESS] {check_url}")
                            else:
                                print(f"[✗ EMPTY] {check_url} (JSON пустой)")
                        else:
                            content_type = response.headers.get('content-type', 'unknown')
                            print(f"[✗ NOT JSON] {check_url} (Content-Type: {content_type})")
                    else:
                        print(f"[{response.status_code}] {check_url}")
                        
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        print(f"[ERR] {check_url} → {e}")
    
    print(f"\n[RESULT] Найдено {len(valid_get_endpoints)} валидных GET эндпоинтов с JSON ответом")
    return valid_get_endpoints

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description='Swagger Endpoints Checker')
    parser.add_argument('-t', '--threads', type=int, default=1, 
                       help='Количество потоков для проверки эндпоинтов (по умолчанию: 1)')
    
    args = parser.parse_args()
    
    print("=== Swagger Endpoints Checker ===")
    print(f"[CONFIG] Потоков: {args.threads}")
    
    # Читаем файл — поддерживаем два формата:
    # 1. Новый: просто URL на строке (https://host/path/swagger.json)
    # 2. Старый: [swagger-api] [http] [info] https://host/path
    try:
        with open("swagger_endpoints.txt", "r") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        swagger_ui_urls = []    # Ссылки на Swagger UI (требуют перебора путей)
        direct_spec_urls = []   # Прямые ссылки на JSON-спецификации

        for line in lines:
            if line.startswith("[swagger-api]"):
                # Старый формат: [swagger-api] [http] [info] https://...
                parts = line.split()
                if len(parts) >= 4:
                    swagger_ui_urls.append(parts[3])
            elif line.startswith("http://") or line.startswith("https://"):
                # Новый формат: просто URL (берём первое слово, игнорируем комментарии)
                url = line.split()[0]
                if is_direct_spec_url(url):
                    direct_spec_urls.append(url)
                else:
                    swagger_ui_urls.append(url)

        print(f"[INFO] Прямых ссылок на спецификации: {len(direct_spec_urls)}")
        print(f"[INFO] Swagger UI URLs (перебор путей): {len(swagger_ui_urls)}")

    except FileNotFoundError:
        print("[ERROR] Файл swagger_endpoints.txt не найден!")
        return

    # Собираем все эндпоинты
    all_endpoints = []

    # Прямые JSON-спецификации
    for spec_url in direct_spec_urls:
        endpoints = load_direct_spec(spec_url)
        all_endpoints.extend(endpoints)

    # Swagger UI URLs — через перебор стандартных путей
    for url in swagger_ui_urls:
        endpoints = extract_paths_from_swagger(url)
        all_endpoints.extend(endpoints)

    print(f"\n[INFO] Всего извлечено {len(all_endpoints)} эндпоинтов из {len(direct_spec_urls) + len(swagger_ui_urls)} источников")
    
    # Проверяем эндпоинты
    if all_endpoints:
        if args.threads > 1:
            valid_gets = check_endpoints_threaded(all_endpoints, args.threads)
        else:
            valid_gets = check_endpoints_single(all_endpoints)
        
        with open("swagger_get_200.txt", "w") as f:
            for url in valid_gets:
                f.write(url + "\n")
        
        print(f"\n[DONE] Результаты сохранены в swagger_get_200.txt")
        print(f"[STATS] Обработано: {len(all_endpoints)} эндпоинтов")
        print(f"[STATS] Валидных: {len(valid_gets)} GET эндпоинтов")
        print(f"[STATS] Использовано потоков: {args.threads}")
    else:
        print("[WARNING] Не найдено ни одного эндпоинта для проверки")

if __name__ == "__main__":
    main()

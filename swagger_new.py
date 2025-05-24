import requests
import json
import urllib3
import re
from urllib.parse import urlparse
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

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
            print("[DEBUG] Не удалось найти swaggerDoc в JS")
            return None
        
        # Пропускаем пробелы
        while start_idx < len(js_content) and js_content[start_idx].isspace():
            start_idx += 1
        
        # Проверяем, что начинается объект
        if js_content[start_idx] != '{':
            print("[DEBUG] Ожидался объект после swaggerDoc")
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
            print("[DEBUG] Неправильная структура объекта swaggerDoc (несбалансированные скобки)")
            return None
        
        # Извлекаем строку JSON
        swagger_json_str = js_content[start_idx:end_idx].strip()
        
        # Парсим JSON
        swagger_data = json.loads(swagger_json_str)
        return swagger_data
            
    except json.JSONDecodeError as e:
        print(f"[DEBUG] Ошибка парсинга JSON: {e}")
        print(f"[DEBUG] Извлечённая строка (первые 500 символов): {swagger_json_str[:500]}...")
    except Exception as e:
        print(f"[DEBUG] Ошибка парсинга JS: {e}")
        
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
        # Банковские API часто используют этот путь
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
        # Стандартный Swagger UI
        swagger_base = path.replace("/index.html", "")
        json_urls.extend([
            f"{base_url}{swagger_base}/v1/swagger.json",
            f"{base_url}{swagger_base}/swagger.json",
            f"{base_url}{swagger_base}/doc.json"
        ])
        js_urls.append(f"{base_url}{swagger_base}/swagger-ui-init.js")
    
    elif path.endswith("/api/swagger"):
        # REST API endpoints
        api_base = path.replace("/swagger", "")
        json_urls.extend([
            f"{base_url}{api_base}/swagger.json",
            f"{base_url}{api_base}/swagger/swagger.json", 
            f"{base_url}{api_base}/v2/api-docs"
        ])
        js_urls.append(f"{base_url}/api/swagger/swagger-ui-init.js")
    
    elif "swagger" in path:
        # Общий случай для путей содержащих swagger
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
    
    print(f"[DEBUG] Сгенерировано {len(json_urls)} JSON и {len(js_urls)} JS вариантов для {swagger_ui_url}")
    
    return json_urls, js_urls

def has_id_parameter(url):
    """Проверяет, содержит ли URL параметры ID"""
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    return re.search(id_pattern, url) is not None

def generate_id_variants(url):
    """Генерирует варианты URL с заменой ID параметров на числа"""
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    variants = []
    
    for id_value in [1, 2, 3]:
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
    
    print(f"\n[INFO] Обрабатываем: {swagger_ui_url}")
    
    json_urls, js_urls = generate_swagger_urls(swagger_ui_url)
    all_urls = json_urls + js_urls
    
    spec_found = False
    for swagger_url in all_urls:
        try:
            print(f"[TRY] {swagger_url}")
            response = requests.get(swagger_url, headers=HEADERS, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = None
                
                # Определяем тип файла и парсим соответственно
                if swagger_url in js_urls or swagger_url.endswith('.js'):
                    print(f"[JS] Парсим JavaScript файл")
                    data = extract_swagger_from_js(response.text)
                    if not data:
                        print(f"[SKIP] SwaggerDoc не найден в JS")
                        continue
                else:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'application/json' in content_type or swagger_url.endswith('.json'):
                        try:
                            data = response.json()
                            print(f"[JSON] Парсим JSON файл")
                        except json.JSONDecodeError:
                            print(f"[SKIP] Невалидный JSON")
                            continue
                    else:
                        print(f"[SKIP] Неподдерживаемый тип (Content-Type: {content_type})")
                        continue
                
                # Валидация Swagger/OpenAPI спецификации
                if data and 'paths' in data and (data.get('swagger') or data.get('openapi')):
                    print(f"[SUCCESS] Найдена спецификация!")
                    print(f"[INFO] API версия: {data.get('swagger') or data.get('openapi')}")
                    print(f"[INFO] Найдено эндпоинтов: {len(data.get('paths', {}))}")
                    
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
                    print(f"[SKIP] Не является Swagger спецификацией")
            else:
                if response.status_code not in [404, 403, 401]:
                    print(f"[{response.status_code}] {swagger_url}")
                    
        except Exception as e:
            if "404" not in str(e) and "403" not in str(e) and "timeout" not in str(e).lower():
                print(f"[ERR] {swagger_url} → {e}")
            continue
    
    if not spec_found:
        print(f"[WARNING] Swagger спецификация не найдена!")
    
    return paths

def check_endpoints(endpoints):
    """Проверяет эндпоинты на доступность с JSON ответом"""
    valid_get_endpoints = []
    
    print(f"\n[INFO] Начинаем проверку {len(endpoints)} эндпоинтов...")
    
    for url, methods in endpoints:
        if "get" in methods:
            urls_to_check = [url]
            
            # Обработка ID параметров
            if has_id_parameter(url):
                id_variants = generate_id_variants(url)
                urls_to_check.extend(id_variants)
                print(f"\n[ID PARAM] Найден ID параметр в: {url}")
                print(f"[ID PARAM] Проверяем варианты: {id_variants}")
            
            # Проверяем каждый URL
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
    print("=== Swagger Endpoints Checker ===")
    
    # Читаем файл с найденными Swagger UI
    try:
        with open("swagger_endpoints.txt", "r") as f:
            swagger_urls = [line.split()[3] for line in f if line.strip().startswith("[swagger-api]")]
        print(f"[INFO] Загружено {len(swagger_urls)} Swagger UI URLs")
    except FileNotFoundError:
        print("[ERROR] Файл swagger_endpoints.txt не найден!")
        return
    
    # Извлекаем все эндпоинты из всех Swagger спецификаций
    all_endpoints = []
    for url in swagger_urls:
        endpoints = extract_paths_from_swagger(url)
        all_endpoints.extend(endpoints)
    
    print(f"\n[INFO] Всего извлечено {len(all_endpoints)} эндпоинтов из {len(swagger_urls)} источников")
    
    # Проверяем эндпоинты
    if all_endpoints:
        valid_gets = check_endpoints(all_endpoints)
        
        # Сохраняем результаты
        with open("swagger_get_200.txt", "w") as f:
            for url in valid_gets:
                f.write(url + "\n")
        
        print(f"\n[DONE] Результаты сохранены в swagger_get_200.txt")
        print(f"[STATS] Обработано: {len(all_endpoints)} эндпоинтов")
        print(f"[STATS] Валидных: {len(valid_gets)} GET эндпоинтов")
    else:
        print("[WARNING] Не найдено ни одного эндпоинта для проверки")

if __name__ == "__main__":
    main()

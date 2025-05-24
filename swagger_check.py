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
    parsed = urlparse(swagger_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def extract_paths_from_swagger(swagger_ui_url):
    paths = []
    base_url = get_base_from_url(swagger_ui_url)
    # Пробуем найти swagger.json
    swagger_json_urls = [
        f"{base_url}/swagger/v1/swagger.json",
        f"{base_url}/swagger.json"
    ]
    for swagger_json_url in swagger_json_urls:
        try:
            response = requests.get(swagger_json_url, headers=HEADERS, verify=False, timeout=10)
            response.raise_for_status()
            data = response.json()
            for endpoint in data.get("paths", {}):
                methods = list(data["paths"][endpoint].keys())
                paths.append((base_url + endpoint, methods))
        except Exception as e:
            print(f"[!] Пропущен {swagger_json_url} → {e}")
            continue
    return paths

def has_id_parameter(url):
    """Проверяет, содержит ли URL параметры ID"""
    # Ищем параметры вида {id}, {ContentID}, {userId} и т.д.
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    return re.search(id_pattern, url) is not None

def generate_id_variants(url):
    """Генерирует варианты URL с заменой ID параметров на числа"""
    variants = []
    id_pattern = r'\{[^}]*[iI][dD][^}]*\}'
    
    # Заменяем все ID параметры на числа 1, 2, 3
    for id_value in [1, 2, 3]:
        variant_url = re.sub(id_pattern, str(id_value), url)
        variants.append(variant_url)
    
    return variants

def is_json_response(response):
    """Проверяет, является ли ответ JSON"""
    content_type = response.headers.get('content-type', '').lower()
    return 'application/json' in content_type

def has_non_empty_body(response):
    """Проверяет, что тело ответа не пустое"""
    try:
        if response.text.strip():
            # Пробуем распарсить JSON
            json_data = response.json()
            # Проверяем, что JSON не пустой
            if isinstance(json_data, dict):
                return len(json_data) > 0
            elif isinstance(json_data, list):
                return len(json_data) > 0
            else:
                return json_data is not None
        return False
    except:
        return False

def check_endpoints(endpoints):
    valid_get_endpoints = []
    
    for url, methods in endpoints:
        if "get" in methods:
            urls_to_check = [url]
            
            # Если URL содержит ID параметры, добавляем варианты с числами
            if has_id_parameter(url):
                urls_to_check.extend(generate_id_variants(url))
                print(f"[ID PARAM] Найден параметр ID в: {url}")
                print(f"[ID PARAM] Проверяем варианты: {generate_id_variants(url)}")
            
            for check_url in urls_to_check:
                try:
                    r = requests.get(check_url, headers=HEADERS, verify=False, timeout=10)
                    
                    if r.status_code == 200:
                        # Проверяем Content-Type JSON
                        if is_json_response(r):
                            # Проверяем, что тело не пустое
                            if has_non_empty_body(r):
                                valid_get_endpoints.append(check_url)
                                print(f"[200 OK + JSON + BODY] {check_url}")
                            else:
                                print(f"[200 OK + JSON - EMPTY] {check_url}")
                        else:
                            content_type = r.headers.get('content-type', 'unknown')
                            print(f"[200 OK - NOT JSON] {check_url} (Content-Type: {content_type})")
                    else:
                        print(f"[{r.status_code}] {check_url}")
                        
                except Exception as e:
                    print(f"[ERR] {check_url} → {e}")
    
    return valid_get_endpoints

def main():
    with open("swagger_endpoints.txt", "r") as f:
        swagger_urls = [line.split()[3] for line in f if line.strip().startswith("[swagger-api]")]
    
    all_endpoints = []
    for url in swagger_urls:
        all_endpoints.extend(extract_paths_from_swagger(url))
    
    valid_gets = check_endpoints(all_endpoints)
    
    with open("swagger_get_200.txt", "w") as f:
        for url in valid_gets:
            f.write(url + "\n")

if __name__ == "__main__":
    main()

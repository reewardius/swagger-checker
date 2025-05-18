import requests
import json
import urllib3
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

def check_endpoints(endpoints):
    valid_get_endpoints = []
    for url, methods in endpoints:
        if "get" in methods:
            try:
                r = requests.get(url, headers=HEADERS, verify=False, timeout=10)
                if r.status_code == 200:
                    valid_get_endpoints.append(url)
                    print(f"[200 OK] {url}")
                else:
                    print(f"[{r.status_code}] {url}")
            except Exception as e:
                print(f"[ERR] {url} → {e}")
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

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_valid_content_type(content_type):
    if content_type is None:
        return False
    return (
        "application/json" in content_type.lower()
        or "text/plain" in content_type.lower()
    )

def check_url(url):
    try:
        response = requests.get(url, timeout=10)
        content_type = response.headers.get("Content-Type", "")
        if is_valid_content_type(content_type):
            return f"[OK] {url} --> {content_type}"
    except requests.RequestException:
        pass  # Ошибки игнорируются

def check_urls_from_file(filename, max_threads=20):
    with open(filename, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_url, url) for url in urls]

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    check_urls_from_file("swagger_get_200.txt")

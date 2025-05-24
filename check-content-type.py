import argparse
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
        pass

def check_urls_from_file(filename, max_threads=20, output_file=None):
    with open(filename, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_url, url) for url in urls]
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)
                results.append(result)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            for line in results:
                f.write(line + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check URLs for specific Content-Types like JSON or plain text.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing a list of URLs.")
    parser.add_argument("-o", "--output", help="Optional path to save the output results to a file.")
    args = parser.parse_args()

    check_urls_from_file(args.file, output_file=args.output)

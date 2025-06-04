from urllib.parse import urlparse
import os

# Функция для генерации всех поддоменов
def generate_variants(url):
    parsed = urlparse(url)
    hostname_parts = parsed.hostname.split('.')
    
    # Сохраняем домен верхнего уровня
    base_urls = set()
    for i in range(len(hostname_parts) - 2):
        subdomain = '.'.join(hostname_parts[i:])
        base_url = f"{parsed.scheme}://{subdomain}"
        base_urls.add(base_url)
    
    # Добавляем оригинальный URL
    base_urls.add(f"{parsed.scheme}://{parsed.hostname}")
    return sorted(base_urls)

# Пример работы
input_file = "alive_http_services.txt"
output_file = "alive_http_services_advanced.txt"

all_urls = set()

with open(input_file, "r") as infile:
    for line in infile:
        url = line.strip()
        if url:
            all_urls.update(generate_variants(url))

with open(output_file, "w") as outfile:
    for url in sorted(all_urls):
        outfile.write(url + "\n")

print(f"Сохранено {len(all_urls)} уникальных URL в {output_file}")

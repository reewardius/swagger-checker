## 🧪 Swagger/OpenAPI Endpoint Checker

This tool extracts Swagger/OpenAPI endpoints from a list of known HTTP services, parses the documentation to find available API paths, and checks GET endpoints for 200 OK status responses.

##### 🚀 Features
- Supports .js, .json, and .html Swagger UI/OpenAPI links
- Automatically detects real Swagger JSON URLs
- Extracts and tests GET endpoints
- Saves reachable GET endpoints (status 200) into an output file

##### 📂 Input Files
To ensure `swagger_new.py` works properly, you must first run `nuclei` with the **swagger and openapi tags**. Here's an example pipeline to generate the required input:
```bash
subfinder -dL root.txt -all -silent -o subs.txt && \
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt && \
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt && \
python3 generate.py -i alive_http_services.txt -o alive_http_services_advanced.txt && \
nuclei -l alive_http_services_advanced.txt -id openapi,swagger-api -o swagger_endpoints.txt -rl 1000 -c 100
```

##### ▶️ How to Use Swagger Checker
Once `nuclei` has been executed and the `swagger_endpoints.txt` file has been generated, run the Python script:
```bash
python3 swagger_checker_threads.py -t 100

[RESULT] Найдено 59 валидных GET эндпоинтов с JSON ответом

[DONE] Результаты сохранены в swagger_get_200.txt
[STATS] Обработано: 1866 эндпоинтов
[STATS] Валидных: 59 GET эндпоинтов
[STATS] Использовано потоков: 100
```
##### 📄 Output
All working GET endpoints (status code 200) are saved in `swagger_get_200.txt`.

---
#### Bugbountytips

##### Check JSON/PLAIN Content-Type

```bash
python check-content-type.py -f swagger_get_200.txt -o content-types-results.txt

[OK] https://target.com/api/v1/check --> application/json; charset=utf-8
[OK] https://example.com/api/v2/status --> application/json; charset=utf-8
```

##### IP + Ports

```
subfinder -d <domain> -all -silent -o subs.txt && \
dnsx -l subs.txt -a -ro -o dnsx.txt && \
naabu -l dnsx.txt -ec -tp 100 -s s -o ports.txt && \
httpx -l ports.txt -o alive_http_services.txt && \
nuclei -l alive_http_services.txt -id openapi,swagger-api -o swagger_endpoints.txt -rl 1000 -c 100 && \
python3 swagger_checker_threads.py -t 100
```

##### PTR Records

```
subfinder -d <domain> -all -silent -o subs.txt && \
dnsx -l subs.txt -a -ro -o dnsx.txt && \
dnsx -l dnsx.txt -ptr -ro > dnsx_ptr.txt && \
naabu -l dnsx_ptr.txt -ec -tp 100 -s s -o ports.txt && \
httpx -l ports.txt -o alive_http_services.txt && \
nuclei -l alive_http_services.txt -id openapi,swagger-api -o swagger_endpoints.txt -rl 1000 -c 100 && \
python3 swagger_checker_threads.py -t 100
```

##### Swagger + Trufflehog
```bash
rm -rf responses/ && httpx -l swagger_get_200.txt -sr -srd responses/ && trufflehog filesystem responses/ > trufflehog_results.txt
```
##### Trufflehog Only Verified
```bash
rm -rf responses/ && httpx -l swagger_get_200.txt -sr -srd responses/ && trufflehog filesystem responses/ --only-verified > trufflehog_verified_results.txt
```

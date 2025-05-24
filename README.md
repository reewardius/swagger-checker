## 🧪 Swagger/OpenAPI Endpoint Checker

This tool extracts Swagger/OpenAPI endpoints from a list of known HTTP services, parses the documentation to find available API paths, and checks GET endpoints for 200 OK status responses.

#### 🚀 Features
- Supports .js, .json, and .html Swagger UI/OpenAPI links
- Automatically detects real Swagger JSON URLs
- Extracts and tests GET endpoints
- Saves reachable GET endpoints (status 200) into an output file

#### 📂 Input Files
Output file from nuclei:
```
nuclei -l alive_http_services.txt -tags swagger,openapi -o swagger_endpoints.txt
```
This script extracts the URL (https://...) from each line and processes it.

#### ▶️ How to Use
Run the Python script:
```
python3 swagger_new.py
```
#### 📄 Output
All working GET endpoints (status code 200) are saved in `swagger_get_200.txt`.

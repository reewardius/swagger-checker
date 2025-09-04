import requests
import json
import argparse
import threading
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json"
}

print_lock = threading.Lock()

def thread_safe_print(message):
    with print_lock:
        print(message)

# === Очистка и подготовка папки результатов ===
def prepare_results_folder(results_dir, mode, url):
    # Sanitize URL for use as a directory name
    sanitized_url = url.replace('://', '_').replace('/', '_').replace(':', '_').replace('.', '_')
    mode_dir = os.path.join(results_dir, mode, sanitized_url)
    os.makedirs(mode_dir, exist_ok=True)
    return mode_dir

# === PII Detection Logic ===
PII_KEYWORDS = [
    "email", "phone", "telephone", "mobile", "fax",
    "cc", "creditcard", "cardnumber", "card", "payment",
    "ssn", "socialsecurity", "taxid", "tin", "nationalid",
    "address", "street", "city", "zip", "postal",
    "name", "firstname", "lastname", "middlename", "fullname",
    "birthdate", "dob", "dateofbirth", "birthday", "age",
    "passport", "driverlicense", "license", "idnumber", "govtid",
    "bankaccount", "iban", "accountnumber", "routing", "swift",
    "username", "login", "password", "token", "session",
    "ipaddress", "deviceid", "macaddress", "biometric", "health",
    "social"
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        types {
          name
          kind
          fields(includeDeprecated: true) {
            name
            args {
              name
            }
            type {
              name
              kind
              ofType {
                name
                kind
              }
            }
          }
        }
      }
    }
    """
}

def post_graphql(url, query):
    try:
        resp = requests.post(url, headers=HEADERS, json=query, timeout=10, verify=False)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        thread_safe_print(f"[ERROR] {e}")
    return None

def get_type(schema_types, type_name):
    for t in schema_types:
        if t["name"] == type_name:
            return t
    return None

def build_fields_block(type_obj, schema_types, depth=0):
    if depth > 3:
        return ""
    fields = type_obj.get("fields", [])
    field_strings = []
    for f in fields:
        fname = f["name"]
        ftype = f["type"]
        while ftype.get("ofType"):
            ftype = ftype["ofType"]
        type_name = ftype.get("name")
        type_kind = ftype.get("kind")
        if type_kind == "OBJECT":
            nested_type = get_type(schema_types, type_name)
            if nested_type:
                nested_fields = build_fields_block(nested_type, schema_types, depth+1)
                field_strings.append(f"{fname} {{ {nested_fields} }}")
            else:
                field_strings.append(fname)
        else:
            field_strings.append(fname)
    return " ".join(field_strings)

def find_pii_fields(schema_json):
    pii_fields = []
    types = schema_json.get("data", {}).get("__schema", {}).get("types", [])
    for t in types:
        if t.get("fields"):
            for f in t["fields"]:
                field_name = f.get("name", "").lower()
                if any(keyword in field_name for keyword in PII_KEYWORDS):
                    pii_fields.append({
                        "type": t["name"],
                        "field": f["name"],
                        "field_type": f["type"]
                    })
    return pii_fields, types

def get_type_name(type_obj):
    t = type_obj
    while t.get("ofType"):
        t = t["ofType"]
    return t.get("name")

def generate_poc(field_info, schema_types):
    type_obj = get_type(schema_types, get_type_name(field_info["field_type"]))
    if type_obj and type_obj.get("fields"):
        fields_block = build_fields_block(type_obj, schema_types)
        query = f"{{ {field_info['field']} {{ {fields_block} }} }}"
    else:
        query = f"{{ {field_info['field']} }}"
    return query

def execute_poc_pii(url, query, field_info, results_dir):
    try:
        query_json = {"query": query}
        resp = requests.post(url, headers=HEADERS, json=query_json, timeout=10, verify=False)
        if resp.status_code == 200:
            ctype = resp.headers.get("content-type", "").lower()
            if "application/json" in ctype or "text/plain" in ctype:
                if resp.text.strip() and "errors" not in resp.text:
                    thread_safe_print(f"[SUCCESS] {url} :: {field_info['field']}")
                    filename = f"{field_info['type']}_{field_info['field']}.txt"
                    filepath = os.path.join(results_dir, filename)
                    curl_cmd = (
                        f"curl -k -X POST \"{url}\" "
                        f"-H 'Content-Type: application/json' "
                        f"-H 'User-Agent: Mozilla/5.0' "
                        f"--data '{json.dumps(query_json)}'"
                    )
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(curl_cmd + "\n\n###\n\n")
                        try:
                            f.write(json.dumps(resp.json(), indent=2, ensure_ascii=False))
                        except:
                            f.write(resp.text)
                    return field_info['field']
    except Exception as e:
        thread_safe_print(f"[ERROR] executing {query}: {e}")
    return None

def check_pii(url, results_dir, threads):
    pii_dir = prepare_results_folder(results_dir, "pii", url)
    schema = post_graphql(url, INTROSPECTION_QUERY)
    if not schema:
        thread_safe_print(f"[ERROR] Не удалось получить схему GraphQL для {url}")
        return []

    pii_fields, schema_types = find_pii_fields(schema)
    if not pii_fields:
        thread_safe_print(f"[INFO] Подозрительных полей с PII не найдено для {url}")
        return []

    valid_pii = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for field in pii_fields:
            query = generate_poc(field, schema_types)
            futures.append(executor.submit(execute_poc_pii, url, query, field, pii_dir))
        
        for f in as_completed(futures):
            res = f.result()
            if res:
                valid_pii.append(res)
    
    return valid_pii

# === GraphQL Endpoint Checker Logic ===
COMMON_VALUES = {
    "id": ["1", "2", "me", "current", "admin"],
    "user": ["1", "me", "admin"],
    "status": ["active", "pending", "open"],
    "limit": ["1", "5", "10"],
    "page": ["1", "2"],
    "email": ["test@example.com"],
    "name": ["test"],
    "retail": ["store", "shop", "item"],
    "fintech": ["account", "balance", "transaction"],
    "warehouse": ["stock", "inventory", "location"],
    "logistics": ["shipment", "tracking", "route"],
    "transport": ["vehicle", "driver", "route"]
}

def guess_values(param_name):
    for key, values in COMMON_VALUES.items():
        if key in param_name.lower():
            return values
    return ["1"]

def check_introspection(url):
    introspection_query = {
        "query": """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              kind
              name
              fields {
                name
                args { name type { kind name ofType { kind name ofType { kind name }}} }
              }
            }
          }
        }
        """
    }
    try:
        r = requests.post(url, headers=HEADERS, json=introspection_query, timeout=10, verify=False)
        if r.status_code == 200 and "application/json" in r.headers.get("content-type", "").lower():
            data = r.json()
            if "data" in data and "__schema" in data["data"]:
                return data["data"]["__schema"]
    except:
        pass
    return None

def extract_operations(schema):
    operations = []
    for t in schema["types"]:
        if t.get("fields"):
            for f in t["fields"]:
                args = [a["name"] for a in f.get("args", [])]
                operations.append({"name": f["name"], "args": args, "type_name": None})
    return operations

def get_named_type(type_obj):
    while type_obj.get("ofType") is not None:
        type_obj = type_obj["ofType"]
    return type_obj.get("name")

def get_fields_recursive(type_name, schema_types, visited=None):
    if visited is None:
        visited = set()
    if type_name in visited or not type_name:
        return ["__typename"]
    visited.add(type_name)

    obj_type = next((t for t in schema_types if t["name"] == type_name), None)
    if not obj_type or not obj_type.get("fields"):
        return ["__typename"]

    fields = []
    for f in obj_type["fields"]:
        nested_type_name = get_named_type(f["type"])
        if nested_type_name and any(t["name"] == nested_type_name for t in schema_types):
            nested_fields = get_fields_recursive(nested_type_name, schema_types, visited.copy())
            fields.append(f"{f['name']} {{ {' '.join(nested_fields)} }}")
        else:
            fields.append(f["name"])
    return fields

def check_single_operation(url, operation, schema_types, results_dir):
    op_name = operation["name"]
    op_args = operation["args"]

    arg_strings = []
    for arg in op_args:
        values = guess_values(arg)
        val = json.dumps(values[0])
        arg_strings.append(f"{arg}: {val}")
    arg_block = f"({', '.join(arg_strings)})" if arg_strings else ""

    op_type_name = None
    for t in schema_types:
        if t.get("fields"):
            for f in t["fields"]:
                if f["name"] == op_name:
                    op_type_name = get_named_type(f.get("type")) if f.get("type") else None
                    break

    fields_block = ""
    if op_type_name:
        fields = get_fields_recursive(op_type_name, schema_types)
        fields_block = "{ " + " ".join(fields) + " }"

    query = {"query": f"{{ {op_name}{arg_block} {fields_block} }}"}
    try:
        r = requests.post(url, headers=HEADERS, json=query, timeout=10, verify=False)
        if r.status_code == 200:
            ctype = r.headers.get("content-type", "").lower()
            if "application/json" in ctype or "text/plain" in ctype:
                if r.text.strip() and "errors" not in r.text:
                    thread_safe_print(f"[SUCCESS] {url} :: {op_name}{arg_block}")
                    filename = f"{op_name}.txt"
                    filepath = os.path.join(results_dir, filename)
                    curl_cmd = (
                        f"curl -k -X POST \"{url}\" "
                        f"-H 'Content-Type: application/json' "
                        f"-H 'User-Agent: Mozilla/5.0' "
                        f"--data '{json.dumps(query)}'"
                    )
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(curl_cmd + "\n\n###\n\n")
                        try:
                            f.write(json.dumps(r.json(), indent=2, ensure_ascii=False))
                        except:
                            f.write(r.text)
                    return op_name
    except:
        pass
    return None

def check_operations(url, results_dir, threads):
    checker_dir = prepare_results_folder(results_dir, "checker", url)
    schema = check_introspection(url)
    if not schema:
        thread_safe_print(f"[ERROR] Не удалось получить схему GraphQL для {url}")
        return []

    operations = extract_operations(schema)
    valid_ops = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_single_operation, url, op, schema["types"], checker_dir): op for op in operations}
        for f in as_completed(futures):
            res = f.result()
            if res:
                valid_ops.append(res)
    return valid_ops

# === Main Logic ===
def main():
    parser = argparse.ArgumentParser(description="GraphQL Analyzer (PII Detection and Endpoint Checker)")
    parser.add_argument("-m", "--mode", choices=["pii", "checker", "both"], default="both", 
                        help="Режим работы: 'pii' для поиска PII, 'checker' для проверки операций, 'both' для обоих")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Один GraphQL endpoint")
    group.add_argument("-f", "--file", help="Файл со списком GraphQL endpoints (по одному в строке)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Количество потоков")
    parser.add_argument("-o", "--output", default="graphql_results", help="Папка для сохранения результатов")
    args = parser.parse_args()

    # Создаем главную папку результатов
    os.makedirs(args.output, exist_ok=True)
    results_dir = args.output

    urls = []
    if args.domain:
        urls.append(args.domain)
    elif args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        if args.mode in ["pii", "both"]:
            thread_safe_print(f"[INFO] Проверка PII для {url}")
            check_pii(url, results_dir, args.threads)
        
        if args.mode in ["checker", "both"]:
            thread_safe_print(f"[INFO] Проверка операций GraphQL для {url}")
            check_operations(url, results_dir, args.threads)

    thread_safe_print(f"\n[DONE] Все PoC сохранены в {results_dir}/ (подпапки: pii/<url>/, checker/<url>/)")

if __name__ == "__main__":
    main()
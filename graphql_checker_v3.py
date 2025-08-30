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

# === Очистка папки результатов ===
def prepare_results_folder(results_dir):
    if os.path.exists(results_dir):
        shutil.rmtree(results_dir)
    os.makedirs(results_dir)
    return results_dir

# === Значения по умолчанию для аргументов ===
COMMON_VALUES = {
    "id": ["1", "2", "me", "current", "admin"],
    "user": ["1", "me", "admin"],
    "status": ["active", "pending", "open"],
    "limit": ["1", "5", "10"],
    "page": ["1", "2"],
    "email": ["test@example.com"],
    "name": ["test"],
    # Новые категории
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

# === Проверка интроспекции ===
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

# === Извлечение операций и аргументов ===
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

                    curl_cmd = (
                        f"curl -k -X POST \"{url}\" "
                        f"-H 'Content-Type: application/json' "
                        f"-H 'User-Agent: Mozilla/5.0' "
                        f"--data '{json.dumps(query)}'"
                    )

                    filename = f"{url.replace('://','_').replace('/','_')}__{op_name}.txt"
                    filepath = os.path.join(results_dir, filename)
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

def check_operations(url, operations, schema_types, threads, results_dir):
    valid_ops = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_single_operation, url, op, schema_types, results_dir): op for op in operations}
        for f in as_completed(futures):
            res = f.result()
            if res:
                valid_ops.append(res)
    return valid_ops

# === MAIN ===
def main():
    parser = argparse.ArgumentParser(description="GraphQL Endpoint Checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Один GraphQL endpoint")
    group.add_argument("-f", "--file", help="Файл со списком GraphQL endpoints (по одному в строке)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Количество потоков для проверки операций")
    parser.add_argument("-o", "--output", default="graphql_results", help="Папка для сохранения результатов")
    args = parser.parse_args()

    results_dir = prepare_results_folder(args.output)

    urls = []
    if args.domain:
        urls.append(args.domain)
    elif args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        schema = check_introspection(url)
        if schema:
            operations = extract_operations(schema)
            check_operations(url, operations, schema["types"], args.threads, results_dir)

    thread_safe_print(f"\n[DONE] Все PoC сохранены в {results_dir}/")

if __name__ == "__main__":
    main()

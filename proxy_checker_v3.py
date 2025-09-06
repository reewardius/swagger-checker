import requests
import json
import argparse
import urllib3
import threading
import uuid
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      enumValues { name }
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
  }
}
"""

def make_session(proxy=None, insecure=False):
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    session.verify = not insecure
    return session

def introspect_schema(session, url):
    try:
        resp = session.post(url, json={"query": INTROSPECTION_QUERY}, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[!] Introspection failed for {url}: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Introspection error for {url}: {e}")
    return None

def unwrap_type(type_obj):
    """Разворачиваем NON_NULL и LIST до базового типа"""
    while type_obj["kind"] in ("NON_NULL", "LIST") and type_obj.get("ofType"):
        type_obj = type_obj["ofType"]
    return type_obj

def build_test_payload(arg, types):
    t = unwrap_type(arg["type"])
    kind = t["kind"]
    name = t.get("name")
    arg_name = arg["name"].lower()

    if kind == "SCALAR":
        if name == "Int":
            return 1
        elif name == "Float":
            return 1.1
        elif name == "Boolean":
            return True
        elif name == "ID":
            if any(keyword in arg_name for keyword in ['id', 'uuid', 'guid']):
                if 'uuid' in arg_name or 'guid' in arg_name:
                    return str(uuid.uuid4())
                else:
                    return "123"
            return "test-id"
        else:
            if any(keyword in arg_name for keyword in ['id', 'number', 'num', 'count', 'index', 'position']):
                if 'id' in arg_name:
                    return "123"
                else:
                    return 1
            return "test"
    
    elif name == "Int" or (name and "int" in name.lower()):
        return 1
    elif name == "Float" or (name and "float" in name.lower()):
        return 1.1  
    elif name == "Boolean" or (name and "bool" in name.lower()):
        return True
    elif name == "ID" or (name and "id" in name.lower()):
        if 'uuid' in arg_name or 'guid' in arg_name:
            return str(uuid.uuid4())
        return "123"
    elif kind == "ENUM":
        enum_type = next((x for x in types if x["name"] == name), None)
        if enum_type and enum_type.get("enumValues"):
            return enum_type["enumValues"][0]["name"]
        return "UNKNOWN_ENUM"
    else:
        if any(keyword in arg_name for keyword in ['id', 'number', 'num', 'count', 'index', 'position', 'order']):
            if 'uuid' in arg_name or 'guid' in arg_name:
                return str(uuid.uuid4())
            elif any(keyword in arg_name for keyword in ['id', 'number', 'num', 'count', 'index', 'position', 'order']):
                return 123
        return "test"

def build_field_selection(field, types, depth=0, max_depth=5):
    if depth > max_depth:
        return field["name"]

    t = unwrap_type(field["type"])
    kind = t["kind"]
    name = t.get("name")
    field_name = field["name"]

    if kind == "OBJECT":
        obj_type = next((x for x in types if x["name"] == name), None)
        if obj_type and obj_type.get("fields"):
            subfields = [build_field_selection(f, types, depth+1, max_depth) for f in obj_type["fields"]]
            return f"{field_name} {{ {' '.join(subfields)} }}"
        else:
            return field_name
    else:
        return field_name

def serialize_arg_value(value):
    """Правильно сериализуем значения для GraphQL запроса"""
    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            if isinstance(v, str):
                items.append(f'{k}: "{v}"')
            else:
                items.append(f'{k}: {json.dumps(v)}')
        return "{" + ", ".join(items) + "}"
    elif isinstance(value, list):
        serialized_items = []
        for item in value:
            if isinstance(item, dict):
                serialized_items.append(serialize_arg_value(item))
            elif isinstance(item, str):
                serialized_items.append(f'"{item}"')
            else:
                serialized_items.append(str(item))
        return "[" + ", ".join(serialized_items) + "]"
    elif isinstance(value, str):
        return f'"{value}"'
    else:
        return str(value).lower() if isinstance(value, bool) else str(value)

def check_field(session, url, operation_type, field, types, semaphore, max_retries=3):
    query_name = field["name"]
    args = field.get("args", [])
    arg_values = {arg["name"]: build_test_payload(arg, types) for arg in args}
    field_str = build_field_selection(field, types)
    base_type = unwrap_type(field["type"])
    
    for attempt in range(max_retries + 1):
        try:
            semaphore.acquire()
            if operation_type == "query":
                if arg_values:
                    arg_str = "(" + ", ".join(f"{k}: {serialize_arg_value(v)}" for k,v in arg_values.items()) + ")"
                    gql = {"query": f"query {{ {query_name}{arg_str} {{ {field_str} }} }}" if base_type["kind"] == "OBJECT" else f"query {{ {query_name}{arg_str} }}"}
                else:
                    gql = {"query": f"query {{ {field_str} }}"}
            elif operation_type == "mutation":
                arg_str = "(" + ", ".join(f"{k}: {serialize_arg_value(v)}" for k,v in arg_values.items()) + ")" if arg_values else ""
                if base_type["kind"] == "OBJECT":
                    gql = {"query": f"mutation {{ {query_name}{arg_str} {{ {field_str} }} }}"}
                else:
                    gql = {"query": f"mutation {{ {query_name}{arg_str} }}"}

            resp = session.post(url, json=gql, timeout=60)
            return {
                "url": url,
                "operation": f"{operation_type}.{query_name}",
                "status": resp.status_code,
                "response": resp.text[:200],
                "args_used": arg_values,
                "query": gql["query"][:100] + "..." if len(gql["query"]) > 100 else gql["query"],
                "attempts": attempt + 1
            }
        except Exception as e:
            if attempt < max_retries:
                print(f"[!] {url} {operation_type}.{query_name} -> Attempt {attempt + 1} failed with error: {str(e)}. Retrying...")
                time.sleep(1)  # Backoff before retry
                continue
            return {
                "url": url,
                "operation": f"{operation_type}.{query_name}",
                "error": str(e),
                "args_used": arg_values,
                "query": gql["query"][:100] + "..." if len(gql["query"]) > 100 else gql["query"],
                "attempts": attempt + 1
            }
        finally:
            semaphore.release()

def process_url(url, session, threads, max_retries=3):
    schema = introspect_schema(session, url)
    if not schema or "data" not in schema:
        print(f"[!] No schema fetched for {url}, skipping.")
        return []

    types = schema["data"]["__schema"]["types"]
    query_type_name = schema["data"]["__schema"]["queryType"]["name"]
    mutation_type_name = schema["data"]["__schema"]["mutationType"]["name"] if schema["data"]["__schema"].get("mutationType") else None

    semaphore = threading.Semaphore(threads)
    tasks = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for t in types:
            if t["name"] == query_type_name and t.get("fields"):
                for f in t["fields"]:
                    tasks.append(executor.submit(check_field, session, url, "query", f, types, semaphore, max_retries))
            if mutation_type_name and t["name"] == mutation_type_name and t.get("fields"):
                for f in t["fields"]:
                    tasks.append(executor.submit(check_field, session, url, "mutation", f, types, semaphore, max_retries))

        results = []
        for future in as_completed(tasks):
            result = future.result()
            if "error" in result:
                print(f"[!] {result['url']} {result['operation']} -> ERROR after {result['attempts']} attempts: {result['error']}")
                if result.get('args_used'):
                    print(f"    Args used: {result['args_used']}")
                if result.get('query'):
                    print(f"    Query: {result['query']}")
            else:
                status_symbol = "[+]" if result['status'] == 200 else "[!]"
                print(f"{status_symbol} {result['url']} {result['operation']} -> {result['status']} (Attempts: {result['attempts']})")
                if result.get('args_used') and result['status'] != 200:
                    print(f"    Args used: {result['args_used']}")
                if result.get('query') and result['status'] != 200:
                    print(f"    Query: {result['query']}")
                if result['status'] != 200 and 'response' in result:
                    print(f"    Response: {result['response']}")
            results.append(result)

    return results

def main():
    parser = argparse.ArgumentParser(description="GraphQL Proxy Checker with Retries")
    parser.add_argument("-u", "--url", help="GraphQL endpoint URL")
    parser.add_argument("-f", "--file", help="File with GraphQL endpoint URLs (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--proxy", help="Proxy URL (example: http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests")
    args = parser.parse_args()

    if not args.url and not args.file:
        print("[!] Error: Either --url or --file must be provided.")
        parser.print_help()
        return

    session = make_session(proxy=args.proxy, insecure=args.insecure)
    all_results = []

    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                print(f"[+] Processing URL: {url}")
                results = process_url(url, session, args.threads, args.retries)
                all_results.extend(results)
        except FileNotFoundError:
            print(f"[!] Error: File {args.file} not found.")
            return
        except Exception as e:
            print(f"[!] Error reading file {args.file}: {e}")
            return
    else:
        all_results = process_url(args.url, session, args.threads, args.retries)

    print("[+] Done. Total requests attempted:", len(all_results))
    
    status_counts = {}
    for r in all_results:
        if 'status' in r:
            status_counts[r['status']] = status_counts.get(r['status'], 0) + 1
    
    print(f"[+] Status code distribution: {status_counts}")
    print(json.dumps({"summary": {"total_operations_attempted": len(all_results), "status_distribution": status_counts}}, indent=2))

if __name__ == "__main__":
    main()
import requests
import json
import argparse
import threading
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print_lock = threading.Lock()

def thread_safe_print(message):
    with print_lock:
        print(message)

# === Circuit Breaker ===
_error_counts = {}      # url -> consecutive error count
_dead_urls = set()      # urls that exceeded threshold
_cb_lock = threading.Lock()
CB_THRESHOLD = 5        # skip after this many consecutive errors

def is_dead(url):
    return url in _dead_urls

def record_error(url):
    with _cb_lock:
        _error_counts[url] = _error_counts.get(url, 0) + 1
        if _error_counts[url] >= CB_THRESHOLD and url not in _dead_urls:
            _dead_urls.add(url)
            thread_safe_print(f"[SKIP] {url} — {CB_THRESHOLD} consecutive errors, skipping remaining requests")

def record_success(url):
    with _cb_lock:
        _error_counts[url] = 0  # reset on success

# === Auth ===
def build_headers(args):
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json"
    }
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.api_key and args.api_key_header:
        headers[args.api_key_header] = args.api_key
    return headers

# === Folder helpers ===
def prepare_results_folder(results_dir, mode, url):
    sanitized_url = re.sub(r'[:/\.]+', '_', url)
    mode_dir = os.path.join(results_dir, mode, sanitized_url)
    os.makedirs(mode_dir, exist_ok=True)
    return mode_dir

# === GraphQL helpers ===
def post_graphql(url, query, headers, timeout=10):
    if is_dead(url):
        return None
    try:
        resp = requests.post(url, headers=headers, json=query, timeout=timeout, verify=False)
        if resp.status_code == 200:
            record_success(url)
            return resp
        record_error(url)
    except Exception as e:
        thread_safe_print(f"[ERROR] {e}")
        record_error(url)
    return None

def is_success(resp):
    """Check if response contains real data (not null, not only errors)."""
    if resp is None:
        return False
    ctype = resp.headers.get("content-type", "").lower()
    if "application/json" not in ctype and "text/plain" not in ctype:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    # Must have "data" key and it must not be None/empty
    data = body.get("data")
    if not data:
        return False
    # If errors exist alongside data — still interesting, but flag it
    return True

def save_result(filepath, url, query_json, resp):
    curl_cmd = (
        f"curl -k -X POST \"{url}\" "
        f"-H 'Content-Type: application/json' "
        f"--data '{json.dumps(query_json)}'"
    )
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(curl_cmd + "\n\n###\n\n")
        try:
            f.write(json.dumps(resp.json(), indent=2, ensure_ascii=False))
        except Exception:
            f.write(resp.text)

# === Introspection ===
INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields(includeDeprecated: true) {
            name
            args { name type { kind name ofType { kind name ofType { kind name } } } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """
}

def get_schema(url, headers):
    resp = post_graphql(url, INTROSPECTION_QUERY, headers)
    if resp:
        try:
            data = resp.json()
            return data.get("data", {}).get("__schema")
        except Exception:
            pass
    return None

def get_named_type(type_obj):
    t = type_obj
    while t and t.get("ofType"):
        t = t["ofType"]
    return t.get("name") if t else None

def get_fields_recursive(type_name, schema_types, visited=None, depth=0):
    if visited is None:
        visited = set()
    if type_name in visited or not type_name or depth > 3:
        return ["__typename"]
    visited.add(type_name)
    obj_type = next((t for t in schema_types if t["name"] == type_name and t.get("fields")), None)
    if not obj_type:
        return ["__typename"]
    fields = []
    for f in obj_type["fields"]:
        nested = get_named_type(f["type"])
        if nested and any(t["name"] == nested and t.get("fields") for t in schema_types):
            nested_fields = get_fields_recursive(nested, schema_types, visited.copy(), depth + 1)
            fields.append(f"{f['name']} {{ {' '.join(nested_fields)} }}")
        else:
            fields.append(f["name"])
    return fields

# === PII Detection ===
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

PII_SEVERITY = {
    "ssn": "Critical", "socialsecurity": "Critical", "creditcard": "Critical",
    "cardnumber": "Critical", "bankaccount": "Critical", "iban": "Critical",
    "password": "Critical", "passport": "Critical",
    "email": "High", "phone": "High", "taxid": "High", "nationalid": "High",
    "driverlicense": "High", "token": "High", "session": "High",
    "address": "Medium", "birthdate": "Medium", "dob": "Medium",
    "name": "Low", "username": "Low", "city": "Low", "zip": "Low",
}

def get_pii_severity(field_name):
    fname = field_name.lower()
    for key, sev in PII_SEVERITY.items():
        if key in fname:
            return sev
    return "Low"

def find_pii_fields(schema):
    pii_fields = []
    for t in schema.get("types", []):
        if t.get("fields"):
            for f in t["fields"]:
                if any(kw in f["name"].lower() for kw in PII_KEYWORDS):
                    pii_fields.append({
                        "type": t["name"],
                        "field": f["name"],
                        "field_type": f["type"],
                        "severity": get_pii_severity(f["name"])
                    })
    return pii_fields

def check_pii(url, headers, results_dir, threads):
    pii_dir = prepare_results_folder(results_dir, "pii", url)
    schema = get_schema(url, headers)
    if not schema:
        thread_safe_print(f"[ERROR] Cannot get schema for {url}")
        return []

    pii_fields = find_pii_fields(schema)
    schema_types = schema.get("types", [])
    findings = []

    def run_pii_field(field):
        type_name = get_named_type(field["field_type"])
        type_obj = next((t for t in schema_types if t["name"] == type_name and t.get("fields")), None)
        if type_obj:
            fb = " ".join(get_fields_recursive(type_name, schema_types))
            query_str = f"{{ {field['field']} {{ {fb} }} }}"
        else:
            query_str = f"{{ {field['field']} }}"
        query_json = {"query": query_str}
        resp = post_graphql(url, query_json, headers)
        if is_success(resp):
            sev = field["severity"]
            thread_safe_print(f"[{sev}] PII field accessible: {field['field']} ({url})")
            fname = f"{field['type']}_{field['field']}.txt"
            save_result(os.path.join(pii_dir, fname), url, query_json, resp)
            try:
                response_body = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            except Exception:
                response_body = resp.text
            return {**field, "query": query_str, "url": url, "response": response_body}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(run_pii_field, f) for f in pii_fields]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                findings.append(res)

    return findings

# === Operations Checker ===
COMMON_VALUES = {
    "id": ["1", "2", "me", "current", "admin",
           "00000000-0000-0000-0000-000000000001"],  # UUID fallback
    "user": ["1", "me", "admin"],
    "status": ["active", "pending", "open"],
    "limit": ["10"],
    "page": ["1"],
    "email": ["test@example.com"],
    "name": ["test"],
}

def guess_value(param_name):
    for key, values in COMMON_VALUES.items():
        if key in param_name.lower():
            return values[0]
    return "1"

def build_operation_query(op_name, op_args, op_type_name, schema_types):
    arg_parts = [f"{a}: {json.dumps(guess_value(a))}" for a in op_args]
    arg_block = f"({', '.join(arg_parts)})" if arg_parts else ""
    fields_block = ""
    if op_type_name:
        fields = get_fields_recursive(op_type_name, schema_types)
        fields_block = "{ " + " ".join(fields) + " }"
    return f"{{ {op_name}{arg_block} {fields_block} }}"

def extract_operations(schema):
    ops = []
    for t in schema.get("types", []):
        if t.get("fields"):
            for f in t["fields"]:
                args = [a["name"] for a in f.get("args", [])]
                type_name = get_named_type(f.get("type", {}))
                ops.append({"name": f["name"], "args": args, "type_name": type_name})
    return ops

def check_operations(url, headers, results_dir, threads, schema=None):
    checker_dir = prepare_results_folder(results_dir, "checker", url)
    if not schema:
        schema = get_schema(url, headers)
    if not schema:
        thread_safe_print(f"[ERROR] Cannot get schema for {url}")
        return []

    schema_types = schema.get("types", [])
    operations = extract_operations(schema)
    findings = []

    def run_op(op):
        query_str = build_operation_query(op["name"], op["args"], op["type_name"], schema_types)
        query_json = {"query": query_str}
        resp = post_graphql(url, query_json, headers)
        if is_success(resp):
            thread_safe_print(f"[SUCCESS] Operation accessible: {op['name']} ({url})")
            save_result(os.path.join(checker_dir, f"{op['name']}.txt"), url, query_json, resp)
            try:
                response_body = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            except Exception:
                response_body = resp.text
            return {**op, "query": query_str, "url": url, "response": response_body}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(run_op, op) for op in operations]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                findings.append(res)

    return findings

# === IDOR Check ===
ID_ARGS = ["id", "userId", "user_id", "accountId", "account_id", "customerId", "customer_id"]

def check_idor(url, headers, results_dir, threads, schema=None, idor_ids=None):
    """
    For every operation that takes an ID-like argument, try a range of IDs.
    Compare responses — if different IDs return different data, it's likely IDOR.
    """
    idor_dir = prepare_results_folder(results_dir, "idor", url)
    if not schema:
        schema = get_schema(url, headers)
    if not schema:
        thread_safe_print(f"[ERROR] Cannot get schema for {url}")
        return []

    schema_types = schema.get("types", [])
    operations = extract_operations(schema)
    ids_to_try = idor_ids if idor_ids else ["1", "2", "3", "4", "5",
                                            "00000000-0000-0000-0000-000000000001",
                                            "00000000-0000-0000-0000-000000000002"]
    findings = []

    def run_idor(op, id_arg):
        results_per_id = {}
        for test_id in ids_to_try:
            # Build query with this specific ID, other args get defaults
            arg_parts = []
            for a in op["args"]:
                if a == id_arg:
                    arg_parts.append(f"{a}: {json.dumps(test_id)}")
                else:
                    arg_parts.append(f"{a}: {json.dumps(guess_value(a))}")
            arg_block = f"({', '.join(arg_parts)})"
            fields_block = ""
            if op["type_name"]:
                fields = get_fields_recursive(op["type_name"], schema_types)
                fields_block = "{ " + " ".join(fields) + " }"
            query_str = f"{{ {op['name']}{arg_block} {fields_block} }}"
            query_json = {"query": query_str}
            resp = post_graphql(url, query_json, headers)
            if is_success(resp):
                try:
                    results_per_id[test_id] = resp.json()
                except Exception:
                    results_per_id[test_id] = resp.text

        if len(results_per_id) > 1:
            unique_responses = {json.dumps(v, sort_keys=True) for v in results_per_id.values()}
            if len(unique_responses) > 1:
                thread_safe_print(f"[IDOR] Different data for different IDs: {op['name']}({id_arg}) ({url})")
            else:
                thread_safe_print(f"[IDOR?] Same data for all IDs (might still be IDOR): {op['name']}({id_arg}) ({url})")

            fname = f"idor_{op['name']}_{id_arg}.txt"
            with open(os.path.join(idor_dir, fname), "w", encoding="utf-8") as f:
                for test_id, data in results_per_id.items():
                    f.write(f"=== ID: {test_id} ===\n")
                    f.write(json.dumps(data, indent=2, ensure_ascii=False))
                    f.write("\n\n")
            return {"op": op["name"], "arg": id_arg, "ids_hit": list(results_per_id.keys()),
                    "url": url, "responses": results_per_id}
        return None

    tasks = []
    for op in operations:
        for arg in op["args"]:
            if any(id_kw in arg.lower() for id_kw in ["id", "user", "account", "customer"]):
                tasks.append((op, arg))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(run_idor, op, arg) for op, arg in tasks]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                findings.append(res)

    return findings

# === Batch Requests ===
def check_batch(url, headers, results_dir, schema=None):
    """
    Send multiple queries in a single batch request.
    Tests if batching is enabled (often bypasses rate limiting).
    """
    batch_dir = prepare_results_folder(results_dir, "batch", url)
    if not schema:
        schema = get_schema(url, headers)
    if not schema:
        thread_safe_print(f"[ERROR] Cannot get schema for {url}")
        return []

    schema_types = schema.get("types", [])
    operations = extract_operations(schema)[:10]  # take first 10 ops for batch test

    batch_payload = []
    for op in operations:
        query_str = build_operation_query(op["name"], op["args"], op["type_name"], schema_types)
        batch_payload.append({"query": query_str})

    try:
        resp = requests.post(url, headers=headers, json=batch_payload, timeout=15, verify=False)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    thread_safe_print(f"[BATCH] Batching ENABLED on {url} — {len(data)} responses received")
                    fpath = os.path.join(batch_dir, "batch_result.txt")
                    curl_cmd = (
                        f"curl -k -X POST \"{url}\" "
                        f"-H 'Content-Type: application/json' "
                        f"--data '{json.dumps(batch_payload)}'"
                    )
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(curl_cmd + "\n\n###\n\n")
                        f.write(json.dumps(data, indent=2, ensure_ascii=False))
                    response_body = json.dumps(data, indent=2, ensure_ascii=False)
                    return [{"url": url, "batch_size": len(data), "enabled": True, "response": response_body}]
                else:
                    thread_safe_print(f"[BATCH] Batching not supported or returned single response on {url}")
            except Exception:
                pass
    except Exception as e:
        thread_safe_print(f"[ERROR] Batch request failed: {e}")
    return []

# === Aliases (Rate Limit Bypass) ===
def check_aliases(url, headers, results_dir, schema=None, alias_count=10):
    """
    Send a single query with many aliases — effectively N requests in one.
    Can bypass per-request rate limits.
    """
    alias_dir = prepare_results_folder(results_dir, "aliases", url)
    if not schema:
        schema = get_schema(url, headers)
    if not schema:
        thread_safe_print(f"[ERROR] Cannot get schema for {url}")
        return []

    schema_types = schema.get("types", [])
    operations = extract_operations(schema)

    # Find operations with ID-like args — most useful for alias abuse
    id_ops = [op for op in operations
               if any("id" in a.lower() for a in op["args"])][:3]

    findings = []
    for op in id_ops:
        alias_parts = []
        ids = list(range(1, alias_count + 1))
        for i, test_id in enumerate(ids):
            arg_parts = []
            for a in op["args"]:
                val = str(test_id) if "id" in a.lower() else guess_value(a)
                arg_parts.append(f"{a}: {json.dumps(val)}")
            arg_block = f"({', '.join(arg_parts)})"
            fields_block = ""
            if op["type_name"]:
                fields = get_fields_recursive(op["type_name"], schema_types)
                fields_block = "{ " + " ".join(fields) + " }"
            alias_parts.append(f"r{i}: {op['name']}{arg_block} {fields_block}")

        query_str = "{ " + " ".join(alias_parts) + " }"
        query_json = {"query": query_str}
        resp = post_graphql(url, query_json, headers)
        if is_success(resp):
            thread_safe_print(f"[ALIASES] Rate limit bypass works for {op['name']} ({alias_count} aliases) on {url}")
            fpath = os.path.join(alias_dir, f"aliases_{op['name']}.txt")
            save_result(fpath, url, query_json, resp)
            try:
                response_body = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            except Exception:
                response_body = resp.text
            findings.append({"op": op["name"], "alias_count": alias_count, "url": url, "response": response_body})

    return findings

# === Markdown Report ===
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

def generate_report(url, pii_findings, op_findings, idor_findings, batch_findings, alias_findings, output_dir):
    lines = [
        f"# GraphQL Security Report",
        f"\n**Target:** `{url}`\n",
        "---\n",
    ]

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| PII Fields Exposed | {len(pii_findings)} |")
    lines.append(f"| Unauthenticated Operations | {len(op_findings)} |")
    lines.append(f"| IDOR Candidates | {len(idor_findings)} |")
    lines.append(f"| Batch Enabled | {'Yes' if batch_findings else 'No'} |")
    lines.append(f"| Alias Rate-Limit Bypass | {'Yes' if alias_findings else 'No'} |")
    lines.append("")

    # PII
    if pii_findings:
        lines.append("## PII Fields Exposed\n")
        sorted_pii = sorted(pii_findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Low"), 4))
        for f in sorted_pii:
            sev = f.get("severity", "Low")
            lines.append(f"### [{sev}] `{f['field']}` (on type `{f['type']}`)\n")
            lines.append(f"**PoC Query:**\n```graphql\n{f.get('query', '')}\n```\n")
            if f.get("response"):
                lines.append(f"**Server Response:**\n```json\n{f['response']}\n```\n")

    # Unauthenticated ops
    if op_findings:
        lines.append("## Unauthenticated Operations\n")
        for f in op_findings:
            lines.append(f"### `{f['name']}`\n")
            lines.append(f"**PoC Query:**\n```graphql\n{f.get('query', '')}\n```\n")
            if f.get("response"):
                lines.append(f"**Server Response:**\n```json\n{f['response']}\n```\n")

    # IDOR
    if idor_findings:
        lines.append("## IDOR Candidates\n")
        for f in idor_findings:
            lines.append(f"### `{f['op']}` (arg: `{f['arg']}`)\n")
            lines.append(f"Responded to IDs: {', '.join(f['ids_hit'])}\n")
            lines.append("**Impact:** Potential access to other users' data.\n")
            if f.get("responses"):
                for test_id, resp_body in f["responses"].items():
                    lines.append(f"**Response for ID `{test_id}`:**\n```json\n{json.dumps(resp_body, indent=2, ensure_ascii=False)}\n```\n")

    # Batch
    if batch_findings:
        lines.append("## Batch Requests Enabled\n")
        lines.append("The server accepts batched GraphQL queries. This can be abused to:\n")
        lines.append("- Bypass rate limiting\n- Enumerate data in bulk\n- Amplify other attacks\n")
        for f in batch_findings:
            if f.get("response"):
                lines.append(f"**Server Response (first 2000 chars):**\n```json\n{f['response'][:2000]}\n```\n")

    # Aliases
    if alias_findings:
        lines.append("## Alias-based Rate Limit Bypass\n")
        for f in alias_findings:
            lines.append(f"### `{f['op']}` — {f['alias_count']} aliases in one request\n")
            if f.get("response"):
                lines.append(f"**Server Response (first 2000 chars):**\n```json\n{f['response'][:2000]}\n```\n")

    report_path = os.path.join(output_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    thread_safe_print(f"\n[REPORT] Saved to {report_path}")
    return report_path

# === Main ===
def main():
    parser = argparse.ArgumentParser(description="GraphQL Security Analyzer")
    parser.add_argument("-m", "--mode", choices=["pii", "checker", "idor", "batch", "aliases", "all"],
                        default="all")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single GraphQL endpoint URL")
    group.add_argument("-f", "--file", help="File with list of endpoints")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("-o", "--output", default="graphql_results")

    # Auth options
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--token", help="Bearer token (Authorization: Bearer ...)")
    auth.add_argument("--cookie", help="Cookie header value")
    auth.add_argument("--api-key", help="API key value")
    auth.add_argument("--api-key-header", default="X-API-Key", help="Header name for API key (default: X-API-Key)")

    # IDOR options
    parser.add_argument("--idor-ids", nargs="+",
                        help="Custom IDs to try for IDOR (default: 1-5 + UUIDs)")
    parser.add_argument("--alias-count", type=int, default=10,
                        help="Number of aliases to use in alias check (default: 10)")

    args = parser.parse_args()

    if os.path.exists(args.output):
        import shutil
        shutil.rmtree(args.output)
        thread_safe_print(f"[CLEAN] Removed old results folder: {args.output}")
    os.makedirs(args.output, exist_ok=True)
    headers = build_headers(args)

    urls = [args.domain] if args.domain else open(args.file).read().splitlines()
    urls = [u.strip() for u in urls if u.strip()]

    for url in urls:
        thread_safe_print(f"\n{'='*60}")
        thread_safe_print(f"[TARGET] {url}")
        thread_safe_print(f"{'='*60}")

        # Fetch schema once, reuse across modes
        schema = get_schema(url, headers)
        if not schema:
            thread_safe_print(f"[WARN] Introspection disabled or unreachable — skipping {url}")
            continue

        pii_findings = op_findings = idor_findings = batch_findings = alias_findings = []

        if args.mode in ["pii", "all"]:
            thread_safe_print(f"\n[*] PII Check")
            pii_findings = check_pii(url, headers, args.output, args.threads)

        if args.mode in ["checker", "all"]:
            thread_safe_print(f"\n[*] Operations Check")
            op_findings = check_operations(url, headers, args.output, args.threads, schema=schema)

        if args.mode in ["idor", "all"]:
            thread_safe_print(f"\n[*] IDOR Check")
            idor_findings = check_idor(url, headers, args.output, args.threads,
                                       schema=schema, idor_ids=args.idor_ids)

        if args.mode in ["batch", "all"]:
            thread_safe_print(f"\n[*] Batch Check")
            batch_findings = check_batch(url, headers, args.output, schema=schema)

        if args.mode in ["aliases", "all"]:
            thread_safe_print(f"\n[*] Aliases Check")
            alias_findings = check_aliases(url, headers, args.output,
                                           schema=schema, alias_count=args.alias_count)

        # Report per URL
        url_output = os.path.join(args.output, re.sub(r'[:/\.]+', '_', url))
        os.makedirs(url_output, exist_ok=True)
        generate_report(url, pii_findings, op_findings, idor_findings,
                        batch_findings, alias_findings, url_output)

    thread_safe_print(f"\n[DONE] Results saved to {args.output}/")

if __name__ == "__main__":
    main()

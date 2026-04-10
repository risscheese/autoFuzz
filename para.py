#!/usr/bin/env python3

# ============================================================
#  para.py — Fast HTML form & API param discovery
#  Used by autofuzz.sh Stage 3
#  Usage: python3 para.py <urls_file>
# ============================================================

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}

# ── Skippable input types (low recon value) ──────────────────
SKIP_TYPES = {'submit', 'button', 'image', 'reset'}


def fetch_url(url, timeout=5):
    """Fetch a URL with one retry on timeout using a longer fallback."""
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
    except requests.exceptions.Timeout:
        try:
            return requests.get(url, headers=HEADERS, timeout=15, verify=False)
        except requests.exceptions.RequestException:
            return None
    except requests.exceptions.RequestException:
        return None


def resolve_action(base_url, action):
    """Resolve a form action to a full absolute URL."""
    if not action or action.strip() == '#':
        return base_url
    return urljoin(base_url, action)


def extract_select_values(select_tag):
    """Pull option values from a <select> element."""
    options = select_tag.find_all('option')
    return [o.get('value', o.get_text(strip=True)) for o in options if o.get('value') or o.get_text(strip=True)]


def scan_json_endpoint(url, response):
    """If the endpoint returns JSON, extract top-level keys as params."""
    content_type = response.headers.get('Content-Type', '')
    if 'application/json' in content_type:
        try:
            data = response.json()
            if isinstance(data, dict):
                return list(data.keys())
        except Exception:
            pass
    return []


def scan_url(url):
    """
    Scan a single URL for forms, params, and accepted methods.
    Returns a structured result dict.
    """
    print(f"\n[*] Scanning: {url}")

    result = {
        'url': url,
        'forms': [],
        'json_params': [],
        'error': None
    }

    response = fetch_url(url)
    if response is None:
        result['error'] = 'Connection failed'
        print(f"    [!] Connection Error: could not reach {url}")
        return result

    # --- JSON endpoint check ---------------------------------
    json_params = scan_json_endpoint(url, response)
    if json_params:
        result['json_params'] = json_params
        print(f"    [+] JSON endpoint detected. Top-level keys: {', '.join(json_params)}")

    # --- HTML form parsing -----------------------------------
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    if not forms and not json_params:
        print("    [-] No HTML forms or JSON params found.")
        return result

    if forms:
        print(f"    [+] Found {len(forms)} form(s)!")

    for i, form in enumerate(forms):
        method  = form.get('method', 'get').upper()
        action  = resolve_action(url, form.get('action'))
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')

        form_data = {
            'index':   i + 1,
            'method':  method,
            'action':  action,
            'enctype': enctype,
            'params':  []
        }

        print(f"\n    --- Form {i+1} ---")
        print(f"    Method  : {method}")
        print(f"    Action  : {action}")
        print(f"    Enctype : {enctype}")
        print(f"    Params  :")

        inputs = form.find_all(['input', 'textarea', 'select'])
        param_count = 0

        for field in inputs:
            name       = field.get('name')
            field_type = field.get('type', 'text').lower()

            # Skip unnamed fields and low-value types
            if not name or field_type in SKIP_TYPES:
                continue

            param_info = {'name': name, 'type': field_type}

            # Extract <select> option values
            if field.name == 'select':
                options = extract_select_values(field)
                param_info['options'] = options
                print(f"      - {name} (Type: select, Options: {options})")
            else:
                print(f"      - {name} (Type: {field_type})")

            form_data['params'].append(param_info)
            param_count += 1

        if param_count == 0:
            print("      - None found (may be JavaScript-driven)")

        result['forms'].append(form_data)

    return result


def write_report(results, report_path):
    """Append Stage 3 results to the param_discovery_report.txt."""
    with open(report_path, 'a') as f:
        for r in results:
            f.write("════════════════════════════════════════\n")
            f.write(f"URL       : {r['url']}\n")

            if r.get('error'):
                f.write(f"Error     : {r['error']}\n\n")
                continue

            if r.get('json_params'):
                f.write("\n  JSON Params:\n")
                for p in r['json_params']:
                    f.write(f"    • {p}\n")

            for form in r.get('forms', []):
                f.write(f"\n  Form {form['index']}:\n")
                f.write(f"    Method  : {form['method']}\n")
                f.write(f"    Action  : {form['action']}\n")
                f.write(f"    Enctype : {form['enctype']}\n")
                f.write(f"    Params  :\n")
                if form['params']:
                    for p in form['params']:
                        line = f"      • {p['name']} (Type: {p['type']})"
                        if 'options' in p:
                            line += f" Options: {p['options']}"
                        f.write(line + "\n")
                else:
                    f.write("      • none\n")

            f.write("\n")


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 para.py <urls.txt> [report.txt]")
        sys.exit(1)

    target_file = sys.argv[1]
    report_file = sys.argv[2] if len(sys.argv) == 3 else "param_discovery_report.txt"

    try:
        with open(target_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: Could not find file '{target_file}'")
        sys.exit(1)

    print(f"Starting param scan on {len(urls)} URLs...")
    print("=" * 50)

    results      = []
    total_forms  = 0
    total_params = 0

    for url in urls:
        if not url.startswith('http'):
            url = 'http://' + url

        result = scan_url(url)
        results.append(result)

        for form in result.get('forms', []):
            total_forms  += 1
            total_params += len(form['params'])

        print("-" * 50)
    
    # Write only results where params were found
    results_with_params = [
        r for r in results
        if r.get('json_params') or any(f['params'] for f in r.get('forms', []))
    ]
    write_report(results_with_params, report_file)
    
    # Final summary
    print(f"\n{'='*50}")
    print(f"[+] Scan Complete")
    print(f"    URLs scanned : {len(urls)}")
    print(f"    Forms found  : {total_forms}")
    print(f"    Params found : {total_params}")
    print(f"    Report saved : {report_file}")


if __name__ == "__main__":
    main()

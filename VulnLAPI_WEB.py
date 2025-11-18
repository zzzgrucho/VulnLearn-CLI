#!/usr/bin/env python3
import requests
import json
import urllib.parse
import time
import socket
import ssl
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup
from prettytable import PrettyTable

RESET = "\033[0m"
BOLD = "\033[1m"

CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREY = "\033[90m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"

VULN_COLOR = "\033[96m"
REQUEST_TIMEOUT = 6
HEADERS_DEFAULT = {
    "User-Agent": "vulnlearn-dast-lite/1.0",
    "Content-Type": "application/json"
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Content-Security-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

BODY_INJECTION_PAYLOADS = [
    {"isAdmin": True},
    {"role": "admin"},
    {"admin": 1},
]

SPECIAL_CHARS_LIST = [
    "'", "\"", "<", ">", "<script>",
    "../", "..\\", "%0d%0a", ";--", "${7*7}"
]

ALTERNATE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def print_banner():
    alpaca = r"""
             __  _
         .-.'  `; `-._  ____
        (_,         .-:'  `; `-._
      ,'o"(        (_,           )
     (__,-'      ,'o"(            )>
        (       (__,-'            )
         `-'._.--._(             )
            ||||  ||||`-'._.--._.-'
    """

    title = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗     
██║   ██║██║   ██║██║     ████╗  ██║██║     
██║   ██║██║   ██║██║     ██╔██╗ ██║██║     
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝
    """

    print(MAGENTA + alpaca + RESET)
    print(CYAN + title + RESET)
    print(YELLOW + "="*90 + RESET)
    print(GREEN + "Bienvenido al DAST Lite de VulnLearn — Seguridad educativa y automatizada." + RESET)
    print(YELLOW + "="*90 + RESET + "\n")


def send_request(host, endpoint, method, headers=None, data=None):
    headers = headers or HEADERS_DEFAULT.copy()

    if not host.startswith("http://") and not host.startswith("https://"):
        host = "http://" + host

    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        url = endpoint
    else:
        url = f"{host.rstrip('/')}/{endpoint.lstrip('/')}"

    try:
        if method.upper() == "GET":
            return requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            return requests.request(
                method.upper(),
                url,
                headers=headers,
                json=data if method.upper() in ["POST", "PUT", "PATCH"] else None,
                timeout=REQUEST_TIMEOUT
            )
    except requests.exceptions.RequestException:
        return None


def print_finding(f):
    print(f"{VULN_COLOR}{BOLD}[!] {f['module']} detectado{RESET}")
    print(f"    {MAGENTA}Endpoint:{RESET} {f['tested_endpoint']}")
    print(f"    {CYAN}Payload:{RESET} {f['payload']}")
    print(f"    {BLUE}HTTP Status:{RESET} {f['status']}")
    print(f"    {GREY}Evidencia:{RESET} {f['evidence']}")
    print(GREY + "-"*70 + RESET + "\n")



def test_method_override(host, endpoint, method, headers, data):
    for alt in ALTERNATE_METHODS:
        if alt == method.upper():
            continue

        resp = send_request(host, endpoint, alt, headers)
        if resp and resp.status_code == 200:
            return {
                "module": "MethodOverride",
                "payload": alt,
                "tested_endpoint": endpoint,
                "status": resp.status_code,
                "evidence": f"Servidor aceptó {alt} con 200 OK."
            }
    return None


def test_weak_input(host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"]:
        return None

    resp = send_request(host, endpoint, method, headers, {})
    if resp and resp.status_code == 200:
        return {
            "module": "WeakInputHandling",
            "payload": "<empty-body>",
            "tested_endpoint": endpoint,
            "status": resp.status_code,
            "evidence": "El servidor aceptó un body vacío."
        }
    return None


def test_server_header(host, endpoint, method, headers, data):
    resp = send_request(host, endpoint, "GET", headers)
    if resp and "Server" in resp.headers:
        return {
            "module": "ServerHeader",
            "payload": resp.headers["Server"],
            "tested_endpoint": endpoint,
            "status": resp.status_code,
            "evidence": f"Cabecera Server: {resp.headers['Server']}"
        }
    return None


def test_header_injection(host, endpoint, method, headers, data):
    test_headers = headers.copy()
    test_headers["Cabecera-Inyectada"] = "prueba"

    resp = send_request(host, endpoint, method, test_headers, data)
    if resp and resp.status_code == 200:
        return {
            "module": "HeaderInjection",
            "payload": "Cabecera-Inyectada: prueba",
            "tested_endpoint": endpoint,
            "status": resp.status_code,
            "evidence": "El servidor aceptó cabeceras arbitrarias."
        }
    return None


def test_body_param_injection(host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"] or not isinstance(data, dict) or not data:
        return None

    for extra in BODY_INJECTION_PAYLOADS:
        test_data = data.copy()
        test_data.update(extra)

        resp = send_request(host, endpoint, method, headers, test_data)
        if resp and resp.status_code in [200, 201]:
            return {
                "module": "BodyParamInjection",
                "payload": json.dumps(extra),
                "tested_endpoint": endpoint,
                "status": resp.status_code,
                "evidence": "El servidor aceptó parámetros no permitidos."
            }
    return None


def test_token_validity(host, endpoint, method, headers, data):
    token_header = None

    for k in headers.keys():
        if k.lower() in ["authorization", "cookie"]:
            token_header = k
            break

    if not token_header:
        return None

    baseline = send_request(host, endpoint, method, headers, data)
    if not baseline:
        return None

    base_status = baseline.status_code

    h_no = headers.copy()
    h_no.pop(token_header, None)
    resp_no = send_request(host, endpoint, method, h_no, data)

    h_t = headers.copy()
    v = h_t[token_header]
    h_t[token_header] = (v[:-1] + "X") if len(v) > 1 else v + "X"
    resp_t = send_request(host, endpoint, method, h_t, data)

    issues = []

    if resp_no and resp_no.status_code == base_status:
        issues.append("sin token")

    if resp_t and resp_t.status_code == base_status:
        issues.append("token modificado")

    if issues:
        return {
            "module": "TokenValidity",
            "payload": ", ".join(issues),
            "tested_endpoint": endpoint,
            "status": base_status,
            "evidence": "El servidor no validó adecuadamente el token."
        }

    return None


def test_special_chars_body(host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"] or not isinstance(data, dict):
        return None

    special_str = " ".join(SPECIAL_CHARS_LIST)

    for key, val in data.items():
        if isinstance(val, str):
            test_data = data.copy()
            test_data[key] = val + " " + special_str
            resp = send_request(host, endpoint, method, headers, test_data)
            if resp and resp.status_code == 200:
                return {
                    "module": "SpecialCharsInBody",
                    "payload": f"{key} -> {special_str}",
                    "tested_endpoint": endpoint,
                    "status": resp.status_code,
                    "evidence": "El endpoint aceptó caracteres especiales."
                }
    return None


def test_tls_security(host, endpoint, method, headers, data):
    parsed = urllib.parse.urlparse(host)
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    if scheme != "https":
        return {
            "module": "TLSSecurity",
            "payload": "Sin HTTPS",
            "tested_endpoint": host,
            "status": "N/A",
            "evidence": "El host no usa HTTPS."
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
    except Exception as e:
        return {
            "module": "TLSSecurity",
            "payload": "Error",
            "tested_endpoint": host,
            "status": "N/A",
            "evidence": str(e)
        }

    return {
        "module": "TLSSecurity",
        "payload": tls_version,
        "tested_endpoint": host,
        "status": "N/A",
        "evidence": f"TLS utilizado: {tls_version}"
    }


def test_security_headers(host, endpoint, method, headers, data):
    resp = send_request(host, endpoint, "GET", headers)
    if not resp:
        return None

    missing = []

    for h in SECURITY_HEADERS:
        if h not in resp.headers:
            missing.append(h)

    if missing:
        return {
            "module": "SecurityHeaders",
            "payload": "Faltan cabeceras",
            "tested_endpoint": endpoint,
            "status": resp.status_code,
            "evidence": f"Faltantes: {', '.join(missing)}"
        }

    return {
        "module": "SecurityHeaders",
        "payload": "Todo OK",
        "tested_endpoint": endpoint,
        "status": resp.status_code,
        "evidence": "Todas presentes"
    }



def get_modules():
    return [
        ("MethodOverride", test_method_override),
        ("WeakInputHandling", test_weak_input),
        ("ServerHeader", test_server_header),
        ("HeaderInjection", test_header_injection),
        ("BodyParamInjection", test_body_param_injection),
        ("TokenValidity", test_token_validity),
        ("SpecialCharsInBody", test_special_chars_body),
        ("TLSSecurity", test_tls_security),
        ("SecurityHeaders", test_security_headers),
    ]


def run_modules(host, endpoint, method, headers, data, quiet=False):
    findings = []
    for name, func in get_modules():
        if not quiet:
            print(MAGENTA + f"[*] Ejecutando {name}..." + RESET)
        try:
            res = func(host, endpoint, method, headers, data)
            if res:
                findings.append(res)
                if not quiet:
                    print(GREEN + f"[+] {name} detectado\n" + RESET)
            else:
                if not quiet:
                    print(GREY + f"[-] {name}: no detectado\n" + RESET)
        except Exception as e:
            if not quiet:
                print(RED + f"[!] Error ejecutando {name}: {e}\n" + RESET)
    return findings



def normalize_base_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}", parsed


def spider_advanced(base_url, headers, max_pages=80, max_js=50):

    origin, parsed_base = normalize_base_url(base_url)

    session = requests.Session()
    session.headers.update(headers)

    queue = deque([origin])
    visited_pages = set()
    api_endpoints = set()
    js_to_visit = set()

    regex_api = re.compile(r'["\'](/api/[A-Za-z0-9_\-./]+)["\']')
    regex_versioned = re.compile(r'["\'](/[^"\']*?/v[0-9]+/[^"\']+)["\']')
    regex_generic = re.compile(r'["\'](/[-A-Za-z0-9_/\.]+)["\']')

    pages_crawled = 0

    print(CYAN + BOLD + "\n[+] Iniciando búsqueda de endpoints..." + RESET)

    while queue and pages_crawled < max_pages:
        url = queue.popleft()
        if url in visited_pages:
            continue

        visited_pages.add(url)
        pages_crawled += 1
        print(GREY + f"[*] Visitando: {url}" + RESET)

        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue

        content_type = resp.headers.get("Content-Type", "")
        text = resp.text or ""

        if "text/html" in content_type or "<html" in text.lower():
            soup = BeautifulSoup(text, "html.parser")

            for tag in soup.find_all(["a", "form", "link"]):
                href = tag.get("href") or tag.get("action")
                if not href:
                    continue
                abs_url = urllib.parse.urljoin(url, href)
                parsed = urllib.parse.urlparse(abs_url)
                if parsed.netloc != parsed_base.netloc:
                    continue
                path = parsed.path or "/"

                if "/api" in path or re.search(r"/v[0-9]+/", path):
                    api_endpoints.add(urllib.parse.urljoin(origin, path))

                if abs_url not in visited_pages:
                    queue.append(abs_url)

            for script in soup.find_all("script", src=True):
                src = script["src"]
                abs_js = urllib.parse.urljoin(url, src)
                parsed = urllib.parse.urlparse(abs_js)
                if parsed.netloc == parsed_base.netloc:
                    js_to_visit.add(abs_js)

        for m in regex_api.finditer(text):
            path = m.group(1)
            api_endpoints.add(urllib.parse.urljoin(origin, path))

        for m in regex_versioned.finditer(text):
            path = m.group(1)
            api_endpoints.add(urllib.parse.urljoin(origin, path))

        json_like = re.findall(r'"(GET|POST|PUT|DELETE|PATCH)\s+(/[A-Za-z0-9_\-./]+)"', text)
        for _, path in json_like:
            api_endpoints.add(urllib.parse.urljoin(origin, path))

        for m in regex_generic.finditer(text):
            path = m.group(1)
            if parsed_base.netloc in origin and path.startswith("/"):
                if "/api" in path or re.search(r"/v[0-9]+/", path):
                    api_endpoints.add(urllib.parse.urljoin(origin, path))

    print(CYAN + BOLD + "\n[+] Analizando archivos JS para rutas..." + RESET)
    js_count = 0
    for js_url in js_to_visit:
        if js_count >= max_js:
            break
        js_count += 1
        print(GREY + f"[*] Analizando JS: {js_url}" + RESET)
        try:
            r_js = session.get(js_url, timeout=REQUEST_TIMEOUT)
            src = r_js.text or ""
        except requests.RequestException:
            continue

        for m in regex_api.finditer(src):
            path = m.group(1)
            api_endpoints.add(urllib.parse.urljoin(origin, path))

        for m in regex_versioned.finditer(src):
            path = m.group(1)
            api_endpoints.add(urllib.parse.urljoin(origin, path))

        for m in re.finditer(r'["\'](/[A-Za-z0-9_\-./]*api/[A-Za-z0-9_\-./]+)["\']', src):
            path = m.group(1)
            api_endpoints.add(urllib.parse.urljoin(origin, path))

    print(YELLOW + f"\n[+] Descubrimiento completado. Páginas visitadas: {pages_crawled}" + RESET)
    print(YELLOW + f"[+] Endpoints API descubiertos: {len(api_endpoints)}" + RESET)

    return sorted(api_endpoints)



def api_mode():
    host = input("[*] Host: (Ejem: http://127.0.0.1:5000): ").strip()
    endpoint = input("[*] Endpoint: (Eje: /users/v1): ").strip()
    method = input("[*] Método HTTP (GET/POST/etc): ").strip().upper()

    raw = input("[*] ¿Enviar JSON Body? (Y/n): ").strip().lower()
    data = {}
    if raw != "n":
        js = input("[*] JSON Body (o vacío): ").strip()
        if js:
            try:
                data = json.loads(js)
            except Exception:
                print(RED + "[!] JSON inválido, ignorado." + RESET)

    headers = HEADERS_DEFAULT.copy()

    ck = input("[*] ¿Enviar cabecera de autenticación? (Y/n): ").strip().lower()
    if ck != "n":
        cname = input("[*] Cabecera (Authorization/Cookie): ").strip()
        cvalue = input("[*] Valor: ").strip()
        if cname and cvalue:
            headers[cname] = cvalue

    print(BOLD + CYAN + "\n[+] Iniciando escaneo API...\n" + RESET)

    start = time.time()
    findings = run_modules(host, endpoint, method, headers, data, quiet=False)

    print("\n" + YELLOW + "="*80 + RESET)
    print(CYAN + BOLD + "[+] Resumen Final (API)" + RESET)
    print(YELLOW + "="*80 + RESET)

    if not findings:
        print(GREEN + "[-] No se detectaron vulnerabilidades." + RESET)
    else:
        for f in findings:
            print_finding(f)

    print(f"{BLUE}[i] Tiempo total: {time.time() - start:.2f}s{RESET}")



def web_mode():
    base_url = input("[*] URL base (ej. https://victima.com): ").strip()
    threads_raw = input("[*] Threads (concurrencia, default 10): ").strip()
    try:
        threads = int(threads_raw) if threads_raw else 10
    except ValueError:
        threads = 10

    headers = HEADERS_DEFAULT.copy()

    ck = input("[*] ¿Enviar cabecera de autenticación global? (Y/n): ").strip().lower()
    if ck != "n":
        cname = input("[*] Cabecera (Authorization/Cookie/etc): ").strip()
        cvalue = input("[*] Valor: ").strip()
        if cname and cvalue:
            headers[cname] = cvalue

    endpoints = spider_advanced(base_url, headers)
    if not endpoints:
        print(RED + "[!] No se encontraron endpoints para escanear." + RESET)
        return

    origin, _ = normalize_base_url(base_url)

    print(CYAN + BOLD + "\n[+] Iniciando escaneo de endpoints descubiertos..." + RESET)
    start = time.time()

    all_findings = []
    endpoint_stats = {}

    def scan_single(url):
        parsed = urllib.parse.urlparse(url)
        host = f"{parsed.scheme}://{parsed.netloc}"
        endpoint = parsed.path or "/"
        if parsed.query:
            endpoint = endpoint + "?" + parsed.query

        local_findings = run_modules(host, endpoint, "GET", headers, None, quiet=True)
        return url, local_findings

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(scan_single, url): url for url in endpoints}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                scanned_url, f_list = future.result()
            except Exception as e:
                print(RED + f"[!] Error escaneando {url}: {e}" + RESET)
                continue

            ep_path = urllib.parse.urlparse(scanned_url).path or "/"

            if f_list:
                print(BOLD + CYAN + f"\n[+] Hallazgos en {scanned_url}" + RESET)
                for f in f_list:
                    print_finding(f)

                all_findings.extend(f_list)
                endpoint_stats.setdefault(ep_path, set())
                for f in f_list:
                    endpoint_stats[ep_path].add(f["module"])
            else:
                print(GREY + f"[-] Sin hallazgos en {scanned_url}" + RESET)

    print("\n" + YELLOW + "="*80 + RESET)
    print(CYAN + BOLD + "[+] Resumen Final (WEB) — Vulnerabilidades por endpoint" + RESET)
    print(YELLOW + "="*80 + RESET)

    if not all_findings:
        print(GREEN + "[-] No se detectaron vulnerabilidades en ningún endpoint." + RESET)
    else:
        table = PrettyTable()
        table.field_names = ["Endpoint", "Módulos detectados", "Total módulos"]

        for ep, mods in sorted(endpoint_stats.items(), key=lambda x: x[0]):
            mods_list = sorted(list(mods))
            table.add_row([ep, ", ".join(mods_list), len(mods_list)])

        print(table)

    print(f"{BLUE}[i] Tiempo total (WEB): {time.time() - start:.2f}s{RESET}")



def main():
    print_banner()
    print(YELLOW + "Selecciona el modo de escaneo:" + RESET)
    print("  1) API ")
    print("  2) WEB \n")

    mode = input("[*] Opción (1/2): ").strip()

    if mode == "2":
        web_mode()
    else:
        api_mode()


if __name__ == "__main__":
    main()

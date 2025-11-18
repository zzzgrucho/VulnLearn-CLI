#!/usr/bin/env python3
import requests
import json
import urllib.parse
import time
import socket
import ssl
import re

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
    headers = headers or HEADERS_DEFAULT

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

    # Sin token
    h_no = headers.copy()
    h_no.pop(token_header, None)
    resp_no = send_request(host, endpoint, method, h_no, data)

    # Token modificado
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


def main():
    print_banner()

    host = input("[*] Host: ").strip()
    endpoint = input("[*] Endpoint: ").strip()
    method = input("[*] Método (GET/POST/etc): ").strip().upper()

    raw = input("[*] ¿Enviar JSON Body? (Y/n): ").strip().lower()
    data = {}
    if raw != "n":
        js = input("[*] JSON Body (o vacío): ").strip()
        if js:
            try:
                data = json.loads(js)
            except:
                print(RED + "[!] JSON inválido, ignorado." + RESET)

    headers = HEADERS_DEFAULT.copy()

    ck = input("[*] ¿Enviar cabecera de autenticación? (Y/n): ").strip().lower()
    if ck != "n":
        cname = input("[*] Cabecera (Authorization/Cookie): ").strip()
        cvalue = input("[*] Valor: ").strip()
        if cname and cvalue:
            headers[cname] = cvalue

    print(BOLD + CYAN + "\n[+] Iniciando escaneo...\n" + RESET)

    modules = [
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

    findings = []
    start = time.time()

    for name, func in modules:
        print(MAGENTA + f"[*] Ejecutando {name}..." + RESET)
        try:
            res = func(host, endpoint, method, headers, data)
            if res:
                findings.append(res)
                print(GREEN + f"[+] {name} detectado\n" + RESET)
            else:
                print(GREY + f"[-] {name}: no detectado\n" + RESET)
        except Exception as e:
            print(RED + f"[!] Error ejecutando {name}: {e}\n" + RESET)

    print("\n" + YELLOW + "="*80 + RESET)
    print(CYAN + BOLD + "[+] Resumen Final" + RESET)
    print(YELLOW + "="*80 + RESET)

    if not findings:
        print(GREEN + "[-] No se detectaron vulnerabilidades." + RESET)
    else:
        for f in findings:
            print_finding(f)

    print(f"{BLUE}[i] Tiempo total: {time.time() - start:.2f}s{RESET}")


if __name__ == "__main__":
    main()

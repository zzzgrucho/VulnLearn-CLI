#!/usr/bin/env python3
import json
import socket
import ssl
import time
import urllib.parse
from datetime import datetime

import requests

RESET = "\033[0m"
BOLD = "\033[1m"

CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREY = "\033[90m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"

REQUEST_TIMEOUT = 6
HEADERS_DEFAULT = {
    "User-Agent": "vulnlearn-dast-lite/2.0",
    "Content-Type": "application/json",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Content-Security-Policy",
    "Permissions-Policy",
]

BODY_INJECTION_PAYLOADS = [
    {"isAdmin": True},
    {"role": "admin"},
    {"admin": 1},
]

SPECIAL_CHARS_LIST = [
    "'",
    '"',
    "<",
    ">",
    "<script>",
    "../",
    "..\\",
    "%0d%0a",
    ";--",
    "${7*7}",
]

ALTERNATE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": BLUE,
}


def print_banner():
    alpaca = r"""
                    /\
               /\  //\\
        /\    //\\///\\\        /\
       //\\  ///\////\\\\  /\  //\\
  /\  /  ^ \/^ ^/^  ^  ^ \/^ \/  ^ \
 / ^\/^ ^   ^  ^    ^   ^ \ ^/  ^  ^\
/^   \^ /\  ^    ^  ^   ^   \/^   ^  \
    /\  /\ \              ^    ^  /\
   /  \/  \ \                   /  \
  /           \_    VULN ALPACA _/
 """

    title = "VulnLAPI - DAST Lite"

    print(MAGENTA + alpaca + RESET)
    print(CYAN + BOLD + title + RESET)
    print(YELLOW + "=" * 88 + RESET)
    print(GREEN + "Escaneo educativo de APIs con reporte estructurado." + RESET)
    print(YELLOW + "=" * 88 + RESET + "\n")


def severity_color(level):
    return SEVERITY_COLORS.get(level.upper(), GREY)


def normalize_host(host):
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "http://" + host
    return host.rstrip("/")


def build_url(host, endpoint):
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    return f"{host.rstrip('/')}/{endpoint.lstrip('/')}"


def response_json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def send_request(session, host, endpoint, method, headers=None, data=None):
    headers = headers or HEADERS_DEFAULT
    host = normalize_host(host)
    url = build_url(host, endpoint)

    try:
        req_method = method.upper()
        body = data if req_method in ["POST", "PUT", "PATCH"] else None
        return session.request(
            req_method,
            url,
            headers=headers,
            json=body,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def make_finding(module, severity, endpoint, payload, status, evidence, recommendation):
    return {
        "module": module,
        "severity": severity,
        "tested_endpoint": endpoint,
        "payload": payload,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def print_finding(index, finding):
    sev = finding["severity"].upper()
    sev_color = severity_color(sev)
    print(f"{BOLD}{sev_color}[{index}] {finding['module']} - {sev}{RESET}")
    print(f"    {MAGENTA}Endpoint:{RESET} {finding['tested_endpoint']}")
    print(f"    {CYAN}Payload:{RESET} {finding['payload']}")
    print(f"    {BLUE}HTTP Status:{RESET} {finding['status']}")
    print(f"    {GREY}Evidencia:{RESET} {finding['evidence']}")
    print(f"    {GREEN}Recomendacion:{RESET} {finding['recommendation']}")
    print(GREY + "-" * 88 + RESET)


def test_method_override(session, host, endpoint, method, headers, data):
    findings = []
    baseline = send_request(session, host, endpoint, method, headers, data)
    base_status = baseline.status_code if baseline else None

    for alt in ALTERNATE_METHODS:
        if alt == method.upper():
            continue

        resp = send_request(session, host, endpoint, alt, headers, data)
        if not resp:
            continue

        # Riesgo cuando metodos no esperados procesan la misma ruta exitosamente.
        if resp.status_code < 300 and (base_status is None or resp.status_code == base_status):
            findings.append(
                make_finding(
                    "MethodOverride",
                    "MEDIUM",
                    endpoint,
                    alt,
                    resp.status_code,
                    f"El endpoint acepta {alt} con estado {resp.status_code}.",
                    "Limitar metodos HTTP permitidos por endpoint y devolver 405 en metodos no autorizados.",
                )
            )
            break

    return findings


def test_weak_input(session, host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"]:
        return []

    resp = send_request(session, host, endpoint, method, headers, {})
    if resp and resp.status_code < 300:
        return [
            make_finding(
                "WeakInputHandling",
                "MEDIUM",
                endpoint,
                "<empty-body>",
                resp.status_code,
                "El servidor acepto un body vacio sin validar campos requeridos.",
                "Aplicar validacion de esquema y campos obligatorios antes de procesar la peticion.",
            )
        ]

    return []


def test_server_header(session, host, endpoint, method, headers, data):
    resp = send_request(session, host, endpoint, "GET", headers)
    if resp and "Server" in resp.headers and resp.headers["Server"].strip():
        server_value = resp.headers["Server"].strip()
        return [
            make_finding(
                "ServerHeader",
                "LOW",
                endpoint,
                server_value,
                resp.status_code,
                f"Cabecera Server expuesta: {server_value}",
                "Ocultar o generalizar la cabecera Server para reducir fingerprinting.",
            )
        ]

    return []


def test_header_injection(session, host, endpoint, method, headers, data):
    test_headers = headers.copy()
    marker = "alpaca-header-marker"
    test_headers["X-Injected-Header"] = marker

    resp = send_request(session, host, endpoint, method, test_headers, data)
    if not resp:
        return []

    reflected = marker in resp.text or resp.headers.get("X-Injected-Header") == marker
    if reflected:
        return [
            make_finding(
                "HeaderInjection",
                "HIGH",
                endpoint,
                "X-Injected-Header: alpaca-header-marker",
                resp.status_code,
                "Se detecto reflexion de cabeceras controladas por el cliente.",
                "Filtrar cabeceras de entrada y evitar reflejarlas en respuestas o logs sin sanitizacion.",
            )
        ]

    return []


def test_body_param_injection(session, host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"] or not isinstance(data, dict) or not data:
        return []

    for extra in BODY_INJECTION_PAYLOADS:
        test_data = data.copy()
        test_data.update(extra)

        resp = send_request(session, host, endpoint, method, headers, test_data)
        if not resp:
            continue

        body_json = response_json(resp)
        echoed = False

        if isinstance(body_json, dict):
            echoed = any(k in body_json for k in extra.keys())
        else:
            echoed = any(k in resp.text for k in extra.keys())

        if resp.status_code in [200, 201] and echoed:
            return [
                make_finding(
                    "BodyParamInjection",
                    "HIGH",
                    endpoint,
                    json.dumps(extra, ensure_ascii=True),
                    resp.status_code,
                    "El endpoint acepto y reflejo parametros no previstos en el body.",
                    "Implementar allowlist de campos y rechazar propiedades no esperadas.",
                )
            ]

    return []


def test_token_validity(session, host, endpoint, method, headers, data):
    token_header = next((k for k in headers if k.lower() in ["authorization", "cookie"]), None)
    if not token_header:
        return []

    baseline = send_request(session, host, endpoint, method, headers, data)
    if not baseline:
        return []

    base_status = baseline.status_code

    headers_no_token = headers.copy()
    headers_no_token.pop(token_header, None)
    resp_no = send_request(session, host, endpoint, method, headers_no_token, data)

    headers_bad_token = headers.copy()
    token_value = headers_bad_token[token_header]
    headers_bad_token[token_header] = (token_value[:-1] + "X") if len(token_value) > 1 else token_value + "X"
    resp_bad = send_request(session, host, endpoint, method, headers_bad_token, data)

    issues = []
    if resp_no and resp_no.status_code == base_status:
        issues.append("sin token")
    if resp_bad and resp_bad.status_code == base_status:
        issues.append("token modificado")

    if issues:
        return [
            make_finding(
                "TokenValidity",
                "CRITICAL",
                endpoint,
                ", ".join(issues),
                base_status,
                "El endpoint responde igual con credenciales ausentes o alteradas.",
                "Validar autenticacion/autorizacion en cada solicitud y retornar 401/403 cuando corresponda.",
            )
        ]

    return []


def test_special_chars_body(session, host, endpoint, method, headers, data):
    if method.upper() not in ["POST", "PUT", "PATCH"] or not isinstance(data, dict) or not data:
        return []

    special_str = " ".join(SPECIAL_CHARS_LIST)

    for key, val in data.items():
        if not isinstance(val, str):
            continue

        test_data = data.copy()
        test_data[key] = f"{val} {special_str}"
        resp = send_request(session, host, endpoint, method, headers, test_data)
        if not resp:
            continue

        reflected = any(token in resp.text for token in ["<script>", "../", "${7*7}"])
        if resp.status_code < 300 and reflected:
            return [
                make_finding(
                    "SpecialCharsInBody",
                    "MEDIUM",
                    endpoint,
                    f"{key} -> {special_str}",
                    resp.status_code,
                    "Caracteres especiales reflejados en la respuesta.",
                    "Sanitizar entradas y codificar salida para evitar inyecciones y traversal.",
                )
            ]

    return []


def test_tls_security(session, host, endpoint, method, headers, data):
    normalized = normalize_host(host)
    parsed = urllib.parse.urlparse(normalized)
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    if scheme != "https":
        return [
            make_finding(
                "TLSSecurity",
                "HIGH",
                normalized,
                "Sin HTTPS",
                "N/A",
                "El host no usa HTTPS para cifrar trafico.",
                "Habilitar HTTPS con certificados validos y redirigir trafico HTTP a HTTPS.",
            )
        ]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                tls_version = secure_sock.version()
    except Exception as exc:
        return [
            make_finding(
                "TLSSecurity",
                "HIGH",
                normalized,
                "TLS handshake failed",
                "N/A",
                f"Error al validar TLS: {exc}",
                "Revisar configuracion TLS y certificados del servidor.",
            )
        ]

    if tls_version in ["TLSv1", "TLSv1.1"]:
        return [
            make_finding(
                "TLSSecurity",
                "HIGH",
                normalized,
                tls_version,
                "N/A",
                f"Version TLS insegura detectada: {tls_version}",
                "Deshabilitar TLS obsoleto y permitir TLS 1.2 o TLS 1.3 unicamente.",
            )
        ]

    return [
        make_finding(
            "TLSSecurity",
            "INFO",
            normalized,
            tls_version,
            "N/A",
            f"Version TLS en uso: {tls_version}",
            "Mantener configuracion actual y monitorear renovaciones de certificado.",
        )
    ]


def test_security_headers(session, host, endpoint, method, headers, data):
    resp = send_request(session, host, endpoint, "GET", headers)
    if not resp:
        return []

    missing = [header for header in SECURITY_HEADERS if header not in resp.headers]
    if missing:
        return [
            make_finding(
                "SecurityHeaders",
                "MEDIUM",
                endpoint,
                "Missing headers",
                resp.status_code,
                "Faltan cabeceras: " + ", ".join(missing),
                "Agregar cabeceras de seguridad en la capa web/reverse proxy.",
            )
        ]

    return [
        make_finding(
            "SecurityHeaders",
            "INFO",
            endpoint,
            "All required headers present",
            resp.status_code,
            "Todas las cabeceras de seguridad requeridas estan presentes.",
            "Mantener esta configuracion y validarla en CI/CD.",
        )
    ]


def print_summary(host, endpoint, method, findings, started_at):
    elapsed = time.time() - started_at
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counters = {level: 0 for level in severity_order}

    for finding in findings:
        sev = finding["severity"].upper()
        counters[sev] = counters.get(sev, 0) + 1

    print("\n" + YELLOW + "=" * 88 + RESET)
    print(CYAN + BOLD + "Reporte Final" + RESET)
    print(YELLOW + "=" * 88 + RESET)
    print(f"{BLUE}Fecha:{RESET} {timestamp}")
    print(f"{BLUE}Objetivo:{RESET} {normalize_host(host)}")
    print(f"{BLUE}Endpoint:{RESET} {endpoint}")
    print(f"{BLUE}Metodo:{RESET} {method}")
    print(f"{BLUE}Tiempo total:{RESET} {elapsed:.2f}s")

    print("\n" + BOLD + "Resumen por severidad" + RESET)
    for level in severity_order:
        color = severity_color(level)
        print(f"  {color}{level:<8}{RESET}: {counters[level]}")

    print("\n" + BOLD + "Detalle de hallazgos" + RESET)
    if not findings:
        print(GREEN + "Sin hallazgos detectables con las pruebas actuales." + RESET)
    else:
        for idx, finding in enumerate(findings, start=1):
            print_finding(idx, finding)


def collect_findings(session, host, endpoint, method, headers, data):
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

    for module_name, module_func in modules:
        print(MAGENTA + f"[*] Ejecutando {module_name}..." + RESET)
        try:
            module_findings = module_func(session, host, endpoint, method, headers, data)
            findings.extend(module_findings)
            if module_findings:
                print(GREEN + f"[+] {module_name}: {len(module_findings)} hallazgo(s)" + RESET)
            else:
                print(GREY + f"[-] {module_name}: sin hallazgos" + RESET)
        except Exception as exc:
            print(RED + f"[!] Error en {module_name}: {exc}" + RESET)

    return findings


def main():
    print_banner()

    host = input("[*] Host: ").strip()
    endpoint = input("[*] Endpoint: ").strip()
    method = input("[*] Metodo (GET/POST/etc): ").strip().upper()

    raw_body = input("[*] Enviar JSON body? (Y/n): ").strip().lower()
    data = {}
    if raw_body != "n":
        payload = input("[*] JSON body (o vacio): ").strip()
        if payload:
            try:
                data = json.loads(payload)
            except Exception:
                print(RED + "[!] JSON invalido, se usara body vacio." + RESET)

    headers = HEADERS_DEFAULT.copy()

    ask_auth = input("[*] Enviar cabecera de autenticacion? (Y/n): ").strip().lower()
    if ask_auth != "n":
        header_name = input("[*] Cabecera (Authorization/Cookie): ").strip()
        header_value = input("[*] Valor: ").strip()
        if header_name and header_value:
            headers[header_name] = header_value

    print("\n" + BOLD + CYAN + "[+] Iniciando escaneo..." + RESET + "\n")

    start_time = time.time()
    with requests.Session() as session:
        findings = collect_findings(session, host, endpoint, method, headers, data)

    print_summary(host, endpoint, method, findings, start_time)


if __name__ == "__main__":
    main()

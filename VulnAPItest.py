#!/usr/bin/env python3
import copy
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

PAYLOAD_ENGINES = {
    "SQLInjection": {
        "severity": "HIGH",
        "payloads": [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:3'--",
        ],
        "error_signatures": [
            "sql syntax",
            "syntax error at or near",
            "unterminated quoted string",
            "sqlite",
            "mysql",
            "postgresql",
            "sqlstate",
            "ora-",
        ],
        "reflection_tokens": ["' OR '1'='1", "UNION SELECT"],
    },
    "NoSQLInjection": {
        "severity": "HIGH",
        "payloads": [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
        ],
        "error_signatures": ["mongodb", "bson", "nosql", "mongoerror"],
        "reflection_tokens": ['"$ne"', '"$regex"'],
    },
    "XSS": {
        "severity": "HIGH",
        "payloads": [
            "<script>alert(1337)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ],
        "error_signatures": [],
        "reflection_tokens": ["<script>alert(1337)</script>", "onerror=alert(1)", "onload=alert(1)"],
    },
    "SSTI": {
        "severity": "HIGH",
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
        ],
        "error_signatures": ["jinja", "template", "mustache", "twig", "handlebars"],
        "reflection_tokens": ["49", "{{7*7}}", "${7*7}"],
    },
    "CommandInjection": {
        "severity": "CRITICAL",
        "payloads": [
            ";id",
            "&& whoami",
            "| cat /etc/passwd",
        ],
        "error_signatures": ["uid=", "gid=", "root:x:", "command not found", "sh:"],
        "reflection_tokens": ["uid=", "gid=", "root:x:"],
    },
    "PathTraversal": {
        "severity": "HIGH",
        "payloads": [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
        ],
        "error_signatures": ["no such file or directory", "access is denied", "permission denied"],
        "reflection_tokens": ["root:x:", "[fonts]", "for 16-bit app support"],
    },
    "CRLFInjection": {
        "severity": "MEDIUM",
        "payloads": [
            "%0d%0aX-Injection-Test: alpaca",
            "\r\nX-Injection-Test: alpaca",
        ],
        "error_signatures": [],
        "reflection_tokens": ["x-injection-test", "alpaca"],
    },
    "OpenRedirect": {
        "severity": "HIGH",
        "payloads": [
            "https://evil.example/path",
            "//evil.example/path",
        ],
        "error_signatures": [],
        "reflection_tokens": ["evil.example/path"],
    },
}

ALTERNATE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

MAX_MUTATIONS_PER_PAYLOAD = 4

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": BLUE,
}


def print_banner():
    robot = """
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗     ███████╗ █████╗ ██████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██║     ██╔════╝██╔══██╗██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║██║     █████╗  ███████║██████╔╝██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══╝  ██╔══██║██╔══██╗██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗███████╗██║  ██║██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                              
───────────────────────────────────────
───▐▀▄───────▄▀▌───▄▄▄▄▄▄▄─────────────
───▌▒▒▀▄▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄──────────
──▐▒▒▒▒▀▒▀▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄────────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▀▄──────
▀█▒▒▒█▌▒▒█▒▒▐█▒▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌─────
▀▌▒▒▒▒▒▒▀▒▀▒▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐───▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌▄█▒█
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▒█▀─
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀───
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌────
─▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐─────
─▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌─────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐──────
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌──────
────▀▄▄▀▀▀▀▀▄▄▀▀▀▀▀▀▀▄▄▀▀▀▀▀▄▄▀────────

 """

    title = "VulnLearn - DAST Lite"

    print(MAGENTA + robot + RESET)
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


def collect_string_paths(value, trail=None):
    trail = trail or []
    if isinstance(value, str):
        return [tuple(trail)]

    paths = []
    if isinstance(value, dict):
        for key, nested in value.items():
            paths.extend(collect_string_paths(nested, trail + [key]))
    elif isinstance(value, list):
        for idx, nested in enumerate(value):
            paths.extend(collect_string_paths(nested, trail + [idx]))

    return paths


def get_path_value(container, trail):
    current = container
    for step in trail:
        current = current[step]
    return current


def set_path_value(container, trail, new_value):
    current = container
    for step in trail[:-1]:
        current = current[step]
    current[trail[-1]] = new_value


def format_path(trail):
    formatted = []
    for step in trail:
        if isinstance(step, int):
            formatted.append(f"[{step}]")
        else:
            formatted.append(step)
    return ".".join(formatted).replace(".[", "[")


def build_body_mutations(data, payload):
    if not isinstance(data, dict):
        return []

    paths = collect_string_paths(data)
    mutations = []

    if not paths:
        test_data = copy.deepcopy(data)
        test_data["dastProbe"] = payload
        return [("body.dastProbe", test_data)]

    for path in paths:
        test_data = copy.deepcopy(data)
        original = get_path_value(test_data, path)
        set_path_value(test_data, path, f"{original}{payload}")
        mutations.append((f"body.{format_path(path)}", test_data))
        if len(mutations) >= MAX_MUTATIONS_PER_PAYLOAD:
            break

    return mutations


def build_query_mutations(endpoint, payload):
    parsed = urllib.parse.urlparse(endpoint)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    mutations = []

    if not query:
        query = {"q": [payload]}
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_endpoint = urllib.parse.urlunparse(parsed._replace(query=new_query))
        return [("query.q", new_endpoint)]

    for key in query:
        test_query = copy.deepcopy(query)
        current = test_query[key][0] if test_query[key] else ""
        test_query[key] = [f"{current}{payload}"]
        new_query = urllib.parse.urlencode(test_query, doseq=True)
        new_endpoint = urllib.parse.urlunparse(parsed._replace(query=new_query))
        mutations.append((f"query.{key}", new_endpoint))
        if len(mutations) >= MAX_MUTATIONS_PER_PAYLOAD:
            break

    return mutations


def detect_payload_anomaly(engine_name, config, payload, baseline, resp):
    signals = []

    if not resp:
        return signals

    baseline_status = baseline.status_code if baseline else None
    response_text = (resp.text or "").lower()
    baseline_text = (baseline.text or "").lower() if baseline else ""

    if resp.status_code >= 500 and (baseline_status is None or baseline_status < 500):
        signals.append(f"status inesperado {resp.status_code}")

    new_errors = [
        signature
        for signature in config.get("error_signatures", [])
        if signature in response_text and signature not in baseline_text
    ]
    if new_errors:
        signals.append("errores sensibles detectados: " + ", ".join(new_errors[:3]))

    new_reflections = [
        token
        for token in config.get("reflection_tokens", [])
        if token.lower() in response_text and token.lower() not in baseline_text
    ]
    if new_reflections:
        signals.append("payload/tokens reflejados en respuesta")

    if engine_name == "OpenRedirect":
        location = (resp.headers.get("Location") or "").lower()
        if resp.status_code in [301, 302, 303, 307, 308] and "evil.example" in location:
            signals.append(f"redireccion abierta detectada hacia {location}")

    if baseline_status and baseline_status != resp.status_code and resp.status_code < 500:
        signals.append(f"status cambio {baseline_status}->{resp.status_code}")

    return signals


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


def test_payload_engines(session, host, endpoint, method, headers, data):
    findings = []
    req_method = method.upper()
    baseline = send_request(session, host, endpoint, req_method, headers, data)

    for engine_name, config in PAYLOAD_ENGINES.items():
        detected = False
        for payload in config.get("payloads", []):
            variations = []
            variations.extend([(vector, endpoint, body) for vector, body in build_body_mutations(data, payload)])
            variations.extend([(vector, ep, data) for vector, ep in build_query_mutations(endpoint, payload)])

            if not variations:
                continue

            for vector, test_endpoint, test_data in variations[:MAX_MUTATIONS_PER_PAYLOAD]:
                resp = send_request(session, host, test_endpoint, req_method, headers, test_data)
                if not resp:
                    continue

                signals = detect_payload_anomaly(engine_name, config, payload, baseline, resp)
                if not signals:
                    continue

                findings.append(
                    make_finding(
                        f"PayloadEngine:{engine_name}",
                        config.get("severity", "MEDIUM"),
                        test_endpoint,
                        payload,
                        resp.status_code,
                        f"{vector} -> {' | '.join(signals)}",
                        "Aplicar validacion estricta, normalizar entrada y usar consultas/plantillas seguras segun el tipo de inyeccion.",
                    )
                )
                detected = True
                break

            if detected:
                break

    return findings


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


def severity_rank(level):
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(level.upper(), 0)


def bar_meter(value, total, width=30):
    safe_total = max(total, 1)
    ratio = max(0, min(1, value / safe_total))
    filled = int(ratio * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def calculate_risk(findings):
    score = 0
    for finding in findings:
        score += SEVERITY_WEIGHTS.get(finding["severity"].upper(), 0)
    score = min(score, 100)

    if score >= 70:
        return score, "SUPERFICIE DE RIESGO ALTA", RED
    if score >= 35:
        return score, "SUPERFICIE DE RIESGO MEDIA", YELLOW
    if score > 0:
        return score, "SUPERFICIE DE RIESGO BAJA", CYAN
    return score, "SIN INDICIOS DE RIESGO EN PRUEBAS ACTUALES", GREEN


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

    total_findings = len(findings)
    risk_score, risk_label, risk_color = calculate_risk(findings)

    print("\n" + YELLOW + "+" + "-" * 86 + "+" + RESET)
    print(CYAN + BOLD + "Panel Ejecutivo" + RESET)
    print(YELLOW + "+" + "-" * 86 + "+" + RESET)
    print(f"{BLUE}Hallazgos totales:{RESET} {total_findings}")
    print(f"{BLUE}Riesgo acumulado:{RESET} {risk_score}/100 {bar_meter(risk_score, 100)}")
    print(f"{BLUE}Postura:{RESET} {risk_color}{BOLD}{risk_label}{RESET}")

    print("\n" + BOLD + "Resumen por severidad" + RESET)
    for level in severity_order:
        color = severity_color(level)
        meter = bar_meter(counters[level], total_findings if total_findings else 1, width=22)
        print(f"  {color}{level:<8}{RESET}: {counters[level]:>3} {meter}")

    if findings:
        print("\n" + BOLD + "Top Hallazgos" + RESET)
        sorted_findings = sorted(findings, key=lambda item: severity_rank(item["severity"]), reverse=True)
        for idx, finding in enumerate(sorted_findings[:5], start=1):
            sev_color = severity_color(finding["severity"])
            print(
                f"  {idx}. {sev_color}{finding['severity']:<8}{RESET} "
                f"{finding['module']} | {finding['tested_endpoint']}"
            )

    print("\n" + BOLD + "Detalle de hallazgos" + RESET)
    if not findings:
        print(GREEN + "Sin hallazgos detectables con las pruebas actuales." + RESET)
    else:
        for idx, finding in enumerate(findings, start=1):
            print_finding(idx, finding)


def collect_findings(session, host, endpoint, method, headers, data):
    modules = [
        ("PayloadEngines", test_payload_engines),
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

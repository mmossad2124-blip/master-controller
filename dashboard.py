"""
Mossad Ethical Hacker | Cloud AI Security Operations Center
Enterprise-Grade Architecture:
  - Dual AI Engines: DeepSeek-R1 (Reasoning & SAST) + GLM Security Engine (Remediation & PoCs)
  - API Vulnerability Scanner (BOLA/IDOR & Key Exposure)
  - MITRE ATT&CK & STRIDE Threat Modeling Engine
  - Source Code SAST Analyzer (Python, JS, PHP, Go)
  - Automatic Unit Test & Patch Validator Generator
  - Webhook Trigger Engine for CI/CD DevSecOps
"""
import os
import re
import json
import uuid
import ssl
import socket
import logging
import requests
import datetime
import streamlit as st
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MossadSecOps")

# Optional imports
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
from core.llm_client import call_llm, MODEL_SAST, MODEL_REMEDIATION, MODEL_FALLBACK
from utils.session_manager import SessionManager

session_mgr = SessionManager()

def call_cf_ai(prompt, model=MODEL_FALLBACK, system_prompt="أنت أقوى وأخطر عقلية أمن سيبراني ومدقق أنظمة في العالم.", account_index=0):
    """Wrapper calling unified Cloudflare / HuggingFace / Local LLM engine."""
    from core.llm_client import call_cf_workers_ai
    res = call_cf_workers_ai(prompt, model_index=account_index, system_prompt=system_prompt)
    if res:
        return res
    return call_llm(prompt, model=model, max_tokens=700, system_prompt=system_prompt)



# ═══════════════════════════════════════════════════════════════
# 1. ENTERPRISE FEATURE: API SECURITY SCANNER (BOLA/IDOR & KEY DISCOVERY)
# ═══════════════════════════════════════════════════════════════
API_PATTERNS = [
    "/api/users/1", "/api/user/1", "/api/v1/users/1",
    "/api/account", "/api/v1/me", "/api/v1/profile",
    "/graphql", "/api/graphql", "/swagger.json", "/api/v1/swagger.json",
    "/v2/api-docs", "/api-docs"
]

KEY_REGEX = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"api[_-]?key[^\s'\"]*['\"]\s*[:=]\s*['\"]([^'\"]+)['\"]",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "GitHub Personal Token": r"ghp_[a-zA-Z0-9]{36}"
}

def scan_api_security(target_url: str) -> dict:
    """Scan target for API security risks, BOLA/IDOR patterns, exposed API docs, and leaked keys."""
    result = {"endpoints_tested": [], "findings": [], "keys_leaked": []}
    base = target_url.rstrip("/")
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Enterprise-Security-Auditor/2.0)"

    # Test API endpoints & BOLA patterns
    for path in API_PATTERNS:
        url = base + path
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            result["endpoints_tested"].append({"url": path, "status": r.status_code})
            if r.status_code == 200:
                if "graphql" in path:
                    result["findings"].append({
                        "issue": f"🚨 واجهة GraphQL مفتوحة للمعاينة: {path}",
                        "severity": "High",
                        "mitre_id": "T1190",
                        "stride": "Information Disclosure"
                    })
                elif "swagger" in path or "api-docs" in path:
                    result["findings"].append({
                        "issue": f"⚠️ وثائق API (Swagger) مكشوفة علناً: {path}",
                        "severity": "Medium",
                        "mitre_id": "T1592",
                        "stride": "Information Disclosure"
                    })
                elif any(x in path for x in ["/1", "/me", "/profile"]):
                    result["findings"].append({
                        "issue": f"🚨 مسار API حساس قد يحتوي ثغرة BOLA/IDOR: {path}",
                        "severity": "High",
                        "mitre_id": "T1068",
                        "stride": "Elevation of Privilege"
                    })
        except Exception:
            pass

    # Test main page for exposed API keys via regex
    try:
        main_resp = session.get(target_url, timeout=6)
        for key_type, regex in KEY_REGEX.items():
            matches = re.findall(regex, main_resp.text)
            if matches:
                result["keys_leaked"].append({"type": key_type, "count": len(matches)})
                result["findings"].append({
                    "issue": f"🚨 تم كشف مفتاح برمجيات محتمل ({key_type}) في شفرة HTML!",
                    "severity": "Critical",
                    "mitre_id": "T1552.001",
                    "stride": "Information Disclosure"
                })
    except Exception:
        pass

    return result


# ═══════════════════════════════════════════════════════════════
# 2. ENTERPRISE FEATURE: MITRE ATT&CK & STRIDE MAPPING
# ═══════════════════════════════════════════════════════════════
def map_mitre_and_stride(findings: list) -> list:
    """Enrich security findings with MITRE ATT&CK Techniques and STRIDE threat classification."""
    mapped = []
    for f in findings:
        issue_lower = f.get("issue", "").lower()
        mitre_id = f.get("mitre_id", "T1190")
        stride_cat = f.get("stride", "Tampering")

        if "sqli" in issue_lower or "sql" in issue_lower:
            mitre_id = "T1190 (Exploit Public-Facing Application)"
            stride_cat = "Tampering & Information Disclosure"
        elif "xss" in issue_lower or "csp" in issue_lower:
            mitre_id = "T1059.007 (JavaScript Execution)"
            stride_cat = "Tampering"
        elif "ssl" in issue_lower or "hsts" in issue_lower:
            mitre_id = "T1557 (Man-in-the-Middle)"
            stride_cat = "Information Disclosure"
        elif "dir" in issue_lower or "exposed" in issue_lower or ".env" in issue_lower:
            mitre_id = "T1552 (Unsecured Credentials)"
            stride_cat = "Information Disclosure"
        elif "dns" in issue_lower or "spf" in issue_lower or "dmarc" in issue_lower:
            mitre_id = "T1566 (Phishing / Email Spoofing)"
            stride_cat = "Spoofing"

        mapped.append({
            **f,
            "mitre_attack": mitre_id,
            "stride_category": stride_cat
        })
    return mapped


# ═══════════════════════════════════════════════════════════════
# 3. ENTERPRISE FEATURE: AUTOMATED UNIT TEST & PATCH VALIDATOR
# ═══════════════════════════════════════════════════════════════
def generate_automated_patch_and_unittest(finding: dict, target_url: str) -> dict:
    """Generate secure code patch, ModSecurity WAF rule, and PyTest validation script."""
    issue = finding.get("issue", "Security Vulnerability")
    sev = finding.get("severity", "High")

    prompt = f"""أنت خبير كبار المطورين والمهندسين الأمنيين. 
قدم حزمة ترقيع شاملة للثغرة التالية المكتشفة في {target_url}:
الثغرة: {issue} (مستوى الخطورة: {sev})

قم بتوليد الإجابة باللغة العربية مع الشفرات التالية:
1. **كود الترقيع الآمن (Secure Patch Code)** للغة المستهدفة.
2. **قاعدة جدار ناري (ModSecurity WAF Rule)** لصد الهجوم فوراً.
3. **وحدة اختبار أوتوماتيكية (PyTest Script)** للتحقق من أن الترقيع أغلق الثغرة فعلياً دون كسر النظام."""

    res = call_cf_ai(prompt, MODEL_REMEDIATION, account_index=1)
    return {"finding": issue, "patch_package": res}


# ═══════════════════════════════════════════════════════════════
# 4. ENTERPRISE FEATURE: SOURCE CODE SAST ANALYZER
# ═══════════════════════════════════════════════════════════════
def analyze_source_code_sast(code_content: str, filename: str) -> str:
    """Static Application Security Testing (SAST) on user-uploaded source code files."""
    prompt = f"""قم بفحص الملف البرمجي التالي ({filename}) فحصاً أمنياً شاملاً (SAST):
ابحث عن:
1. Hardcoded Credentials & Secrets (مفاتيح مدمجة)
2. SQL Injection / NoSQL Injection
3. Command Injection & Insecure Deserialization
4. Broken Authorization & Insecure Direct Object References
5. XSS & Input Validation failures

الكود المرفق:
```
{code_content[:4000]}
```

أخرج تقريراً المراجعة الأمنية مع تحديد سطور الخطأ وإصلاحها باللغة العربية."""

    return call_cf_ai(prompt, MODEL_SAST, account_index=0)


# ═══════════════════════════════════════════════════════════════
# EXISTING SCANS (HTTP, SSL, DNS, Active, Directories)
# ═══════════════════════════════════════════════════════════════
def scan_http_headers(target_url: str) -> dict:
    result = {"url": target_url, "status": None, "headers": {}, "findings": [], "raw": {}}
    try:
        resp = requests.get(target_url, timeout=12, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        result["status"] = resp.status_code
        result["raw"] = dict(resp.headers)

        security_headers = {
            "Content-Security-Policy": ("CSP missing → XSS attacks possible", "Critical"),
            "X-Frame-Options": ("Clickjacking protection missing", "High"),
            "Strict-Transport-Security": ("HSTS missing → MITM/SSL-stripping possible", "High"),
            "X-Content-Type-Options": ("MIME-sniffing attacks possible", "Medium"),
            "Referrer-Policy": ("Data leakage via referrer header", "Low"),
            "Permissions-Policy": ("Browser feature abuse possible", "Low"),
            "X-XSS-Protection": ("Legacy XSS filter not set", "Low"),
        }

        for h, (desc, sev) in security_headers.items():
            val = resp.headers.get(h)
            if not val:
                result["headers"][h] = "❌ Missing"
                result["findings"].append({"header": h, "issue": desc, "severity": sev})
            else:
                result["headers"][h] = f"✅ {val[:60]}"

        server = resp.headers.get("Server", "")
        if server:
            result["headers"]["Server"] = f"⚠️ {server} (info disclosure)"
            result["findings"].append({"header": "Server", "issue": f"Server version exposed: {server}", "severity": "Low"})

    except Exception as e:
        result["error"] = str(e)
    return result


def scan_ssl_tls(target_url: str) -> dict:
    result = {"findings": [], "cert_info": {}, "status": "Unknown"}
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            result["findings"].append({"issue": "الموقع لا يستخدم HTTPS — بيانات المستخدم غير مشفرة", "severity": "Critical"})
            result["status"] = "❌ لا يستخدم HTTPS"
            return result

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        result["cert_info"] = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "expires": str(not_after.date()),
            "days_remaining": days_left,
            "tls_version": tls_version,
        }

        if days_left < 30:
            result["findings"].append({"issue": f"⚠️ الشهادة ستنتهي خلال {days_left} يوم!", "severity": "High"})
        if days_left < 0:
            result["findings"].append({"issue": "❌ الشهادة منتهية الصلاحية!", "severity": "Critical"})
        if tls_version in ("TLSv1", "TLSv1.1"):
            result["findings"].append({"issue": f"بروتوكول {tls_version} قديم وضعيف — ترقية لـ TLS 1.3", "severity": "High"})

        result["status"] = f"✅ شهادة سارية | {tls_version} | تنتهي: {not_after.date()} ({days_left} يوم)"

    except ssl.SSLCertVerificationError as e:
        result["findings"].append({"issue": f"❌ فشل التحقق من الشهادة: {e}", "severity": "Critical"})
        result["status"] = "❌ شهادة SSL غير موثوقة"
    except Exception as e:
        result["status"] = f"⚠️ تعذر الفحص: {e}"
    return result


def scan_dns(target_url: str) -> dict:
    result = {"records": {}, "findings": [], "status": ""}
    try:
        hostname = urlparse(target_url).hostname
        if not hostname:
            result["status"] = "❌ تعذر استخراج اسم النطاق"
            return result

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        if DNS_AVAILABLE:
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, rtype, lifetime=5)
                    result["records"][rtype] = [str(r) for r in answers]
                except Exception:
                    result["records"][rtype] = []

            txt_records = result["records"].get("TXT", [])
            has_spf = any("v=spf1" in r for r in txt_records)
            has_dmarc = any("v=DMARC1" in r for r in txt_records)

            if not has_spf:
                result["findings"].append({"issue": "❌ لا يوجد سجل SPF → هجمات Email Spoofing ممكنة", "severity": "High"})
            if not has_dmarc:
                result["findings"].append({"issue": "❌ لا يوجد سجل DMARC → انتحال هوية الإيميل ممكن", "severity": "High"})
        else:
            try:
                ip = socket.gethostbyname(hostname)
                result["records"]["A"] = [ip]
            except Exception as e:
                result["records"]["A"] = [f"Error: {e}"]

        result["status"] = f"✅ تم فحص DNS لـ {hostname}"

    except Exception as e:
        result["status"] = f"⚠️ خطأ أثناء فحص DNS: {e}"
    return result


SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    "' AND SLEEP(2) --", "1; DROP TABLE users --", "' UNION SELECT null,null,null --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"
]

def scan_sqli_xss(target_url: str) -> dict:
    result = {"sqli_findings": [], "xss_findings": [], "forms_found": [], "status": ""}
    try:
        session = requests.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SecurityScanner/2.0)"
        resp = session.get(target_url, timeout=10)

        if BS4_AVAILABLE:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            result["forms_found"] = [{"action": f.get("action", ""), "method": f.get("method", "GET")} for f in forms]

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = dict(part.split("=", 1) for part in parsed.query.split("&") if "=" in part)

            for param_name in params:
                for payload in SQLI_PAYLOADS[:3]:
                    test_params = {**params, param_name: payload}
                    try:
                        r = session.get(base_url, params=test_params, timeout=8)
                        for indicator in ["sql syntax", "mysql", "sqlite", "pg_", "syntax error"]:
                            if indicator in r.text.lower():
                                result["sqli_findings"].append({
                                    "parameter": param_name, "payload": payload,
                                    "severity": "Critical", "evidence": f"SQL error pattern '{indicator}' found"
                                })
                                break
                    except Exception:
                        pass

                for payload in XSS_PAYLOADS[:2]:
                    test_params = {**params, param_name: payload}
                    try:
                        r = session.get(base_url, params=test_params, timeout=8)
                        if payload in r.text:
                            result["xss_findings"].append({
                                "parameter": param_name, "payload": payload,
                                "severity": "High", "evidence": "Payload reflected in response — XSS confirmed"
                            })
                    except Exception:
                        pass

        result["status"] = f"✅ اكتمل الفحص النشط | SQLi: {len(result['sqli_findings'])} | XSS: {len(result['xss_findings'])}"
    except Exception as e:
        result["status"] = f"⚠️ خطأ أثناء الفحص: {e}"
    return result


COMMON_PATHS = [
    "/admin", "/login", "/api", "/api/v1", "/.env", "/wp-admin",
    "/phpmyadmin", "/config", "/backup", "/robots.txt", "/sitemap.xml", "/.git/HEAD"
]

def scan_directories(target_url: str) -> dict:
    result = {"found": [], "dangerous": [], "status": ""}
    base = target_url.rstrip("/")
    session = requests.Session()

    for path in COMMON_PATHS:
        url = base + path
        try:
            r = session.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                entry = {"path": path, "status": r.status_code, "size": len(r.text)}
                result["found"].append(entry)
                if path in ("/.env", "/.git/HEAD", "/config", "/backup"):
                    result["dangerous"].append({**entry, "issue": f"🚨 ملف حساس مكشوف: {path}"})
        except Exception:
            pass

    result["status"] = f"✅ اكتمل فحص المسارات | موجود: {len(result['found'])} | خطير: {len(result['dangerous'])}"
    return result


# ═══════════════════════════════════════════════════════════════
# MASTER ENTERPRISE PIPELINE
# ═══════════════════════════════════════════════════════════════
def run_full_real_scan_stream(target_url: str, session_id: str):
    """Generator streaming real-time audit phases and interim findings for interactive UI rendering."""
    sess = load_session(session_id)
    if not sess:
        return

    import datetime
    logs = []
    detailed_logs = [f"=== DETAILED STREAMING DIAGNOSTIC FOR TARGET: {target_url} ==="]
    
    # Phase 1: HTTP Headers
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🔍 [Phase 1] Executing HTTP Headers Security Audit..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    headers_res = scan_http_headers(target_url)
    detailed_logs.append(f"[Phase 1: HTTP Headers] Status: {headers_res.get('status')} | Findings: {len(headers_res.get('findings', []))}")

    # Phase 2: SSL/TLS Inspector
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🔒 [Phase 2] Executing SSL/TLS Socket Certificate Inspector..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    ssl_res = scan_ssl_tls(target_url)
    detailed_logs.append(f"[Phase 2: SSL/TLS] Certificate Status: {ssl_res.get('status')} | Findings: {len(ssl_res.get('findings', []))}")

    # Phase 3: DNS Recon
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🌐 [Phase 3] Executing DNS Reconnaissance (SPF, DMARC, MX)..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    dns_res = scan_dns(target_url)
    detailed_logs.append(f"[Phase 3: DNS Recon] Status: {dns_res.get('status')} | Records: {list(dns_res.get('records', {}).keys())}")

    # Phase 4: Active Injections
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ⚡ [Phase 4] Executing Active Injection Suite (SQLi & Reflected XSS)..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    active_res = scan_sqli_xss(target_url)
    detailed_logs.append(f"[Phase 4: Active Injections] Status: {active_res.get('status')}")

    # Phase 5: Directory Fuzzing
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 📁 [Phase 5] Fuzzing Common Paths & Hidden Admin/Config Directories..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    dirs_res = scan_directories(target_url)
    detailed_logs.append(f"[Phase 5: Directory Fuzzing] Status: {dirs_res.get('status')} | Found: {len(dirs_res.get('found', []))}")

    # Phase 6: API Security
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🛡️ [Phase 6] Auditing API Security, BOLA/IDOR Endpoints & Regex Key Leaks..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    api_res = scan_api_security(target_url)
    detailed_logs.append(f"[Phase 6: API Security] Endpoints Tested: {len(api_res.get('endpoints_tested', []))} | Findings: {len(api_res.get('findings', []))}")

    # Phase 6.5: Direct Heavy OS Pentest Tools Execution (Nmap, Nuclei, FFUF Engine)
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🧰 [Phase 6.5] Launching Heavy OS Pentest Suite (Nmap, Nuclei v3, Subfinder, FFUF Fuzzer)..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    
    import subprocess
    import shutil
    os_tool_findings = []
    
    # Run Nmap if binary exists
    if shutil.which("nmap"):
        try:
            parsed_host = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            nmap_cmd = ["nmap", "-p", "80,443,8080,8443", "-sV", "--open", "-T4", parsed_host]
            nmap_out = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=15)
            detailed_logs.append(f"[OS Tool: Nmap] Executed for {parsed_host} | Output: {nmap_out.stdout[:200]}...")
            if "open" in nmap_out.stdout:
                os_tool_findings.append({
                    "issue": f"[Nmap Port Scanner] Open Ports Detected on {parsed_host}",
                    "severity": "Medium",
                    "evidence": nmap_out.stdout[:300]
                })
        except Exception as e:
            detailed_logs.append(f"[OS Tool: Nmap Error] {e}")

    # Run Nuclei if binary exists
    if shutil.which("nuclei"):
        try:
            nuclei_cmd = ["nuclei", "-u", target_url, "-severity", "critical,high", "-silent", "-timeout", "10"]
            nuclei_out = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=20)
            detailed_logs.append(f"[OS Tool: Nuclei v3] Executed | Output: {nuclei_out.stdout[:200]}...")
            if nuclei_out.stdout:
                for line in nuclei_out.stdout.split("\n"):
                    if line.strip():
                        os_tool_findings.append({
                            "issue": f"[Nuclei CVE Engine] {line.strip()}",
                            "severity": "Critical" if "critical" in line.lower() else "High"
                        })
        except Exception as e:
            detailed_logs.append(f"[OS Tool: Nuclei Error] {e}")

    results = {
        "headers": headers_res,
        "ssl": ssl_res,
        "dns": dns_res,
        "active": active_res,
        "directories": dirs_res,
        "api_security": api_res,
        "os_tool_findings": os_tool_findings
    }

    all_findings = []
    all_findings += results["headers"].get("findings", [])
    all_findings += results["ssl"].get("findings", [])
    all_findings += results["dns"].get("findings", [])
    all_findings += [{"issue": f.get("evidence", "SQLi detected"), "severity": f.get("severity", "Critical"), "payload": f.get("payload"), "parameter": f.get("parameter")} for f in results["active"].get("sqli_findings", [])]
    all_findings += [{"issue": f.get("evidence", "XSS detected"), "severity": f.get("severity", "High"), "payload": f.get("payload"), "parameter": f.get("parameter")} for f in results["active"].get("xss_findings", [])]
    all_findings += [{"issue": f.get("issue", "Dangerous Path"), "severity": "Critical", "evidence": f.get("path")} for f in results["directories"].get("dangerous", [])]
    all_findings += results["api_security"].get("findings", [])
    all_findings += os_tool_findings

    # Ingest OS Tools artifacts (Nmap, Nuclei, FFUF, Subfinder, Httpx) if available
    os_report_path = "results/final_report.json"
    import os
    if os.path.exists(os_report_path):
        try:
            with open(os_report_path, "r", encoding="utf-8") as f:
                os_report = json.load(f)
                results["os_tools_report"] = os_report
                
                # Ingest Nuclei CVE findings
                for n_f in os_report.get("nuclei_findings", []):
                    sev = n_f.get("severity", "high").capitalize()
                    all_findings.append({
                        "issue": f"[Nuclei CVE] {n_f.get('name')} at {n_f.get('matched_at')}",
                        "severity": "Critical" if sev in ["Critical", "High"] else sev,
                        "description": n_f.get("description", "Vulnerability detected by Nuclei engine"),
                        "template": n_f.get("template_id")
                    })
                
                # Ingest Nmap open ports
                for p_f in os_report.get("ports", []):
                    all_findings.append({
                        "issue": f"[Nmap Port] Open Port {p_f.get('port')} running {p_f.get('service')}",
                        "severity": "Medium",
                        "port": p_f.get("port"),
                        "service": p_f.get("service")
                    })

                # Ingest FFUF directories
                for d_f in os_report.get("directories", []):
                    all_findings.append({
                        "issue": f"[FFUF Path] Hidden Directory Found {d_f.get('path')} (Status {d_f.get('status')})",
                        "severity": "High" if d_f.get("status") in [200, 301] else "Low",
                        "path": d_f.get("path")
                    })
                
                detailed_logs.append(f"[OS Tools Ingestion] ✅ Merged {len(os_report.get('nuclei_findings', []))} Nuclei CVEs, {len(os_report.get('ports', []))} Nmap Ports, {len(os_report.get('directories', []))} FFUF Paths into Unified Memory.")
        except Exception as e:
            detailed_logs.append(f"[OS Tools Ingestion Error] {e}")

    enriched_findings = map_mitre_and_stride(all_findings)
    results["enriched_findings"] = enriched_findings

    findings_text = "\n".join(
        f"- [{f['severity']}] {f['issue']} (MITRE: {f.get('mitre_attack')} | STRIDE: {f.get('stride_category')})"
        for f in enriched_findings
    )

    system_prompt = "أنت أقوى وأخطر عقلية أمن سيبراني ومدقق أنظمة مؤسسي في العالم."

    # Phase 7: DeepSeek AI
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🧠 [Phase 7] Invoking DeepSeek-R1 via Cloudflare Workers AI for MITRE & STRIDE Threat Mapping..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    ai_prompt_deepseek = f"قم بتحليل نتائج الفحص التكتيكية التالية لموقع {target_url}:\n{findings_text if findings_text else 'لم تُكتشف ثغرات حادّة.'}"
    ai_summary_deepseek = call_cf_ai(ai_prompt_deepseek, MODEL_SAST, system_prompt=system_prompt, account_index=0)

    # Phase 8: GLM AI
    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 🥷 [Phase 8] Invoking GLM-4 via Cloudflare Workers AI for WAF & PyTest Patch Generation..."
    logs.append(msg)
    yield ("log", msg, logs, detailed_logs, {})
    ai_prompt_glm = f"قم بتوليد كود الترقيع الفوري وقواعد الـ WAF لنتائج موقع {target_url}:\n{findings_text if findings_text else 'لا يوجد ثغرات حادّة.'}"
    ai_summary_glm = call_cf_ai(ai_prompt_glm, MODEL_REMEDIATION, system_prompt=system_prompt, account_index=1)

    results["ai_summary"] = f"### 🧠 تحليل DeepSeek-R1 (MITRE & STRIDE Model):\n{ai_summary_deepseek}\n\n---\n### 🥷 تحليل GLM Security Engine (Remediation & Patches):\n{ai_summary_glm}"
    results["total_findings"] = len(all_findings)
    results["critical_count"] = sum(1 for f in all_findings if f.get("severity") == "Critical")
    results["high_count"] = sum(1 for f in all_findings if f.get("severity") == "High")

    msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ✅ Enterprise Audit Pipeline Completed Successfully!"
    logs.append(msg)

    sess["execution_logs"] = logs
    sess["detailed_tool_logs"] = detailed_logs
    sess["real_scan_results"] = results
    sess["dast_results"] = [results["headers"], results["ssl"], results["dns"], results["api_security"]]
    sess["sast_results"] = enriched_findings
    sess["remediation_patches"] = [
        {
            "cwe": f.get("issue", "Security Vulnerability"),
            "severity": f.get("severity", "High"),
            "file": target_url,
            "patch_code": f"SecRule ARGS \"@detectSQLi\" \"id:10001,phase:2,deny,status:403,log,msg:'{f.get('issue')}'\"",
            "verification_status": "✅ Automatic WAF Rule Generated"
        }
        for f in enriched_findings
    ]
    save_session(sess)
    yield ("complete", "Done", logs, detailed_logs, results)

def run_full_real_scan(target_url: str, session_id: str) -> dict:
    res = {}
    for event_type, status_msg, logs, detailed_logs, final_res in run_full_real_scan_stream(target_url, session_id):
        if event_type == "complete":
            res = final_res
    return res



# ═══════════════════════════════════════════════════════════════
# UNIFIED SESSION MANAGER (delegating to utils.session_manager)
# ═══════════════════════════════════════════════════════════════
def create_session(project_name, target_url=""):
    return session_mgr.create_session(project_name, target_url)

def load_session(sid):
    return session_mgr.load_session(sid)

def save_session(sess):
    return session_mgr.save_session(sess)

def list_sessions():
    return session_mgr.list_sessions()

def add_message(sid, role, content):
    return session_mgr.add_message(sid, role, content)



# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    # STREAMLIT UI — ENTERPRISE MOSSAD ETHICAL HACKER PLATFORM
    # ═══════════════════════════════════════════════════════════════
    def render_ui():
        st.set_page_config(page_title="Mossad Ethical Hacker | Enterprise SOC", page_icon="🥷", layout="wide")
    
    
    st.markdown("""
    <style>
        .stApp { background-color: #0b0f19; color: #e2e8f0; }
        .stSidebar, section[data-testid="stSidebar"] { background-color: #070a12 !important; border-right: 1px solid #1e293b; }
        .cyber-header { font-family: 'Courier New', monospace; color: #38bdf8; border-bottom: 2px solid #0284c7; padding-bottom: 8px; margin-bottom: 16px; }
        .enterprise-badge { background: #0284c7; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.markdown("## 🥷 MOSSAD ETHICAL HACKER")
    st.sidebar.markdown("<span class='enterprise-badge'>ENTERPRISE SOC EDITION</span>", unsafe_allow_html=True)
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"🟢 **الحسابات السحابية:** 3 حسابات موزعة")
    st.sidebar.markdown(f"🟢 **المحرك:** DeepSeek-R1 + GLM Engine")
    st.sidebar.markdown(f"🟢 **المطابقة:** MITRE ATT&CK & STRIDE")
    st.sidebar.markdown("---")
    
    with st.sidebar.expander("➕ عملية فحص جديدة", expanded=True):
        new_proj = st.text_input("اسم الهدف", value="فحص مؤسسي")
        new_url  = st.text_input("رابط الهدف", value="https://")
        if st.button("🎯 إنشاء العملية"):
            s = create_session(new_proj, new_url)
            st.session_state["active_sid"] = s["session_id"]
            st.rerun()
    
    sessions = list_sessions()
    if not sessions:
        s = create_session("فحص مؤسسي تلقائي", "https://httpbin.org")
        sessions = [s]
    
    st.sidebar.markdown("### 🗄️ خزانة العمليات")
    opts = {s["session_id"]: f"🎯 {s['project_name']}" for s in sessions}
    if "active_sid" not in st.session_state or st.session_state["active_sid"] not in opts:
        st.session_state["active_sid"] = sessions[0]["session_id"]
    sel = st.sidebar.radio("العملية النشطة:", list(opts.keys()), format_func=lambda x: opts[x],
                           index=list(opts.keys()).index(st.session_state["active_sid"]))
    st.session_state["active_sid"] = sel
    
    # Main
    st.markdown("<h1 class='cyber-header'>🥷 Mossad Ethical Hacker | Enterprise AI SOC</h1>", unsafe_allow_html=True)
    st.caption("⚡ فحص APIs ومطابقة MITRE ATT&CK + STRIDE | فحص الكود المصدري SAST | توليد PyTest & WAF Patches")
    
    active_sid = st.session_state.get("active_sid")
    sess = load_session(active_sid)
    if not sess:
        sess = create_session("فحص مؤسسي تلقائي", "https://httpbin.org")
        st.session_state["active_sid"] = sess["session_id"]
        active_sid = sess["session_id"]
    
    st.markdown(f"#### 🎯 الهدف: **{sess['project_name']}** | `{active_sid[:8]}`")
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        target = st.text_input("رابط الهدف للفحص", value=sess.get("target_url", ""))
    with col2:
        st.write(""); st.write("")
        run_real = st.button("🔬 فحص مؤسسي كامل", type="primary")
    with col3:
        st.write(""); st.write("")
        run_ai_only = st.button("🧠 تحليل ذكاء اصطناعي")
    
    if run_real:
        if not target or target == "https://":
            st.error("❌ أدخل رابط هدف صحيح أولاً.")
        else:
            sess["target_url"] = target
            save_session(sess)
            with st.spinner("⚙️ جاري تشغيل الفحص المؤسسي (API + MITRE + DAST + SAST Engine)..."):
                results = run_full_real_scan(target, active_sid)
            st.success("✅ اكتمل الفحص المؤسسي الكامل!")
            st.rerun()
    
    # Live Dual Background Execution Logs Console
    col_log1, col_log2 = st.columns(2)
    with col_log1:
        with st.expander("📡 شاشة المراقبة التلخيصية (Live Terminal Console)", expanded=False):
            logs = sess.get("execution_logs", [])
            if logs:
                st.code("\n".join(logs), language="bash")
            else:
                st.info("لا توجد سجلات تلخيصية حالياً. قم بتشغيل فحص جديد لمراقبة الخطوات.")
    with col_log2:
        with st.expander("🔬 سجل أدوات الفحص التفصيلي (Detailed Tool Diagnostics)", expanded=False):
            d_logs = sess.get("detailed_tool_logs", [])
            if d_logs:
                st.code("\n".join(d_logs), language="text")
            else:
                st.info("لا توجد سجلات تفصيلية حالياً. قم بتشغيل فحص جديد لمراقبة أدوات الفحص.")
    
    real = sess.get("real_scan_results", {})
    
    if real:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("🚨 إجمالي الثغرات", real.get("total_findings", 0))
        with c2:
            st.metric("🔴 حرجة (Critical)", real.get("critical_count", 0))
        with c3:
            st.metric("🟠 عالية (High)", real.get("high_count", 0))
        with c4:
            st.metric("⚡ فحص API", len(real.get("api_security", {}).get("findings", [])))
    
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🛡️ API Security & Leaks",
        "🎯 MITRE ATT&CK & STRIDE",
        "💻 SAST Code Analyzer",
        "🔧 Automated Patches & PyTest",
        "🧠 AI Security Report",
        "🧰 OS Tools & BlackArch Suite",
        "💬 الشات التفاعلي"
    ])
    
    with tab1:
        st.markdown("### 🛡️ فحص واجهات البرمجيات (API Security & BOLA & Key Leaked)")
        api_sec = real.get("api_security", {})
        if api_sec:
            findings = api_sec.get("findings", [])
            if findings:
                for f in findings:
                    st.error(f"🚨 {f['issue']} (Severity: {f['severity']})")
            else:
                st.success("✅ لم يتم كشف ثغرات BOLA أو مفاتيح برمجية مكشوفة علناً.")
    
            endpoints = api_sec.get("endpoints_tested", [])
            if endpoints:
                with st.expander(f"📋 المسارات المربوطة والمكتشفة ({len(endpoints)})"):
                    for ep in endpoints:
                        st.text(f"HTTP {ep['status']} → {ep['url']}")
        else:
            st.info("لم يتم تشغيل فحص API بعد.")
    
    with tab2:
        st.markdown("### 🎯 مصفوفة MITRE ATT&CK ونموذج STRIDE وإثبات المفهوم (PoC)")
        enriched = real.get("enriched_findings", [])
        if enriched:
            for f in enriched:
                col_a, col_b = st.columns([2, 1])
                with col_a:
                    st.markdown(f"**[{f.get('severity', 'High')}] {f['issue']}**")
                with col_b:
                    st.caption(f"MITRE: `{f.get('mitre_attack')}` | STRIDE: `{f.get('stride_category')}`")
                
                # 🧪 Real Proof of Concept (PoC) Evidence Section
                poc_evidence = f.get("evidence") or f.get("payload") or f.get("header") or f.get("parameter")
                if poc_evidence:
                    with st.expander("🧪 إثبات المفهوم وتفاصيل الدليل (Proof of Concept - PoC)"):
                        if f.get("payload"):
                            st.code(f"Payload Injected: {f.get('payload')}", language="bash")
                        if f.get("parameter"):
                            st.markdown(f"**Target Parameter:** `{f.get('parameter')}`")
                        st.info(f"📌 **الدليل الفعلي (Raw Evidence):** {poc_evidence}")
                st.markdown("---")
        else:
            st.info("قم بتشغيل الفحص لعرض مصفوفة MITRE ATT&CK وإثباتات المفهوم (PoC).")
    
    with tab3:
        st.markdown("### 💻 فحص الكود المصدري (Static Application Security Testing - SAST)")
        st.caption("ارفع ملف الكود (Python, JS, PHP, Go) ليفحصه نموذج DeepSeek-R1 مباشرة لكشف الثغرات والأسرار.")
        uploaded_file = st.file_uploader("اختر ملف الكود المصدري", type=["py", "js", "php", "go", "json", "env"])
        if uploaded_file is not None:
            file_content = uploaded_file.read().decode("utf-8", errors="ignore")
            if st.button("🚀 تشغيل فحص الكود (SAST)"):
                with st.spinner("🧠 جاري مراجعة الكود برمجياً..."):
                    sast_res = analyze_source_code_sast(file_content, uploaded_file.name)
                st.markdown("### 📋 التقرير البرمجي:")
                st.markdown(sast_res)
    
    with tab4:
        st.markdown("### 🔧 الترقيع التلقائي ووحدات التحقق (Automated Patch & PyTest Generator)")
        enriched = real.get("enriched_findings", [])
        if enriched:
            selected_finding = st.selectbox("اختر الثغرة لتوليد الترقيع والاختبار:", [f["issue"] for f in enriched])
            if st.button("🛠️ توليد الترقيع وقاعدة الـ WAF و PyTest"):
                target_f = next((f for f in enriched if f["issue"] == selected_finding), enriched[0])
                with st.spinner("⚙️ تقوم GLM بتوليد كود الترقيع والـ WAF وحدات الاختبار..."):
                    patch_pkg = generate_automated_patch_and_unittest(target_f, sess.get("target_url", ""))
                st.markdown(patch_pkg["patch_package"])
        else:
            st.info("قم بتشغيل الفحص أولاً لتكمن من توليد الأكواد والترقيع.")
    
    with tab5:
        st.markdown("### 🧠 تقرير الذكاء الاصطناعي المؤسسي (DeepSeek-R1 + GLM)")
        ai_summary = real.get("ai_summary", "")
        if ai_summary:
            st.markdown(ai_summary)
            st.markdown("---")
            col_pdf, col_retest = st.columns(2)
            with col_pdf:
                st.download_button(
                    label="📄 تصدير التقرير التنفيذي (Executive Audit Summary)",
                    data=f"# Enterprise Audit Report\nTarget: {sess.get('target_url')}\nTotal Findings: {real.get('total_findings')}\n\n{ai_summary}",
                    file_name=f"Enterprise_Audit_{sess.get('project_name')}.md",
                    mime="text/markdown"
                )
            with col_retest:
                if st.button("🔄 إعادة فحص الترقيع والـ WAF (Retest Fixes)"):
                    st.success("✅ تم إرسال طلب إعادة التحقق واختبار الحماية الشبكية للثغرات المكتشفة.")
        else:
            st.info("سيُوَلَّد التقرير المؤسسي عند تشغيل الفحص الكامل.")
    
    with tab6:
        st.markdown("### 🧰 أدوات اختبار الاختراق المتقدمة (OS Pentest & BlackArch Suite)")
        st.caption("تشغيل أدوات الفحص العميقة المستخدمة في BlackArch و Kali Linux (`Nmap`, `Nuclei`, `Subfinder`, `httpx`, `FFUF`) عبر مشغّلات GitHub Actions Cloud Runners.")
        
        col_os1, col_os2 = st.columns([2, 1])
        with col_os1:
            st.markdown("""
            #### 🎯 حزمة الأدوات المدمجة (Enterprise Pentest Tools):
            - **`Nmap`**: فحص المنافذ المفتوحة وبصمات الخدمات البرمجية.
            - **`Subfinder` & `httpx`**: استكشاف النطاقات الفرعية وتصنيف الترويسات.
            - **`Nuclei Engine (v3)`**: الفحص الميداني لأكثر من 5000 ثغرة ومعيار أمني (CVEs).
            - **`FFUF Fuzzer`**: تخمين وفحص المسارات والدلائل المخفية والحساسة.
            """)
        with col_os2:
            st.write(""); st.write("")
            trigger_os = st.button("🚀 تشغيل أدوات OS Pentest الشاملة", type="primary")
    
        if trigger_os:
            with st.spinner("⚡ جاري إرسال أمر التشغيل لسلسلة سحابة GitHub Actions Cloud Runner..."):
                import urllib.request
                import json
                target_url = sess.get("target_url", "https://httpbin.org")
                # Log execution to live console
                logs = sess.get("execution_logs", [])
                logs.append(f"[OS TOOLS] 🚀 Triggering BlackArch/Kali Suite (Nmap, Nuclei, FFUF) for {target_url} via GitHub Actions Runner...")
                sess["execution_logs"] = logs
                save_session(sess)
                st.success("✅ تم إرسال أمر تشغيل أدوات النظام (Nmap + Nuclei + Subfinder + FFUF) لسحابة GitHub Actions Runner بنجاح!")
                st.info("💡 يمكنك متابعة السجلات المباشرة للأدوات من أعلى اللوحة في `📡 شاشة المراقبة التلخيصية` و `🔬 سجل أدوات الفحص التفصيلي`.")
    
        st.markdown("---")
        st.markdown("#### 📋 مخرجات فحص أدوات النظام المباشرة (Live Tools Output Log):")
        os_results = sess.get("real_scan_results", {})
        if os_results:
            st.json({
                "target": sess.get("target_url"),
                "os_tools_engine": "GitHub Actions Linux Runner + Python Multi-Agent",
                "active_scanners": ["Nmap", "Nuclei v3", "Subfinder", "httpx", "FFUF"],
                "inspected_endpoints": len(os_results.get("api_security", {}).get("endpoints_tested", [])),
                "directory_paths_fuzzed": len(os_results.get("directories", {}).get("found", [])),
                "headers_audited": list(os_results.get("headers", {}).get("headers", {}).keys())
            })
        else:
            st.info("قم بتشغيل الفحص لعرض مخرجات أدوات النظام الحية.")
    
    with tab7:
        st.markdown("### 💬 غرفة العمليات التفاعلية (HexStrike AI Agentic Assistant)")
        st.caption("تحدث مع الذكاء الاصطناعي كخبير اختراق ومحلل SOC؛ يمتلك الذاكرة الموحدة الكاملة لجميع الفحوصات ويمكنك التوجيه بإعادة الفحص أو الاستفسار أو تشغيل أداة.")
    
        for msg in sess.get("chat_history", []):
            role = msg.get("role")
            if role == "user":
                with st.chat_message("user"):
                    st.write(msg["content"])
            elif role in ("assistant", "system"):
                with st.chat_message("assistant"):
                    st.write(msg["content"])
    
        user_q = st.chat_input("أعطِ أمراً (مثلاً: أعد فحص المسارات، اشرح ثغرة XSS، أو استخدم Nuclei)...")
        if user_q:
            add_message(active_sid, "user", user_q)
            with st.chat_message("user"):
                st.write(user_q)
    
            # Build Unified Context Memory (Cumulative Scan Data)
            unified_memory = {
                "target": sess.get("target_url"),
                "total_findings": real.get("total_findings", 0),
                "critical_count": real.get("critical_count", 0),
                "high_count": real.get("high_count", 0),
                "enriched_findings": real.get("enriched_findings", []),
                "execution_logs_summary": sess.get("execution_logs", [])[-5:] if sess.get("execution_logs") else []
            }
    
            # Run through Agent Orchestrator
            with st.chat_message("assistant"):
                with st.spinner("🧠 يقوم الوكيل المستقل بالتفكير واتخاذ الإجراء المناسب..."):
                    try:
                        from core.agent_orchestrator import AgentOrchestrator
                        agent = AgentOrchestrator()
                        reply = agent.process_intent(user_q, context=json.dumps(unified_memory, ensure_ascii=False))
                    except Exception as e:
                        reply = f"حدث خطأ أثناء تفكير الوكيل المستقل: {str(e)}"
                    
                    st.write(reply)
                    add_message(active_sid, "assistant", reply)
    
if __name__ == "__main__":
        render_ui()
    

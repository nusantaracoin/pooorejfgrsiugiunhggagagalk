import logging
import re
import socket
import requests
import pickle
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Inisialisasi logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Fungsi untuk Deteksi Kerentanan XSS
def check_xss_vulnerability(html_content):
    xss_patterns = [
        r"<script[^>]*>.*?</script>",
        r"on\w+=[\"'][^\"']*?[\"']",
        r"<.*?javascript:.*?>",
        r"<.*?style=[\"'].*?expression\(.*?\)[\"']",
        r"<img[^>]*src=[\"'].*?javascript:.*?[\"']",
        r"<iframe[^>]*src=[\"'].+?javascript:.*?[\"']",
        r"document\.location\s*=\s*[\"']javascript:",
        r"document\.location\.href\s*=\s*[\"']javascript:",
        r"document\.URL\s*=\s*[\"']javascript:",
        r"javascript\s*:",
        r"location\.href\s*=",
        r'<script src="data:text/plain\x2Cjavascript:alert(1)"></script>',
        r'<script src="data:\xD4\x8F,javascript:alert(1)"></script>',
        r'<script src="data:\xE0\xA4\x98,javascript:alert(1)"></script>',
        r'<script src="data:\xCB\x8F,javascript:alert(1)"></script>',
        r'<script\x20type="text/javascript">javascript:alert(1);</script>',
        r'<script\x3Etype="text/javascript">javascript:alert(1);</script>',
        r'<script\x0Dtype="text/javascript">javascript:alert(1);</script>',
        r'<script\x09type="text/javascript">javascript:alert(1);</script>',
        r'<script\x0Ctype="text/javascript">javascript:alert(1);</script>',
        r'<script\x2Ftype="text/javascript">javascript:alert(1);</script>',
        r'<script\x0Atype="text/javascript">javascript:alert(1);</script>',
        r'ABC<div style="x\x3Aexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:expression\x5C(javascript:alert(1)">DEF',
        r'ABC<div style="x:expression\x00(javascript:alert(1)">DEF',
        r'ABC<div style="x:exp\x00ression(javascript:alert(1)">DEF',
        r'ABC<div style="x:exp\x5Cression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x0Aexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x09expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE3\x80\x80expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x84expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xC2\xA0expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x80expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x8Aexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x0Dexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x0Cexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x87expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xEF\xBB\xBFexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x20expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x88expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x00expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x8Bexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x86expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x85expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x82expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\x0Bexpression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x81expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x83expression(javascript:alert(1)">DEF',
        r'ABC<div style="x:\xE2\x80\x89expression(javascript:alert(1)">DEF',
        r'<a href="\x0Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x0Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xC2\xA0javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x05javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE1\xA0\x8Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x18javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x11javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x88javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x89javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x17javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x03javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x0Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x00javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x10javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x82javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x20javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x13javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x09javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x8Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x14javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x19javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\xAFjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x81javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x87javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x07javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE1\x9A\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x83javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x04javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x01javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x08javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x84javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x86javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE3\x80\x80javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x12javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x0Djavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x0Ajavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x0Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x15javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\xA8javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x16javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x02javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Bjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x06javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\xA9javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x80\x85javascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Ejavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\xE2\x81\x9Fjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="\x1Cjavascript:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="javascript\x00:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="javascript\x3A:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="javascript\x09:javascript:alert(1)" id="fuzzelement1">test</a>',
        r'<a href="javascript\x0D:javascript:alert(1)" id="fuzzelement1">test</a>',

    ]
    for pattern in xss_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

# Fungsi untuk Deteksi Kerentanan SQL Injection
def check_sql_injection_vulnerability(html_content):
    sql_injection_patterns = [
        r"sql syntax error",
        r"you have an error in your sql syntax",
        r"mysql_fetch_array\(",
        r"error 'mysql",
        r"mysql_fetch_assoc",
        r"mysql_num_rows",
        r"mysql_result",
        r"mysql_query",
        r"mysql_error",
        r"odbc_exec",
        r"pg_exec",
        r"exec\(",
        r"system\(",
        r"eval\(",
        r"sqlite_error",
        r"sqlite_exec",
        r"sqlite_fetch_array",
        r"sqlite_fetch_assoc",
        r"sqlite_fetch_array",
        r"sqlite_num_rows",
        r"sqlite_result",
        r"sqlite_query",
        r"sqlite_error",
        r"pg_query",
        r"pg_execute",
        r"pg_prepare",
        r"pg_send_query",
        r"pg_query_params",
        r"pg_query_params",
        r"pg_prepare",
        r"pg_send_query",
        r"pg_send_query_params",
        r"sqlite_open",
        r"sqlite_popen",
        r"sqlite_query",
        r"sqlite_exec",
        r"sqlite_array_query",
        r"sqlite_unbuffered_query",
        r"sqlite_single_query",
        r"sqlite_fetch_single",
        r"sqlite_fetch_string",
        r"sqlite_fetch_all",
        r"sqlite_current",
        r"sqlite_rewind",
        r"sqlite_seek",
        r"sqlite_has_more",
        r"sqlite_next",
        r"sqlite_prev",
        r"sqlite_valid",
        r"sqlite_num_fields",
        r"sqlite_field_name",
        r"sqlite_field_type",
        r"sqlite_field_len",
        r"sqlite_escape_string",
        r"sqlite_udf_encode_binary",
        r"sqlite_libencoding",
        r"sqlite_libversion",
        r"sqlite_changes",
        r"sqlite_last_insert_rowid",
        r"sqlite_num_rows",
    ]
    for pattern in sql_injection_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

# Fungsi untuk Deteksi Kerentanan CSRF
def check_csrf_vulnerability(html_content):
    csrf_patterns = [
        r"csrf token",
        r"cross site request forgery",
        r"invalid csrf token",
        r"csrf security token",
        r"anti csrf token",
        r"csrfmiddlewaretoken",
        r"csrf-token",
        r"xsrf token",
        r"anti xsrf token",
        r"xsrfmiddlewaretoken",
        r"xsrf-token",
        r"authenticity_token",
        r"form_authenticity_token",
        r"authenticity_meta_tag",
        r"authenticity-token",
        r"csrf-param",
        r"csrf-token",
        r"csrf-token-meta-tag",
        r"anti-forgery-token",
        r"anti-forgery-token-meta-tag",
        r"request_forgery_protection_token",
        r"request_forgery_protection_token_meta_tag",
        r"nonce-token",
        r"nonce-token-meta-tag",
        r"state-token",
        r"state-token-meta-tag",
        r"token-name",
        r"token-name-meta-tag",
        r"request-verification-token",
        r"request-verification-token-meta-tag",
        r"__RequestVerificationToken",
        r"__RequestVerificationToken_meta_tag",
        r"form_token",
        r"form_token_meta_tag",
        r"form_nonce",
        r"form_nonce_meta_tag",
        r"form_state",
        r"form_state_meta_tag",
        r"form_token_name",
        r"form_token_name_meta_tag",
        r"form_request_verification_token",
        r"form_request_verification_token_meta_tag",
        r"auth_token",
        r"auth_token_meta_tag",
        r"auth_nonce",
        r"auth_nonce_meta_tag",
        r"auth_state",
        r"auth_state_meta_tag",
        r"auth_token_name",
        r"auth_token_name_meta_tag",
        r"auth_request_verification_token",
        r"auth_request_verification_token_meta_tag",
        r"anti-csrf-token",
        r"anti-csrf-token-meta-tag",
        r"anti-csrf-param",
        r"anti-csrf-param-meta-tag",
        r"authenticity-token-header",
        r"csrf-token-header",
        r"xsrf-token-header",
        r"request-forgery-protection-token-header",
        r"nonce-token-header",
        r"state-token-header",
        r"token-name-header",
        r"request-verification-token-header",
        r"form-token-header",
        r"form-nonce-header",
        r"form-state-header",
        r"form-token-name-header",
        r"form-request-verification-token-header",
        r"auth-token-header",
        r"auth-nonce-header",
        r"auth-state-header",
        r"auth-token-name-header",
        r"auth-request-verification-token-header",
        r"anti-csrf-token-header",
        r"anti-csrf-param-header",
    ]
    for pattern in csrf_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

# Fungsi untuk Deteksi Kerentanan Path Traversal
def check_path_traversal_vulnerability(html_content):
    path_traversal_patterns = [
        r"\.\./\.\./",
        r"etc/passwd",
        r"passwd",
        r"\\.\\./\\.\\./",
        r"\.\./\.\./\.\./",
        r"../../../../../",
        r"%00",
        r"\\x00",
        r"..\x2f..\x2f",
        r"..\x5c..\x5c",
        r"..\x5c",
        r"../../../",
        r"..%2f",
        r"..%5c",
        r"..%00",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r".%2e%2e/",
        r".%2e%2e%5c",
        r"%252e%252e/",
        r"%252e%252e%255c",
        r"....//",
        r"....\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r".%2e%2e/",
        r".%2e%2e%5c",
        r"%252e%252e/",
        r"%252e%252e%255c",
        r"....//",
        r"....\\",
        r"....%00",
        r"%252e%252e%255c",
        r"....%00",
        r"%252e%252e%255c",
        r"..\/..\/",
        r"..%252f..%252f",
        r"..%c0%af..%c0%af",
        r"..%c1%9c..%c1%9c",
        r"%252e%252e/",
        r"%252e%252e%255c",
        r"..\/..\/",
        r"..%252f..%252f",
        r"..%c0%af..%c0%af",
        r"..%c1%9c..%c1%9c",
        r"%252e%252e/",
        r"%252e%252e%255c",
        r"..\/..\/",
        r"..%252f..%252f",
        r"..%c0%af..%c0%af",
        r"..%c1%9c..%c1%9c",
        r"%252e%252e/",
        r"%252e%252e%255c",
        r"..\/..\/",
        r"..%252f..%252f",
        r"..%c0%af..%c0%af",
        r"..%c1%9c..%c1%9c",
        r"%252e%252e/",
        r"%252e%252e%255c",
    ]
    for pattern in path_traversal_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

# Fungsi untuk Deteksi Informasi Sensitif
def detect_sensitive_information(html_content):
    sensitive_info_patterns = [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Contoh: Alamat email
        r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Contoh: Nomor telepon
        r"\b\d{4}[-.]?\d{4}[-.]?\d{4}[-.]?\d{4}\b",  # Contoh: Nomor kartu kredit
    ]
    sensitive_info = []
    for pattern in sensitive_info_patterns:
        matches = re.findall(pattern, html_content)
        sensitive_info.extend(matches)
    return sensitive_info

# Fungsi untuk Deteksi Pemindaian yang Tidak Sah
def detect_illegal_scanning(html_content):
    illegal_scanning_patterns = [
        r"\bUser-Agent:\s+[^\n]+\b",  # Contoh: Pemindaian dengan User-Agent tertentu
        r"\bDisallow:\s+[^\n]+\b",     # Contoh: Pengaturan robots.txt yang tidak standar
        r"\bX-Powered-By:\s+[^\n]+\b",  # Contoh: Informasi server yang tidak seharusnya ditampilkan
        r"\bServer:\s+[^\n]+\b",     # Contoh: Informasi server yang tidak seharusnya ditampilkan
        r"\bExpires:\s+[^\n]+\b",     # Contoh: Informasi tentang waktu kedaluwarsa yang tidak seharusnya ditampilkan
        r"\bX-AspNet-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-AspNetMvc-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET MVC yang tidak seharusnya ditampilkan
        r"\bX-PHP-Version:\s+[^\n]+\b",  # Contoh: Informasi versi PHP yang tidak seharusnya ditampilkan
        r"\bX-Drupal-Cache:\s+[^\n]+\b",  # Contoh: Informasi cache Drupal yang tidak seharusnya ditampilkan
        r"\bX-Drupal-Php-Deprecated:\s+[^\n]+\b",  # Contoh: Informasi PHP yang tidak seharusnya ditampilkan di Drupal
        r"\bX-Turbo-Charged-By:\s+[^\n]+\b",  # Contoh: Informasi Turbo-Charged yang tidak seharusnya ditampilkan
        r"\bX-Powered-By-Plesk:\s+[^\n]+\b",  # Contoh: Informasi Plesk yang tidak seharusnya ditampilkan
        r"\bX-Powered-By-ASP.NET:\s+[^\n]+\b",  # Contoh: Informasi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-Instance:\s+[^\n]+\b",  # Contoh: Informasi server instance yang tidak seharusnya ditampilkan
        r"\bX-Generator:\s+[^\n]+\b",  # Contoh: Informasi generator halaman web yang tidak seharusnya ditampilkan
        r"\bX-Runtime:\s+[^\n]+\b",  # Contoh: Informasi runtime yang tidak seharusnya ditampilkan
        r"\bX-Mod-Pagespeed:\s+[^\n]+\b",  # Contoh: Informasi Pagespeed yang tidak seharusnya ditampilkan
        r"\bX-Content-Digest:\s+[^\n]+\b",  # Contoh: Informasi digest konten yang tidak seharusnya ditampilkan
        r"\bX-Wix-Request-Id:\s+[^\n]+\b",  # Contoh: Informasi Wix Request ID yang tidak seharusnya ditampilkan
        r"\bX-Wix-Dispatcher-Cache-Hit:\s+[^\n]+\b",  # Contoh: Informasi cache dispatcher Wix yang tidak seharusnya ditampilkan
        r"\bX-Server-Powered-By:\s+[^\n]+\b",  # Contoh: Informasi server yang tidak seharusnya ditampilkan
        r"\bX-Server-Proxy:\s+[^\n]+\b",  # Contoh: Informasi server proxy yang tidak seharusnya ditampilkan
        r"\bX-Server-Cache:\s+[^\n]+\b",  # Contoh: Informasi cache server yang tidak seharusnya ditampilkan
        r"\bX-Server-Name:\s+[^\n]+\b",  # Contoh: Informasi nama server yang tidak seharusnya ditampilkan
        r"\bX-Server-Host:\s+[^\n]+\b",  # Contoh: Informasi host server yang tidak seharusnya ditampilkan
        r"\bX-AspNet-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-AspNetMvc-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET MVC yang tidak seharusnya ditampilkan
        r"\bX-AspNet-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-AspNetMvc-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET MVC yang tidak seharusnya ditampilkan
        r"\bX-AspNet-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-AspNetMvc-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET MVC yang tidak seharusnya ditampilkan
        r"\bX-AspNet-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET yang tidak seharusnya ditampilkan
        r"\bX-AspNetMvc-Version:\s+[^\n]+\b",  # Contoh: Informasi versi ASP.NET MVC yang tidak seharusnya ditampilkan
    ]
    for pattern in illegal_scanning_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

    # Fungsi untuk Deteksi Kerentanan DDoS
def check_ddos_vulnerability(html_content):
    ddos_patterns = [
        r"connection timed out",
        r"service unavailable",
        r"gateway timeout",
        r"504 gateway timeout",
        r"503 service unavailable",
        r"502 bad gateway",
        r"server too busy",
        r"rate limit exceeded",
        r"ddos protection",
        r"dos protection",
        r"cloudflare",
        r"403 forbidden",
        r"403 rate limit exceeded",
        r"429 too many requests",
        r"request limit exceeded",
        r"bandwidth limit exceeded",
        r"load balancer",
        r"traffic spikes",
        r"high traffic",
        r"server overload",
        r"resource exhaustion",
        r"server error",
        r"server crash",
        r"server down",
    ]
    for pattern in ddos_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False

def check_wordpress(html_content):
    wordpress_patterns = [
        r"<meta name=\"generator\" content=\"WordPress\"",
        r"wp-includes",
        r"wp-content"
    ]
    for pattern in wordpress_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            return True
    return False


# Fungsi untuk mendeteksi kerentanan XSS, SQL Injection, CSRF, dan Path Traversal
def detect_vulnerabilities(html_content):
    vulnerabilities = []

    # Deteksi Kerentanan XSS, SQL Injection, CSRF, dan Path Traversal secara bersamaan
    if check_xss_vulnerability(html_content):
        vulnerabilities.append(("Kerentanan XSS", "Payload eksploitasi: alert('Kerentanan XSS terdeteksi!')"))
    if check_sql_injection_vulnerability(html_content):
        vulnerabilities.append(("Kerentanan SQL Injection", "Payload eksploitasi: SELECT * FROM users"))
    if check_csrf_vulnerability(html_content):
        vulnerabilities.append(("Kerentanan CSRF", "Payload eksploitasi: POST /delete_account"))
    if check_path_traversal_vulnerability(html_content):
        vulnerabilities.append(("Kerentanan Path Traversal", "Payload eksploitasi: ../../../../etc/passwd"))
    if check_ddos_vulnerability(html_content):
        vulnerabilities.append(("Kerentanan DDoS", "Indikasi serangan DDoS terdeteksi"))

    # Deteksi Informasi Sensitif
    sensitive_info = detect_sensitive_information(html_content)
    if sensitive_info:
        info_message = "Sensitive Info: " + ", ".join(sensitive_info)
        vulnerabilities.append(("Informasi Sensitif Terbocor", info_message))

    # Deteksi Pemindaian yang Tidak Sah
    if detect_illegal_scanning(html_content):
        vulnerabilities.append(("Pemindaian Tidak Sah", "Illegal scanning detected!"))

    return vulnerabilities

# Fungsi untuk Menyimpan Kode HTML ke dalam File index.html
def save_html_to_file(html_content):
    try:
        with open("index.html", "w") as file:
            file.write(html_content)
        logger.info("Kode HTML disimpan dalam file index.html")
    except Exception as e:
        logger.error(f"Gagal menyimpan file: {e}")

# Fungsi untuk Menampilkan Kode HTML dari URL
def display_html_code(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text
        save_html_to_file(html_content)
        logger.info(f"Kode HTML dari {url} disimpan dalam file index.html")
    except requests.RequestException as e:
        logger.error(f"Gagal memuat halaman: {e}")
    except Exception as e:
        logger.error(f"Terjadi kesalahan: {e}")

# Fungsi untuk memindai website
def scan_website(target_url):
    try:
        response = requests.get(target_url)
        response.raise_for_status()
        html_content = response.text

        # Logika pemindaian website
        sensitive_info = detect_sensitive_information(html_content)
        if sensitive_info:
            logger.warning("Ditemukan informasi sensitif:")
            for info in sensitive_info:
                logger.warning(info)

        if detect_illegal_scanning(html_content):
            logger.warning("Pemindaian tidak sah terdeteksi.")

        vulnerabilities = detect_vulnerabilities(html_content)
        if vulnerabilities:
            logger.warning("Ditemukan kerentanan:")
            for vulnerability_name, vulnerability_description in vulnerabilities:
                logger.warning(f"{vulnerability_name}: {vulnerability_description}")
        else:
            logger.info("Tidak ditemukan kerentanan.")
    except requests.RequestException as e:
        logger.error(f"Gagal memuat halaman: {e}")
    except Exception as e:
        logger.error(f"Terjadi kesalahan dalam pemindaian: {e}")

def read_cookies_from_file(filename):
    try:
        with open(filename, "rb") as f:  # Buka file dalam mode baca biner ('rb')
            cookies = pickle.load(f)  # Membaca cookies dari file .pkl
            return cookies
    except Exception as e:
        print(f"Terjadi kesalahan saat membaca file cookies: {e}")
        return None

# Fungsi utama
def main():
    target_url = input("Masukkan URL situs web yang ingin dipindai: ")
    display_contact_info_from_url(target_url)
    display_html_code(target_url)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    steal_cookies(target_url, headers)
    try:
        response = requests.get(target_url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"{Fore.RED}Gagal memuat halaman: {e}{Style.RESET_ALL}")
        return

    html_content = response.text

    # Mendapatkan informasi header Server
    server_header = response.headers.get('Server')
    if server_header:
        print(f"{Fore.GREEN}Informasi Server:{Style.RESET_ALL} {server_header}")
    else:
        print(f"{Fore.YELLOW}Header Server tidak ditemukan dalam respons HTTP.{Style.RESET_ALL}")

    # Memeriksa alamat IP atau nama host server
    try:
        hostname = target_url.split('//')[1].split('/')[0]  # Mengambil bagian hostname dari URL
        ip_address = socket.gethostbyname(hostname)
        print(f"{Fore.GREEN}Alamat IP dari server:{Style.RESET_ALL} {ip_address}")

        # Pemindaian port pada server
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            print(f"{Fore.GREEN}Port terbuka pada server:{Style.RESET_ALL} {', '.join(map(str, open_ports))}")
        else:
            print(f"{Fore.YELLOW}Tidak ada port terbuka yang ditemukan.{Style.RESET_ALL}")

        # Menggunakan GeoIP untuk mendapatkan informasi lokasi
        geoip_response = requests.get(f"https://freegeoip.app/json/{ip_address}")
        geoip_data = geoip_response.json()
        latitude = geoip_data['latitude']
        longitude = geoip_data['longitude']

        # Membangun tautan ke Google Maps
        google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"
        print(f"{Fore.GREEN}Lokasi server:{Style.RESET_ALL} {google_maps_link}")
    except Exception as e:
        print(f"{Fore.RED}Gagal mendapatkan informasi lokasi server: {e}{Style.RESET_ALL}")

    if check_wordpress(html_content):
        print(f"{Fore.GREEN}Situs web merupakan situs web WordPress.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Situs web bukan merupakan situs web WordPress.{Style.RESET_ALL}")

    sensitive_info = detect_sensitive_information(html_content)
    if sensitive_info:
        print(f"{Fore.YELLOW}Ditemukan informasi sensitif:{Style.RESET_ALL}")
        for info in sensitive_info:
            print(f"{Fore.YELLOW}{info}{Style.RESET_ALL}")

    if detect_illegal_scanning(html_content):
        print(f"{Fore.YELLOW}Pemindaian tidak sah terdeteksi.{Style.RESET_ALL}")

    vulnerabilities = detect_vulnerabilities(html_content)
    if vulnerabilities:
        print(f"{Fore.YELLOW}Ditemukan kerentanan:{Style.RESET_ALL}")
        for vulnerability_name, vulnerability_description in vulnerabilities:
            print(f"{Fore.RED}{vulnerability_name}:{Style.RESET_ALL} {vulnerability_description}")
    else:
        print(f"{Fore.GREEN}Tidak ditemukan kerentanan.{Style.RESET_ALL}")

    # Mencuri cookie dan menyimpannya dalam file
def steal_cookies(target_url, headers):
    try:
        # Mengirim permintaan HTTP GET dengan header yang disediakan
        response = requests.get(target_url, headers=headers)
        response.raise_for_status()  # Memeriksa apakah ada kesalahan dalam respons

        # Memeriksa apakah respons mengandung cookie
        if 'set-cookie' in response.headers:
            # Ekstraksi cookie dari respons HTTP
            cookies = response.cookies
            if cookies:
                # Menyimpan cookie dalam file 'cookies.pkl'
                with open("cookies.pkl", "wb") as f:  # Buka file untuk menulis dalam mode biner ('wb')
                    pickle.dump(cookies, f)  # Menulis cookies ke dalam file .pkl
                print("Cookie telah berhasil dicuri dan disimpan dalam file 'cookies.pkl'.")
            else:
                print("Tidak ada cookie yang ditemukan dalam respons HTTP.")
        else:
            print("Respons HTTP tidak mengandung cookie.")

    except requests.exceptions.RequestException as e:
        print(f"Gagal melakukan permintaan HTTP: {e}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

cookies = read_cookies_from_file("cookies.pkl")
if cookies:
    print("Cookies berhasil dibaca:")
    print(cookies)
else:
    print("Gagal membaca cookies dari file.")

# Fungsi untuk mengekstrak nomor telepon dari teks
def extract_phone_numbers(text):
    # Pola untuk nomor telepon dengan format yang lebih umum
    phone_pattern = r'(\+\d{1,2}\s?)?(\(\d{3,}\)|\d{3,})[\s.-]?\d{3,}[\s.-]?\d{4,}'
    phone_numbers = re.findall(phone_pattern, text)
    return [''.join(filter(str.isdigit, phone)) for phone in phone_numbers]  # Menghapus karakter non-digit

# Fungsi untuk mengekstrak alamat email dari teks
def extract_emails(text):
    # Pola untuk alamat email dengan format yang lebih umum
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return emails

# Fungsi untuk mengekstrak nomor telepon dan alamat email dari URL
def extract_contact_info_from_url(target_url):
    try:
        response = requests.get(target_url)
        response.raise_for_status()
        html_content = response.text

        # Membuat objek BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Mengekstrak teks dari seluruh halaman web
        text = soup.get_text()

        # Mengekstrak nomor telepon dan alamat email
        phone_numbers = extract_phone_numbers(text)
        emails = extract_emails(text)

        return phone_numbers, emails
    except requests.RequestException as e:
        logger.error(f"Gagal memuat halaman: {e}")
        return [], []
    except Exception as e:
        logger.error(f"Terjadi kesalahan: {e}")
        return [], []

# Fungsi untuk menampilkan nomor telepon dan alamat email dari URL
def display_contact_info_from_url(target_url):
    phone_numbers, emails = extract_contact_info_from_url(target_url)
    if phone_numbers:
        logger.info("Nomor telepon yang ditemukan:")
        for phone_number in phone_numbers:
            logger.info(phone_number)
    else:
        logger.info("Nomor telepon tidak ditemukan.")
    
    if emails:
        logger.info("Alamat email yang ditemukan:")
        for email in emails:
            logger.info(email)
    else:
        logger.info("Alamat email tidak ditemukan.")

if __name__ == "__main__":
    main()
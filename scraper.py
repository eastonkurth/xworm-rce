import requests
import subprocess
from importlib.util import find_spec as library_exists
if not library_exists('colorama'):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'colorama'])
if not library_exists('requests'):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])
if not library_exists('bs4'):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'bs4'])
from bs4 import BeautifulSoup
import threading
from time import sleep
import random
from colorama import init, Fore
import os
import re
import socket
import sys

init()
apikey = "holytspmo"
delay = 2.0
jitter = 0.5
dns_timeout = 3
session_c2s = set()
alreadyscraped = set()
http_session = requests.Session()
http_session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.5',
})
SESSION = requests.Session()
HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-GB,en;q=0.9',
    'cache-control': 'max-age=0',
    'priority': 'u=0, i',
    'sec-ch-ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
}
COOKIES = {
    '_csrf': 'tspmo-eastonkurth',
}
sample_queue = []
IP_REGEX = r"(?!127\.\d+\.\d+\.\d+)(?!10\.\d+\.\d+\.\d+)(?!192\.168\.\d+\.\d+)(?!172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)(?!169\.254\.\d+\.\d+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
PORT_FORWARD_HOSTS = r"(?:\.ddns\.org|\.duckdns\.org|\.ddns\.net|\.portmap\.io|\.portmap\.host|\.no-ip\.org|\.no-ip\.biz|\.dyndns\.org|\.ngrok\.com|\.localtunnel\.me|\.serveo\.net|\.hopto\.org|\.myqnapcloud\.com)"
HOST_REGEX = rf"^(?!.*api\.telegram\.org)([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{{2,}}(?::\d{{1,5}})?(?=.*{PORT_FORWARD_HOSTS})"
C2_REGEX = rf"({IP_REGEX}|\w+(\.\w+)+):\d{{1,5}}"
TELEGRAM_REGEX = r"https?://api\.telegram\.org/bot([0-9]+:[A-Za-z0-9_-]+)/sendMessage\?chat_id=(-?[0-9]+)"
EXCLUDED_PATTERNS = [r".*\.ip\.gl\.ply\.gg:.*", r".*\.gl\.at\.ply\.gg:.*"]
already_found_bots = set()

def checkfortelebotsandsavethem(html_content):
    if not html_content:
        return
    matches = re.findall(TELEGRAM_REGEX, html_content)
    urls = re.findall(r"(https?://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+/sendMessage\?chat_id=[-0-9]+)", html_content)
    for url in urls:
        matches_from_url = re.findall(TELEGRAM_REGEX, url)
        if matches_from_url:
            matches.extend(matches_from_url)
    for token, chat_id in matches:
        bot_info = f"{token}:{chat_id}"
        if bot_info not in already_found_bots:
            already_found_bots.add(bot_info)
            with open("bots.txt", 'a') as f:
                f.write(f"[TOKEN:CHATID] {bot_info}\n")
            print(f"{Fore.GREEN}[   INFO   ] Found + saved new Telegram bot: {bot_info}")

def validhost(host):
    try:
        if host.lower() in ('localhost', '0.0.0.0', '127.0.0.1'):
            return False
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
            parts = host.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
            return False
        socket.setdefaulttimeout(dns_timeout)
        socket.gethostbyname(host)
        return True
    except:
        return False

def scrapethreatfox():
    headers = {'API-KEY': apikey, 'Content-Type': 'application/json'}
    data = {"query": "get_iocs", "days": 7, "tag": "Xworm"}
    try:
        response = http_session.post('https://threatfox-api.abuse.ch/api/v1/', headers=headers, json=data, timeout=15)
        response.raise_for_status()
        result = response.json()
        if result.get('query_status') == 'ok':
            c2_servers = []
            for ioc in result.get('data', []):
                if 'description' in ioc:
                    checkfortelebotsandsavethem(ioc['description'])
                if ioc.get('ioc_type') == 'ip:port':
                    c2_servers.append(ioc['ioc'])
            print(f"{Fore.YELLOW}[   INFO   ] Found {len(c2_servers)} C2 servers")
            return c2_servers
        return []
    except:
        print(f"{Fore.RED}[   BAD   ] Threatfox API error")
        return []

def excludedc2(c2):
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, c2):
            return True
    return False

def loadalreadyscrapedc2s():
    global alreadyscraped
    if os.path.exists("alreadyscraped.txt"):
        with open("alreadyscraped.txt", 'r') as f:
            alreadyscraped = set(line.strip() for line in f if line.strip())
    print(f"{Fore.YELLOW}[   INFO   ] Loaded {len(alreadyscraped)} already scraped C2s")

def loadthetelegrambots():
    global already_found_bots
    if os.path.exists("bots.txt"):
        with open("bots.txt", 'r') as f:
            for line in f:
                if "[TOKEN:CHATID]" in line:
                    parts = line.strip().split(" ", 1)
                    if len(parts) > 1:
                        already_found_bots.add(parts[1].strip())
    print(f"{Fore.YELLOW}[   INFO   ] Loaded {len(already_found_bots)} existing Telegram bots")

def savec2s(c2_servers):
    if not c2_servers:
        return 0
    existing = set()
    if os.path.exists("reports.txt"):
        with open("reports.txt", 'r') as f:
            existing = set(line.strip() for line in f if line.strip())
    new_c2s = []
    for c2 in c2_servers:
        if c2 in session_c2s or c2 in existing or c2 in alreadyscraped or excludedc2(c2):
            continue
        if validc2(c2):
            new_c2s.append(c2)
            session_c2s.add(c2)
            alreadyscraped.add(c2)
    if new_c2s:
        with open("reports.txt", 'a') as f:
            for c2 in new_c2s:
                f.write(f"{c2}\n")
        with open("alreadyscraped.txt", 'a') as f:
            for c2 in new_c2s:
                f.write(f"{c2}\n")
        report_count = sum(1 for _ in open("reports.txt")) if os.path.exists("reports.txt") else 0
        print(f"{Fore.YELLOW}[   INFO   ] Added {len(new_c2s)} new C2 servers.")
        print(f"{Fore.YELLOW}[   INFO   ] Found {report_count} reports total.")
    return len(new_c2s)

def validc2(c2):
    if "api.telegram.org/bot" in c2:
        matches = re.findall(TELEGRAM_REGEX, c2)
        for token, chat_id in matches:
            bot_info = f"{token}:{chat_id}"
            if bot_info not in already_found_bots:
                already_found_bots.add(bot_info)
                with open("bots.txt", 'a') as f:
                    f.write(f"[TOKEN:CHATID] {bot_info}\n")
                print(f"{Fore.GREEN}[   INFO   ] Found + saved new Telegram bot: {bot_info}")
        return False
    if not c2 or ":" not in c2:
        return False
    host, port = c2.split(":", 1)
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False
    except ValueError:
        return False
    if not host or len(host) < 3:
        return False
    if re.match(r"^(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|169\.254\.\d+\.\d+)$", host):
        return False
    if excludedc2(c2):
        return False
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, host):
        parts = host.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
        return False
    if '.' in host and not host.startswith('.') and not host.endswith('.'):
        if any(pattern in host.lower() for pattern in [
            '.ddns.org', '.duckdns.org', '.ddns.net', '.portmap.io', '.portmap.host',
            '.no-ip.org', '.no-ip.biz', '.dyndns.org', '.ngrok.com', 
            '.localtunnel.me', '.serveo.net', '.hopto.org', '.myqnapcloud.com'
        ]):
            return True
        return True
    return False

def extractconfig(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    config = {}
    for div in soup.select(".key-value > div"):
        key = div.select_one(".config-entry-heading").text.strip()
        value = None
        for selector in [".clipboard > p", ".value-text"]:
            value_element = div.select_one(selector)
            if value_element:
                value = value_element.text.strip()
                break
        if value is None:
            code_block = div.select_one(".code-block")
            if code_block and code_block.get("data-code-content"):
                value = code_block["data-code-content"]
        config[key] = value
    return config

def getc2fromapastebinurl(url):
    if ":" in url and url.startswith("https://pastebin.com/raw/"):
        url = url.split(":")[0]
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text.strip()
        return None
    except:
        return None

def processtssample(sample_id):
    try:
        response = SESSION.get(f"https://tria.ge/{sample_id.split('|')[1]}", cookies=COOKIES, headers=HEADERS, timeout=10)
        checkfortelebotsandsavethem(response.text)
        config = extractconfig(response.text)
        c2_value = config.get("C2")
        if not c2_value:
            return
        if "pastebin.com" in c2_value:
            pastebin_url = c2_value if c2_value.startswith("https://pastebin.com/raw/") else f"https://pastebin.com/raw/{c2_value.split('/')[-1]}"
            c2_value = getc2fromapastebinurl(pastebin_url)
            if not c2_value:
                return
            checkfortelebotsandsavethem(c2_value)
        if c2_value in session_c2s or c2_value in alreadyscraped or excludedc2(c2_value):
            return
        if validc2(c2_value):
            session_c2s.add(c2_value)
            alreadyscraped.add(c2_value)
            with open("reports.txt", "a") as f:
                f.write(c2_value + "\n")
            with open("alreadyscraped.txt", "a") as f:
                f.write(c2_value + "\n")
            report_count = sum(1 for _ in open("reports.txt")) if os.path.exists("reports.txt") else 0
            print(f"{Fore.YELLOW}[   INFO   ] Found C2: {c2_value}")
            print(f"{Fore.YELLOW}[   INFO   ] Found {report_count} reports.")
    except:
        pass

def worker():
    while True:
        if sample_queue:
            processtssample(sample_queue.pop(0))
        sleep(delay + random.uniform(0, jitter))

def scrapetriage():
    offset_params = {}
    while True:
        if len(sample_queue) > 20:
            sleep(10)
            continue
        response = SESSION.get("https://tria.ge/s", params={"q": "family:xworm", "limit": 20, **offset_params}, cookies=COOKIES, headers=HEADERS, timeout=15)
        sample_ids = []
        html = response.text
        for pos in [i for i in range(len(html)) if html.startswith('data-sample-id', i)]:
            snippet = html[pos:pos+300]
            try:
                timestamp = snippet.split('h-datetime="')[1].split('"')[0]
                sample_id = snippet.split('data-sample-id="')[1].split('"')[0]
                sample_ids.append(f"{timestamp}|{sample_id}")
            except:
                continue
        sample_queue.extend(sample_ids)
        print(f"{Fore.YELLOW}[   INFO   ] C2s updated: {len(sample_ids)} new samples...")
        if not sample_ids:
            sleep(60)
            offset_params = {}
        else:
            offset_params = {"offset": sample_ids[-1].split('|')[0]}

def checknet():
    try:
        socket.gethostbyname("1.1.1.1")
        return True
    except:
        return False

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.YELLOW + r"""

____  _____      __                      __________              
\   \/  /  \    /  \___________  _____   \______   \ ____  ____  
 \     /\   \/\/   /  _ \_  __ \/     \   |       _// ___\/ __ \ 
 /     \ \        (  <_> )  | \/  Y Y  \  |    |   \  \__\  ___/ 
/___/\  \ \__/\  / \____/|__|  |__|_|  /  |____|_  /\___  >___  >
      \_/      \/                    \/          \/     \/    \/ 
    made by github.com/eastonkurth
    """)
    with open('reports.txt', 'a') as lol:
        pass
    with open('bots.txt', 'a') as bots_file:
        pass
    loadalreadyscrapedc2s()
    loadthetelegrambots()
    if not checknet():
        print(f"{Fore.RED}[   ERROR  ] Your not connected to the internet!")
        sys.exit(1)
    c2_servers = scrapethreatfox()
    savec2s(c2_servers)
    threading.Thread(target=scrapetriage, daemon=True).start()
    for _ in range(20):
        threading.Thread(target=worker, daemon=True).start()
    try:
        while True:
            sleep(60)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[   INFO   ] Scraper stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()

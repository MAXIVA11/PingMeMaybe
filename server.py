import socket
import struct
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# --- Logging helpers ---
def log_info(msg):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    console.print(f"{timestamp} [bold cyan][INFO][/bold cyan] {msg}")

def log_success(msg):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    console.print(f"{timestamp} [bold green][+][/bold green] {msg}")

def log_warning(msg):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    console.print(f"{timestamp} [bold yellow][!][/bold yellow] {msg}")

def log_error(msg):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    console.print(f"{timestamp} [bold red][-][/bold red] {msg}")

def log_exit(msg):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    console.print(f"{timestamp} [bold red][x][/bold red] {msg}")

def print_banner():
    banner = Text("PingMeMaybe", style="bold magenta")
    panel = Panel(banner, style="magenta", expand=False, border_style="bright_magenta")
    console.print(panel)

# --- AES-CBC+HMAC Decryption ---
def decrypt_cbc_hmac(key, iv, ciphertext, tag):
    aes_key = key[:16]
    hmac_key = key[16:]
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    h.verify(tag)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_len = plaintext[-1]
    return plaintext[:-padding_len]

# --- Packet Receiver ---
def recv_all(sock, key):
    aesgcm = AESGCM(key)
    buffer = {}
    total_chunks = None
    current_filename = None

    log_info("Waiting for ICMP echo requests...")

    try:
        while True:
            packet, addr = sock.recvfrom(65535)
            ip_header = packet[:20]
            icmp_header = packet[20:28]
            icmp_type, code, chksum, p_id, seq = struct.unpack('!BBHHH', icmp_header)
            if icmp_type != 8:
                continue

            raw_payload = packet[28:]
            if len(raw_payload) < 12:
                continue

            # Try AES-GCM first
            try:
                nonce = raw_payload[:12]
                ct = raw_payload[12:-16]
                tag = raw_payload[-16:]
                data = aesgcm.decrypt(nonce, ct + tag, None)
            except Exception:
                if len(raw_payload) < 48:
                    continue
                iv = raw_payload[:16]
                tag = raw_payload[-32:]
                ct = raw_payload[16:-32]
                try:
                    data = decrypt_cbc_hmac(key, iv, ct, tag)
                except Exception:
                    continue

            if seq == 0xFFFF:
                filename_bytes = data[8:]
                try:
                    filename_str = filename_bytes.decode('utf-8')
                except:
                    filename_str = "file.bin"

                if buffer and total_chunks and current_filename:
                    with open(current_filename, 'wb') as f:
                        for i in range(total_chunks):
                            f.write(buffer[i])
                    log_success(f"Saved: {current_filename}")
                    buffer.clear()
                    total_chunks = None

                current_filename = filename_str
                log_info(f"Receiving: {current_filename}")
                buffer.clear()
                total_chunks = None
                continue

            idx, total = struct.unpack('!II', data[:8])
            chunk = data[8:]

            buffer[idx] = chunk
            total_chunks = total

            if len(buffer) == total_chunks and current_filename:
                with open(current_filename, 'wb') as f:
                    for i in range(total_chunks):
                        f.write(buffer[i])
                log_success(f"Saved: {current_filename}")
                buffer.clear()
                total_chunks = None

    except KeyboardInterrupt:
        log_exit("Received Ctrl+C. Exiting gracefully.")
        try:
            sock.close()
        except:
            pass
        exit(0)

# --- Main ---
if __name__ == '__main__':
    print_banner()
    key = os.urandom(32)
    hexkey = key.hex()
    console.print(f"[bold blue]AES-GCM Key:[/bold blue] [yellow]{hexkey}[/yellow]")

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_all(s, key)

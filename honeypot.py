import socket
import threading
import time
from datetime import datetime
from urllib.parse import unquote
import json

# Configuration
HONEYPOT_IP = "0.0.0.0"
PORTS = {
    "HTTP": 8080,
    "SSH": 2222,
    "FTP": 2121,
    "TELNET": 2323
}

LOG_FILE = "logs/attack_logs.json"

def log_attack(client_ip, service, data):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "ip": client_ip,
        "data": data
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    
    print(f"[!] {service} attack from {client_ip}")

# HTTP Service
def handle_http(client_socket):
    client_ip = client_socket.getpeername()[0]
    
    try:
        request = client_socket.recv(4096).decode()
        
        if "POST /login" in request:
            body = request.split('\r\n\r\n')[1]
            creds = dict(pair.split('=') for pair in body.split('&'))
            log_attack(client_ip, "HTTP", {
                "type": "Login Attempt",
                "email": unquote(creds.get('email', '')),
                "password": unquote(creds.get('password', ''))
            })
            
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            response += b"<h3>Login Failed!</h3>"
            client_socket.send(response)
        else:
            with open("login.html", "rb") as f:
                client_socket.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + f.read())
                
    except Exception as e:
        log_attack(client_ip, "HTTP", {"error": str(e)})
    finally:
        client_socket.close()

# SSH Service (simplified)
def handle_ssh(client_socket):
    client_ip = client_socket.getpeername()[0]
    try:
        client_socket.send(b"SSH-2.0-OpenSSH_8.2p1\r\n")
        data = client_socket.recv(1024)
        log_attack(client_ip, "SSH", {
            "activity": data.decode(errors='ignore')[:100]  # Log first 100 chars
        })
        client_socket.send(b"Permission denied\n")
    finally:
        client_socket.close()

# FTP Service
def handle_ftp(client_socket):
    client_ip = client_socket.getpeername()[0]
    try:
        client_socket.send(b"220 FTP Server Ready\r\n")
        user = client_socket.recv(1024)
        client_socket.send(b"331 Password required\r\n")
        password = client_socket.recv(1024)
        
        log_attack(client_ip, "FTP", {
            "username": user.decode().strip(),
            "password": password.decode().strip()
        })
        
        client_socket.send(b"230 Login successful\n")
    finally:
        client_socket.close()

# Telnet Service
def handle_telnet(client_socket):
    client_ip = client_socket.getpeername()[0]
    try:
        client_socket.send(b"Username: ")
        username = client_socket.recv(1024)
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024)
        
        log_attack(client_ip, "TELNET", {
            "username": username.decode().strip(),
            "password": password.decode().strip()
        })
        
        client_socket.send(b"Login failed\n")
    finally:
        client_socket.close()

def start_service(port, name, handler):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HONEYPOT_IP, port))
    server.listen(5)
    print(f"[*] {name} service on port {port}")
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handler, args=(client,)).start()

if __name__ == "__main__":
    print("=== Honeypot Starter Pack ===")
    print("Services running on ports:")
    for service, port in PORTS.items():
        print(f"{service}: {port}")
    
    services = [
        (PORTS["HTTP"], "HTTP", handle_http),
        (PORTS["SSH"], "SSH", handle_ssh),
        (PORTS["FTP"], "FTP", handle_ftp),
        (PORTS["TELNET"], "TELNET", handle_telnet)
    ]
    
    for port, name, handler in services:
        threading.Thread(target=start_service, args=(port, name, handler)).start()
    
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down")
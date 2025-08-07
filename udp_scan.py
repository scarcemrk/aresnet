import socket
import concurrent.futures
from utils import get_service_name, detect_vulnerabilities

def scan_udp_port(target, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (target, port))
        data, _ = sock.recvfrom(1024)

        # If we receive data, the port is open or responding
        service = get_service_name(port)
        fake_banner = f"{service.lower()}/udp"
        vuln = detect_vulnerabilities(fake_banner)

        output = f"[open] {target}:{port}/udp  --> {service}"
        if vuln:
            output += f"\n   ⚠️  Vulnerability: {vuln}"
        print(output)

    except socket.timeout:
        pass  # Port is likely closed or not responding
    except Exception:
        pass
    finally:
        sock.close()

def scan_udp(target, ports):
    print(f"[*] Scanning {target} on UDP ports: {ports}\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for port in ports:
            executor.submit(scan_udp_port, target, port)
import socket
import os
import importlib.util
import time

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS", 139: "SMB",
    143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    500: "ISAKMP", 993: "IMAPS", 995: "POP3S", 1900: "SSDP",
    3306: "MySQL", 3389: "RDP"
}

def get_service_name(port):
    return COMMON_PORTS.get(port, "Unknown")

def grab_tcp_banner(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b'Hello\r\n')
            return s.recv(1024).decode(errors='ignore').strip()
    except Exception:
        return None

def grab_udp_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)

        if port == 53:
            dns_query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
            s.sendto(dns_query, (ip, port))
        elif port == 123:
            ntp_data = b'\x1b' + 47 * b'\0'
            s.sendto(ntp_data, (ip, port))
        elif port == 161:
            snmp_request = bytes.fromhex("30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 04 70 75 62 6c 02 01 00 02 01 00 30 0b 30 09 06 05 2b 06 01 02 01 05 00")
            s.sendto(snmp_request, (ip, port))
        else:
            s.sendto(b"Hello", (ip, port))

        data, _ = s.recvfrom(1024)
        return data.decode(errors='ignore').strip()
    except Exception:
        return None
    finally:
        s.close()

def detect_vulnerabilities(banner):
    banner = banner.lower()
    vuln_keywords = {
        "vsftpd 2.3.4": "vsFTPd 2.3.4 - Backdoor",
        "apache/2.2.8": "Apache 2.2.8 - Directory Traversal",
        "apache/2.2": "Apache 2.2 - outdated, CVE-2011-3192",
        "php/5.3": "PHP 5.3 - Multiple RCE CVEs",
        "mysql 5.5": "MySQL 5.5 - CVE-2012-2122 (Auth bypass)",
        "openssh_4.7": "OpenSSH 4.7 - Remote Code Execution",
        "openssh_7.2": "OpenSSH 7.2 - CVE-2016-0777 (Private key leakage)",
        "openssh_7.4": "OpenSSH 7.4 - CVE-2016-10010 (Privilege escalation)",
        "apache/2.4.6": "Apache 2.4.6 - CVE-2017-9788 (mod_http2 DoS)",
        "php/5.4.16": "PHP 5.4.16 - Multiple vulnerabilities (outdated version)",
        "exim 4.87": "Exim 4.87 - CVE-2019-15846 (Command Injection)",
        "microsoft-iis/6.0": "IIS 6.0 - WebDAV Exploit (CVE-2017-7269)",
        "proftpd 1.3.5": "ProFTPD 1.3.5 - File disclosure vulnerability",
        "dns": "DNS over UDP - vulnerable to amplification (open resolver)",
        "ntp": "NTP - vulnerable to reflection (CVE-2013-5211, monlist)",
        "snmp": "SNMP - may leak info via public community string"
    }
    for keyword, vuln in vuln_keywords.items():
        if keyword in banner:
            return vuln
    return None

def detect_os_by_ttl(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(2)
        s.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x00", (ip, 1))
        data, addr = s.recvfrom(1024)
        ttl = data[8]
        if ttl >= 128:
            return f"Possible OS: Windows (TTL={ttl})"
        elif ttl >= 64:
            return f"Possible OS: Linux/Unix (TTL={ttl})"
        else:
            return f"Unknown OS (TTL={ttl})"
    except Exception as e:
        return f"OS detection failed: {e}"
    finally:
        s.close()

def run_scripts(ip, port, banner, script_dir):
    results = []
    if not script_dir or not os.path.isdir(script_dir):
        return results

    for filename in os.listdir(script_dir):
        if filename.endswith(".py"):
            script_path = os.path.join(script_dir, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], script_path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                if hasattr(module, "run"):
                    result = module.run(ip, port, banner)
                    if result:
                        results.append((filename, result))
            except Exception as e:
                results.append((filename, f"Script error: {e}"))
    return results
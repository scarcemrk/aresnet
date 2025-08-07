import subprocess
import platform

def discover_hosts():
    os_name = platform.system()
    try:
        if os_name == "Windows":
            output = subprocess.check_output("arp -a", shell=True).decode()
        else:
            output = subprocess.check_output(["arp", "-a"]).decode()
        print(output)
    except Exception as e:
        print(f"[!] Failed to run network discovery: {e}")
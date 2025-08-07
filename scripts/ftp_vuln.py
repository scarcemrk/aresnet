import ftplib

def run(ip, port, service=None, banner=None):
    result = {
        "vulnerable": False,
        "details": ""
    }

    try:
        # Attempt anonymous login
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=5)
        ftp.login()
        result["vulnerable"] = True
        result["details"] = "FTP allows anonymous login"
        ftp.quit()
        return result
    except ftplib.error_perm as e:
        if "530" in str(e):
            pass  # Anonymous login denied

    # Try default credentials
    default_creds = [("admin", "admin"), ("ftp", "ftp"), ("user", "pass")]
    for user, pwd in default_creds:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login(user, pwd)
            result["vulnerable"] = True
            result["details"] = f"FTP login succeeded with default creds: {user}/{pwd}"
            ftp.quit()
            return result
        except Exception:
            continue

    return result
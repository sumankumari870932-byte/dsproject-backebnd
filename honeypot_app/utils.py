def detect_attack(payload):
    payload = payload.lower()

    if "or 1=1" in payload or "' or '" in payload or "--" in payload:
        return "SQL Injection"

    elif "<script>" in payload or "alert(" in payload:
        return "XSS"

    elif ";" in payload or "&&" in payload or "ls" in payload:
        return "Command Injection"

    elif "../" in payload or "/etc/passwd" in payload:
        return "Directory Traversal"

    elif payload.count("admin") > 1 or payload.count("123") > 1:
        return "Brute Force"

    return "Normal"


def get_country_from_ip(ip):
    if ip.startswith("192.168"):
        return "India"
    elif ip.startswith("172.16"):
        return "USA"
    elif ip.startswith("10."):
        return "Germany"
    return "Unknown"
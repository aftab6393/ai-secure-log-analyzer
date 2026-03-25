import re

def detect_attacks(content):
    threats = []

    # 🔴 SQL Injection
    if re.search(r"(SELECT|UNION|DROP|INSERT|DELETE).*--", content, re.IGNORECASE):
        threats.append({
            "type": "SQL Injection",
            "severity": "critical"
        })

    # 🔴 XSS Attack
    if re.search(r"<script>|javascript:|onerror=", content, re.IGNORECASE):
        threats.append({
            "type": "XSS Attack",
            "severity": "high"
        })

    # 🔴 Brute Force
    failed_logins = len(re.findall(r"failed login", content, re.IGNORECASE))
    if failed_logins > 3:
        threats.append({
            "type": "Brute Force Attack",
            "severity": "critical"
        })

    # 🔴 Command Injection
    if re.search(r"(;|\|\||&&)\s*(ls|cat|whoami|pwd)", content):
        threats.append({
            "type": "Command Injection",
            "severity": "critical"
        })

    # 🔴 Suspicious API abuse
    if re.search(r"(api_key|token).*(GET|POST)", content, re.IGNORECASE):
        threats.append({
            "type": "API Abuse",
            "severity": "medium"
        })

    return threats
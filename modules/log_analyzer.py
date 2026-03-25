import re

def analyze_log(content):
    findings = []

    # Email
    emails = re.findall(r'[\w\.-]+@[\w\.-]+', content)
    for email in emails:
        findings.append({
            "type": "email",
            "value": email,
            "risk": "low"
        })

    # Password
    passwords = re.findall(r'password=([^\s]+)', content, re.IGNORECASE)
    for pwd in passwords:
        findings.append({
            "type": "password",
            "value": pwd,
            "risk": "critical"
        })

    # API Key
    api_keys = re.findall(r'api_key=([^\s]+)', content, re.IGNORECASE)
    for key in api_keys:
        findings.append({
            "type": "api_key",
            "value": key,
            "risk": "high"
        })

    return findings
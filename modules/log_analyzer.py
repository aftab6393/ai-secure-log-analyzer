import re

def analyze_log(content):
    findings = []
    seen = set()

    def add_finding(type_, value, risk):
        key = (type_, value)
        if key not in seen and value:
            findings.append({
                "type": type_,
                "value": value.strip(),
                "risk": risk
            })
            seen.add(key)

    # 📧 Email detection
    emails = re.findall(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', content)
    for email in emails:
        add_finding("email", email, "low")

    # 🔐 Password detection (more flexible)
    passwords = re.findall(r'(password|pwd|pass)\s*[:=]\s*([^\s]+)', content, re.IGNORECASE)
    for _, pwd in passwords:
        if len(pwd) >= 4:
            add_finding("password", pwd, "critical")

    # 🔑 API Keys / Tokens / Secrets
    api_keys = re.findall(r'(api[_-]?key|token|secret|auth)\s*[:=]\s*([^\s]+)', content, re.IGNORECASE)
    for _, key in api_keys:
        if len(key) > 8:
            add_finding("api_key", key, "high")

    # 🌐 IP Address detection (validated range)
    ips = re.findall(
        r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        content
    )
    for ip in ips:
        add_finding("ip_address", ip, "medium")

    # 🌍 URL detection
    urls = re.findall(r'https?://[^\s]+', content)
    for url in urls:
        add_finding("url", url, "low")

    # 📂 File paths (Windows + Linux)
    paths = re.findall(r'([A-Za-z]:\\[^\s]+|\/[^\s]+)', content)
    for path in paths:
        add_finding("file_path", path, "low")

    # 🚨 Failed login attempts (count-based severity)
    failed_attempts = len(re.findall(
        r'failed login|authentication failed|unauthorized',
        content,
        re.IGNORECASE
    ))

    if failed_attempts >= 5:
        add_finding("auth_issue", f"{failed_attempts} failed attempts", "critical")
    elif failed_attempts >= 2:
        add_finding("auth_issue", f"{failed_attempts} suspicious attempts", "high")

    # 💳 Credit Card detection (basic validation)
    cards = re.findall(r'\b(?:\d[ -]*?){13,16}\b', content)
    for card in cards:
        digits = re.sub(r'\D', '', card)
        if 13 <= len(digits) <= 16:
            add_finding("credit_card", card, "critical")

    # 🔐 JWT Tokens
    jwt_tokens = re.findall(
        r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        content
    )
    for token in jwt_tokens:
        add_finding("jwt_token", token, "critical")

    # 💻 Suspicious system commands
    commands = re.findall(
        r'\b(ls|cat|rm|wget|curl|chmod|whoami|sudo)\b',
        content
    )
    for cmd in commands:
        add_finding("suspicious_command", cmd, "medium")

    # ⚠️ System errors
    if re.search(r'error|exception|stack trace|fatal', content, re.IGNORECASE):
        add_finding("system_error", "System error detected", "medium")

    return findings
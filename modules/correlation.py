from collections import Counter
import re

def correlate_logs(content):
    results = []

    # IP correlation
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    ip_counts = Counter(ips)

    for ip, count in ip_counts.items():
        if count > 3:
            results.append({
                "type": "Suspicious IP Activity",
                "value": ip,
                "count": count,
                "severity": "high"
            })

    # Failed login correlation
    failed = len(re.findall(r'failed login', content, re.IGNORECASE))
    if failed > 3:
        results.append({
            "type": "Brute Force Pattern",
            "value": f"{failed} failed attempts",
            "severity": "critical"
        })

    return results
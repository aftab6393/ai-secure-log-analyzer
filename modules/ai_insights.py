def generate_insights(findings, content):
    insights = []

    if any(f["type"] == "password" for f in findings):
        insights.append("Sensitive credentials exposed")

    if "stack trace" in content.lower():
        insights.append("Stack trace reveals internal system details")

    if "failed login" in content.lower():
        insights.append("Multiple failed login attempts detected")

    if "select" in content.lower():
        insights.append("Possible SQL injection attempt")

    if "<script>" in content.lower():
        insights.append("Possible XSS attack detected")

    return insights
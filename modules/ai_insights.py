

def generate_insights(findings, content):
    insights = []

    types = [f["type"] for f in findings]

    # Sensitive credentials
    if "password" in types or "api_key" in types:
        insights.append("Sensitive credentials exposed")

    # Stack trace detection (IMPORTANT FIX)
    if "error" in content.lower() or "exception" in content.lower():
        insights.append("Stack trace reveals internal system details")

    return insights
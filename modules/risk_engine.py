def calculate_risk(findings):
    score = 0

    for f in findings:
        if f["risk"] == "critical":
            score += 5
        elif f["risk"] == "high":
            score += 4
        elif f["risk"] == "medium":
            score += 2
        else:
            score += 3   # email = 3 (important change)

    if score >= 10:
        level = "high"
    elif score >= 5:
        level = "medium"
    else:
        level = "low"

    return {"score": score, "level": level}
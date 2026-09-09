import re


def calculate_phishing_score(email_body):
    score = 0
    reasons = []

    text = email_body.lower()

    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "verify your account",
        "account suspended",
        "click here",
        "confirm your identity"
    ]

    for word in urgent_words:
        if word in text:
            score += 10
            reasons.append(f"Contains suspicious phrase: {word}")

    if re.search(r"https?://", text):
        score += 15
        reasons.append("Contains a URL")

    if re.search(r"\b(password|otp|pin|credit card|bank account)\b", text):
        score += 20
        reasons.append("Requests sensitive information")

    if re.search(r"\b(login|verify|security alert|payment required)\b", text):
        score += 15
        reasons.append("Contains phishing-related language")

    score = min(score, 100)

    if score >= 70:
        verdict = "phishing"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
from fastapi import FastAPI
from pydantic import BaseModel

from extraction.entity_extractor import extract_entities
from phishing.phishing_model import calculate_phishing_score
from url.url_classifier import classify_urls
from llm.explainer import generate_explanation


app = FastAPI()


class EmailRequest(BaseModel):
    emailBody: str
    headers: str


@app.post("/api/ai/phishing-score")
def phishing_score(request: EmailRequest):
    entities = extract_entities(
        request.emailBody,
        request.headers
    )

    phishing_result = calculate_phishing_score(
        request.emailBody
    )

    url_result = classify_urls(
        entities["urls"]
    )

    final_score = min(
        phishing_result["score"] + url_result["scoreBump"],
        100
    )

    if final_score >= 70:
        verdict = "phishing"
    elif final_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    explanation = generate_explanation(
        request.emailBody,
        final_score,
        entities
    )

    return {
        "phishingScore": final_score,
        "verdict": verdict,
        "explanation": explanation,
        "entities": entities
    }
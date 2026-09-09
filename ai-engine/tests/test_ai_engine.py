"""
Unit and API contract tests for TraceMail AI — AI Engine.
Tests adherence to Section 6 & 9.3 of Master Engineering Plan.
"""

from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Add ai-engine to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import app
from extraction.entity_extractor import extract_entities
from phishing.phishing_model import calculate_phishing_score
from url.url_classifier import classify_urls

client = TestClient(app)

SAMPLE_PHISH_BODY = "URGENT: Your account has been suspended. Click here to verify your account immediately: http://paypa1-secure.com/login. Please enter your password."
SAMPLE_HEADERS = "From: PayPal Support <support@paypal.com>\nTo: victim@company.com\nSubject: Account Alert"


def test_entity_extractor():
    entities = extract_entities(SAMPLE_PHISH_BODY, SAMPLE_HEADERS)
    assert "http://paypa1-secure.com/login" in entities["urls"]
    assert "paypa1-secure.com" in entities["domains"]
    assert "PayPal Support <support@paypal.com>" in entities["senderClaim"]


def test_phishing_model():
    res = calculate_phishing_score(SAMPLE_PHISH_BODY)
    assert res["score"] >= 70
    assert res["verdict"] == "phishing"
    assert len(res["reasons"]) > 0


def test_url_classifier():
    res = classify_urls(["http://paypa1-secure.com/login", "http://185.220.101.4/phish"])
    assert res["scoreBump"] > 0
    assert len(res["suspiciousUrls"]) >= 1


def test_phishing_score_endpoint_contract():
    payload = {
        "emailBody": SAMPLE_PHISH_BODY,
        "headers": SAMPLE_HEADERS
    }
    response = client.post("/api/ai/phishing-score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "phishingScore" in data
    assert isinstance(data["phishingScore"], int)
    assert 0 <= data["phishingScore"] <= 100
    assert data["verdict"] in ["phishing", "suspicious", "safe"]
    assert "explanation" in data
    assert "entities" in data
    assert "urls" in data["entities"]
    assert "ips" in data["entities"]
    assert "domains" in data["entities"]
    assert "senderClaim" in data["entities"]
    assert "senderActual" in data["entities"]

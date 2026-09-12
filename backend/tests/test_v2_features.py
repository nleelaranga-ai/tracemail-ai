"""
Unit tests for Master Plan v2 features:
Gmail OAuth, Inbox Scanner, SOC Command Center, Evidence Locker, AI Explainability, Node Topology, and Attachment Scanner.
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_gmail_oauth_login_url():
    res = client.get("/api/auth/google/login")
    assert res.status_code == 200
    data = res.json()
    assert "authUrl" in data
    assert "accounts.google.com" in data["authUrl"]
    assert "gmail.readonly" in data["authUrl"]


def test_gmail_oauth_callback():
    res = client.get("/api/auth/google/callback?email=analyst@tracemail.ai")
    assert res.status_code == 200
    data = res.json()
    assert data["connected"] is True
    assert data["email"] == "analyst@tracemail.ai"


def test_inbox_scan_and_results():
    scan_res = client.post("/api/inbox/scan?email=analyst@tracemail.ai")
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "complete"
    assert scan_data["emailsScanned"] >= 1

    results_res = client.get("/api/inbox/results?email=analyst@tracemail.ai")
    assert results_res.status_code == 200
    results = results_res.json()
    assert isinstance(results, list)
    assert len(results) >= 1
    first_item = results[0]
    assert "threatScore" in first_item
    assert "risk" in first_item
    assert "verdict" in first_item
    assert "investigationId" in first_item


def test_soc_overview_endpoint():
    res = client.get("/api/soc/overview")
    assert res.status_code == 200
    data = res.json()
    assert "totalScanned" in data
    assert "phishingDetected" in data
    assert "criticalThreats" in data
    assert "riskDistribution" in data
    assert "topBrands" in data
    assert isinstance(data["topBrands"], list)
    assert "topCountries" in data
    assert isinstance(data["topCountries"], list)


def test_org_heatmap_endpoint():
    res = client.get("/api/org/heatmap")
    assert res.status_code == 200
    departments = res.json()
    assert isinstance(departments, list)
    assert len(departments) >= 3
    dept = departments[0]
    assert "department" in dept
    assert "threatCount" in dept
    assert "vulnerabilityScore" in dept
    assert "riskLevel" in dept


def test_evidence_locker_and_tamper_detection():
    # Fetch existing demo case
    case_id = "inv_paypal_phish_demo_01"
    
    # 1. Get evidence record
    get_res = client.get(f"/api/evidence/{case_id}")
    assert get_res.status_code == 200
    ev_data = get_res.json()
    assert ev_data["investigationId"] == case_id
    assert "sha256" in ev_data
    assert len(ev_data["sha256"]) == 64
    assert len(ev_data["custodyLog"]) >= 2

    # 2. Verify legitimate evidence (Assert Verified)
    verify_res = client.post(f"/api/evidence/{case_id}/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["status"] == "Verified"
    assert verify_data["verified"] is True

    # 3. Simulate tamper detection (Assert Tampered)
    tamper_res = client.post(f"/api/evidence/{case_id}/verify?simulated_corrupt=true")
    assert tamper_res.status_code == 200
    tamper_data = tamper_res.json()
    assert tamper_data["status"] == "Tampered"
    assert tamper_data["verified"] is False
    assert "mismatch" in tamper_data["message"].lower() or "altered" in tamper_data["message"].lower()

    # 4. Verify non-mutating simulation guarantee: database record is STILL Verified!
    reverify_res = client.post(f"/api/evidence/{case_id}/verify")
    assert reverify_res.status_code == 200
    assert reverify_res.json()["status"] == "Verified"
    assert reverify_res.json()["verified"] is True

    # 5. Nonexistent investigation must return 404
    missing_res = client.get("/api/evidence/non_existent_case_9999")
    assert missing_res.status_code == 404


def test_ai_explainability_weights():
    case_id = "inv_paypal_phish_demo_01"
    res = client.get(f"/api/ai/explainability/{case_id}")
    assert res.status_code == 200
    data = res.json()
    assert "score" in data
    assert "reasons" in data
    assert isinstance(data["reasons"], list)
    assert len(data["reasons"]) >= 3
    
    # Verify each reason has category, weight, and label
    for r in data["reasons"]:
        assert "label" in r
        assert "weight" in r
        assert "category" in r

    # Nonexistent investigation must return 404
    missing_res = client.get("/api/ai/explainability/non_existent_case_9999")
    assert missing_res.status_code == 404


def test_graph_node_detail_endpoint():
    node_res = client.get("/api/graph/node/185.220.101.4")
    assert node_res.status_code == 200
    node = node_res.json()
    assert node["nodeId"] == "185.220.101.4"
    assert "whois" in node
    assert "reputation" in node
    assert "abuseScore" in node
    assert "timeline" in node
    assert isinstance(node["timeline"], list)


def test_attachment_malware_scanner():
    # 1. Clean document
    clean_res = client.post("/api/threat/attachment", json={
        "filename": "internship_offer.pdf",
        "sha256": "a" * 64
    })
    assert clean_res.status_code == 200
    clean_data = clean_res.json()
    assert clean_data["malicious"] is False
    assert clean_data["positives"] == 0
    assert "Clean" in clean_data["verdict"]

    # 2. Hostile double-extension executable
    mal_res = client.post("/api/threat/attachment", json={
        "filename": "urgent_invoice.pdf.exe",
        "sha256": "b" * 64
    })
    assert mal_res.status_code == 200
    mal_data = mal_res.json()
    assert mal_data["malicious"] is True
    assert mal_data["heuristic_risk"] is True
    assert "Trojan" in mal_data["verdict"] or "Executable" in mal_data["verdict"]

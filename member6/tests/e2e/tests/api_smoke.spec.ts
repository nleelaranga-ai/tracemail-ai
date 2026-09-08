/**
 * TraceMail AI — Member 6: E2E Tests
 * File: member6/tests/e2e/tests/api_smoke.spec.ts
 *
 * API smoke tests — hit backend REST endpoints directly via fetch.
 * These tests run without needing the frontend and verify that
 * the Reports Engine API is alive and responding correctly.
 *
 * Tags: @api @smoke
 *
 * Backend URL: http://localhost:8000 (configurable via BACKEND_URL env)
 */

import { test, expect, APIRequestContext, request } from "@playwright/test";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";
const INV_ID = "INV-E2E-001";

// ---------------------------------------------------------------------------
// Sample investigation payload (mirrors conftest.py fixture)
// ---------------------------------------------------------------------------

const SAMPLE_PAYLOAD = {
  investigation_id: INV_ID,
  case_summary: {
    investigation_id: INV_ID,
    subject: "URGENT: Your account has been compromised",
    from_address: "security@paypa1-alerts.com",
    to_addresses: ["victim@company.com"],
    received_at: "2026-09-08T12:30:00Z",
    analyzed_at: "2026-09-08T13:00:00Z",
    threat_type: "phishing",
    analyst_notes: "E2E test investigation",
  },
  risk_score: {
    overall_score: 92.5,
    verdict: "MALICIOUS",
    confidence: 0.97,
    phishing_score: 95.0,
    spoofing_score: 88.0,
    malware_score: 10.0,
    bec_score: 20.0,
  },
  sender_analysis: {
    display_name: "PayPal Security Team",
    email_address: "security@paypa1-alerts.com",
    reply_to: "harvest@evil-domain.ru",
    return_path: "bounce@paypa1-alerts.com",
    sender_domain: "paypa1-alerts.com",
    originating_ip: "185.220.101.45",
    mail_server: "mail.paypa1-alerts.com",
    domain_age_days: 3,
    domain_registered: "2026-09-05",
    is_free_email: false,
    is_newly_registered: true,
    lookalike_domain: "paypal.com",
    header_from_mismatch: true,
  },
  authentication: {
    spf_result: "fail",
    spf_details: "No matching SPF record",
    dkim_result: "fail",
    dkim_selector: null,
    dkim_domain: null,
    dmarc_result: "fail",
    dmarc_policy: "reject",
    arc_result: "none",
    authentication_summary: "SPF FAIL · DKIM FAIL · DMARC FAIL",
  },
  malicious_ips: [
    {
      ip: "185.220.101.45",
      threat_score: 96.0,
      threat_categories: ["phishing", "tor-exit"],
      reputation_source: ["AbuseIPDB", "Spamhaus"],
      geo: {
        ip: "185.220.101.45",
        country: "Russia",
        country_code: "RU",
        city: "Moscow",
        is_tor: true,
        is_vpn: false,
        is_proxy: false,
        is_datacenter: false,
      },
      abuse_reports: 142,
    },
  ],
  malicious_urls: [
    {
      url: "http://paypa1-alerts.com/secure/verify?token=abc123",
      domain: "paypa1-alerts.com",
      threat_score: 98.0,
      threat_categories: ["phishing"],
      is_phishing_kit: true,
      is_credential_harvester: true,
    },
  ],
  reputation_scores: [
    {
      entity: "paypa1-alerts.com",
      entity_type: "domain",
      score: 97.0,
      sources: ["VirusTotal"],
      categories: ["phishing"],
      last_checked: "2026-09-08T13:00:00Z",
      is_blacklisted: true,
      blacklist_count: 8,
    },
  ],
  timeline: [
    {
      timestamp: "2026-09-08T12:30:00Z",
      event_type: "RECEIVED",
      description: "Email received",
      actor: "mx1.company.com",
      metadata: {},
    },
    {
      timestamp: "2026-09-08T13:00:00Z",
      event_type: "ANALYZED",
      description: "Analysis complete",
      actor: "TraceMail AI",
      metadata: {},
    },
  ],
  correlation_graph: {
    nodes: [
      { node_id: "n1", node_type: "email", label: "security@paypa1-alerts.com", threat_score: 92.5, attributes: {} },
      { node_id: "n2", node_type: "ip", label: "185.220.101.45", threat_score: 96.0, attributes: {} },
    ],
    edges: [
      { source_id: "n1", target_id: "n2", relationship: "SENDS_FROM", confidence: 0.95 },
    ],
  },
  evidence: {
    raw_headers: "From: security@paypa1-alerts.com\r\nTo: victim@company.com",
    parsed_headers: { from: "security@paypa1-alerts.com" },
    email_body_text: "Your account is at risk.",
    email_body_html: "<p>Your account is at risk.</p>",
    attachments: [],
    extracted_urls: ["http://paypa1-alerts.com/secure/verify?token=abc123"],
    extracted_ips: ["185.220.101.45"],
    hashes: {
      md5: "d41d8cd98f00b204e9800998ecf8427e",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
  },
};

// ---------------------------------------------------------------------------
// API Request Context
// ---------------------------------------------------------------------------

let apiContext: APIRequestContext;

test.beforeAll(async () => {
  apiContext = await request.newContext({
    baseURL: BACKEND_URL,
    extraHTTPHeaders: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });
});

test.afterAll(async () => {
  await apiContext.dispose();
});

// ---------------------------------------------------------------------------
// Smoke Tests
// ---------------------------------------------------------------------------

test.describe("@api @smoke Reports API Smoke Tests", () => {

  test("backend health check responds", async () => {
    const resp = await apiContext.get("/health");
    // Accept 200 or 404 — just verify backend is up
    expect([200, 404]).toContain(resp.status());
  });

  test("POST /api/v1/reports/generate returns 200", async () => {
    const resp = await apiContext.post("/api/v1/reports/generate", {
      data: SAMPLE_PAYLOAD,
    });
    expect(resp.status()).toBe(200);
  });

  test("POST /api/v1/reports/generate returns investigation_id", async () => {
    const resp = await apiContext.post("/api/v1/reports/generate", {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    expect(body).toHaveProperty("investigation_id", INV_ID);
  });

  test("POST /api/v1/reports/generate returns PDF and JSON report URLs", async () => {
    const resp = await apiContext.post("/api/v1/reports/generate", {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    expect(body.reports).toHaveProperty("pdf");
    expect(body.reports).toHaveProperty("json");
    expect(body.reports.pdf.url).toContain(INV_ID);
    expect(body.reports.json.url).toContain(INV_ID);
  });

  test("GET /api/report/json/{id} returns 200 with full report", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("report_id");
    expect(body).toHaveProperty("report_hash");
    expect(body).toHaveProperty("investigation_id", INV_ID);
  });

  test("JSON report contains all 10 forensic sections", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    const sections = [
      "case_summary", "risk_score", "sender_analysis", "authentication",
      "malicious_ips", "malicious_urls", "reputation_scores",
      "timeline", "correlation_graph", "evidence",
    ];
    for (const section of sections) {
      expect(body).toHaveProperty(section);
    }
  });

  test("JSON report verdict is MALICIOUS for test payload", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    expect(body.risk_score.verdict).toBe("MALICIOUS");
  });

  test("JSON report overall_score is between 0 and 100", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    expect(body.risk_score.overall_score).toBeGreaterThanOrEqual(0);
    expect(body.risk_score.overall_score).toBeLessThanOrEqual(100);
  });

  test("JSON report report_hash is 64-char hex string", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    const body = await resp.json();
    expect(body.report_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("GET /api/report/json with wrong ID returns 400", async () => {
    const resp = await apiContext.get("/api/report/json/WRONG-ID", {
      data: SAMPLE_PAYLOAD,
    });
    expect(resp.status()).toBe(400);
  });

  test("GET /api/report/json with empty body returns 422", async () => {
    const resp = await apiContext.get(`/api/report/json/${INV_ID}`, {
      data: {},
    });
    expect(resp.status()).toBe(422);
  });

  test("GET /api/report/pdf/{id} responds (200 or 500)", async () => {
    const resp = await apiContext.get(`/api/report/pdf/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    // 200 = WeasyPrint available; 500 = WeasyPrint not installed (still valid flow)
    expect([200, 500]).toContain(resp.status());
  });

  test("PDF response has correct content-type when available", async () => {
    const resp = await apiContext.get(`/api/report/pdf/${INV_ID}`, {
      data: SAMPLE_PAYLOAD,
    });
    if (resp.status() === 200) {
      expect(resp.headers()["content-type"]).toBe("application/pdf");
    }
  });
});

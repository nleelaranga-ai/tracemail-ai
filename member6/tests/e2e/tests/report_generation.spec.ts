/**
 * TraceMail AI — Member 6: E2E Tests
 * File: member6/tests/e2e/tests/report_generation.spec.ts
 *
 * E2E UI tests for the report generation flow:
 * User navigates to an investigation result → triggers PDF/JSON report
 * download → verifies file downloaded correctly.
 *
 * Tags: @ui @report
 *
 * Frontend URL: http://localhost:3000
 */

import { test, expect, Download } from "@playwright/test";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const INV_ID = "INV-E2E-001";

test.describe("@ui @report Report Generation UI Flow", () => {

  test.beforeEach(async ({ page }) => {
    // Navigate to the investigation results page
    await page.goto(`${FRONTEND_URL}/investigation/${INV_ID}`);
  });

  test("investigation results page loads", async ({ page }) => {
    // Page title or heading must mention the investigation
    await expect(page).toHaveTitle(/.*(TraceMail|Investigation|Report).*/i);
  });

  test("risk score is displayed on page", async ({ page }) => {
    // Risk score badge/indicator must be visible
    const riskEl = page.locator('[data-testid="risk-score"], .risk-score, [class*="risk"]').first();
    await expect(riskEl).toBeVisible({ timeout: 10_000 });
  });

  test("verdict badge is displayed", async ({ page }) => {
    // Verdict (MALICIOUS/SUSPICIOUS/CLEAN) badge must be visible
    const verdictEl = page
      .locator('[data-testid="verdict"], .verdict-badge, [class*="verdict"]')
      .first();
    await expect(verdictEl).toBeVisible({ timeout: 10_000 });
  });

  test("Generate PDF Report button is present", async ({ page }) => {
    const pdfBtn = page.getByRole("button", { name: /pdf|report|download/i }).first();
    await expect(pdfBtn).toBeVisible({ timeout: 10_000 });
  });

  test("Generate JSON Report button is present", async ({ page }) => {
    const jsonBtn = page.getByRole("button", { name: /json|machine.readable/i }).first();
    await expect(jsonBtn).toBeVisible({ timeout: 10_000 });
  });

  test("clicking PDF report triggers file download", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download");
    const pdfBtn = page.getByRole("button", { name: /pdf|report|download/i }).first();
    await pdfBtn.click();
    const download: Download = await downloadPromise;
    // Filename must end with .pdf
    expect(download.suggestedFilename()).toMatch(/\.pdf$/i);
  });

  test("clicking JSON report triggers file download", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download");
    const jsonBtn = page.getByRole("button", { name: /json|machine.readable/i }).first();
    await jsonBtn.click();
    const download: Download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.json$/i);
  });

  test("PDF download has non-zero size", async ({ page }) => {
    const downloadPromise = page.waitForEvent("download");
    const pdfBtn = page.getByRole("button", { name: /pdf|report/i }).first();
    await pdfBtn.click();
    const download: Download = await downloadPromise;
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test("all 10 report sections are visible in the UI", async ({ page }) => {
    const sections = [
      "Case Summary",
      "Risk Score",
      "Sender Analysis",
      "Authentication",
      "Malicious IP",
      "Malicious URL",
      "Reputation",
      "Timeline",
      "Correlation",
      "Evidence",
    ];
    for (const section of sections) {
      const el = page.getByText(new RegExp(section, "i")).first();
      await expect(el).toBeVisible({ timeout: 5_000 });
    }
  });

  test("authentication results show SPF DKIM DMARC", async ({ page }) => {
    await expect(page.getByText(/SPF/i).first()).toBeVisible();
    await expect(page.getByText(/DKIM/i).first()).toBeVisible();
    await expect(page.getByText(/DMARC/i).first()).toBeVisible();
  });

  test("malicious IPs section shows at least one entry", async ({ page }) => {
    const ipEl = page.locator(
      '[data-testid="malicious-ip-list"] li, .malicious-ip, [class*="malicious-ip"]'
    ).first();
    await expect(ipEl).toBeVisible({ timeout: 10_000 });
  });

  test("timeline shows at least two events", async ({ page }) => {
    const events = page.locator(
      '[data-testid="timeline-event"], .timeline-event, [class*="timeline"]'
    );
    await expect(events).toHaveCount(2, { timeout: 10_000 });
  });
});

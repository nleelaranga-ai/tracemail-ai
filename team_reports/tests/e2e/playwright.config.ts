import { defineConfig, devices } from "@playwright/test";

/**
 * TraceMail AI — Team Reports: E2E Test Configuration
 * File: team_reports/tests/e2e/playwright.config.ts
 *
 * Playwright configuration for E2E tests against the full stack.
 * Backend: http://localhost:8000
 * Frontend: http://localhost:3000
 *
 * Run all tests:    npx playwright test
 * Run with UI:      npx playwright test --ui
 * Run headed:       npx playwright test --headed
 * API tests only:   npx playwright test --grep @api
 */

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ["html", { outputFolder: "playwright-report", open: "never" }],
    ["json", { outputFile: "test-results/results.json" }],
    ["list"],
  ],
  use: {
    baseURL: process.env.FRONTEND_URL || "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "on-first-retry",
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
  },

  /* ── Browsers ─────────────────────────────────────────────── */
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 5"] },
    },
  ],

  /* ── Dev server auto-start (optional) ───────────────────── */
  // webServer: [
  //   {
  //     command: "cd ../../../.. && uvicorn app.main:app --port 8000",
  //     url: "http://localhost:8000/health",
  //     reuseExistingServer: !process.env.CI,
  //   },
  //   {
  //     command: "cd ../../../.. && npm run dev",
  //     url: "http://localhost:3000",
  //     reuseExistingServer: !process.env.CI,
  //   },
  // ],

  outputDir: "test-results",
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
});

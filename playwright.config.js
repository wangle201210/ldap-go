const fs = require("node:fs");
const path = require("node:path");
const { defineConfig, devices } = require("@playwright/test");

function localChromiumExecutable() {
  if (process.env.PLAYWRIGHT_EXECUTABLE_PATH) {
    return process.env.PLAYWRIGHT_EXECUTABLE_PATH;
  }
	if (process.env.PLAYWRIGHT_USE_SYSTEM_CHROME !== "1") return undefined;
  const candidates = process.platform === "darwin"
    ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    : process.platform === "win32"
      ? [
          path.join(process.env.PROGRAMFILES || "", "Google/Chrome/Application/chrome.exe"),
          path.join(process.env["PROGRAMFILES(X86)"] || "", "Google/Chrome/Application/chrome.exe")
        ]
      : ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
  return candidates.find((candidate) => candidate && fs.existsSync(candidate));
}

const executablePath = localChromiumExecutable();

module.exports = defineConfig({
  testDir: "./tests/e2e/webadmin",
  testMatch: /TC\d{3}-.+\.spec\.js/,
  outputDir: "./test-results/e2e-artifacts",
  globalSetup: require.resolve("./tests/e2e/support/global-setup"),
  globalTeardown: require.resolve("./tests/e2e/support/global-teardown"),
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
	failOnFlakyTests: Boolean(process.env.CI),
  forbidOnly: Boolean(process.env.CI),
  reporter: [
    ["line"],
    ["html", { outputFolder: "playwright-report", open: "never" }]
  ],
  use: {
    ...devices["Desktop Chrome"],
    locale: "en-US",
    colorScheme: "light",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    launchOptions: executablePath ? { executablePath } : {}
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } }
  ]
});

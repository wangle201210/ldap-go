const { test, expect, login, openLogin, waitForWorkspace } = require("../support/fixtures");

test("TC001 auth/startup has no permanent loading and persists the locale", async ({ page, e2e }, testInfo) => {
  await openLogin(page, e2e);

  await page.locator("#login-dn").fill(e2e.rootDN);
  await page.locator("#login-password").fill("definitely-wrong");
  await page.locator("#login-submit").click();
  await expect(page.locator("#login-error")).toBeVisible();
  await expect(page.locator("#login-submit")).toBeEnabled();

  await login(page, e2e);
  await waitForWorkspace(page);
  await expect(page.locator("#content-state")).toBeHidden();
  await expect(page.locator("#entry-table-wrap")).toBeVisible();

  await page.locator('[data-language="zh-CN"]:visible').click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await expect(page.locator("#connection-label")).toHaveText("已连接");
  await expect(page.locator("#new-entry-button")).toContainText("新建条目");
  await expect.poll(() => page.evaluate(() => localStorage.getItem("ldap-go.webadmin.language"))).toBe("zh-CN");

  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspace(page);
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await expect(page.locator("#connection-label")).toHaveText("已连接");

  await page.locator('[data-language="en"]:visible').click();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspace(page);
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.locator("#connection-label")).toHaveText("Connected");
  await page.screenshot({ path: testInfo.outputPath("tc001-startup-en.png"), fullPage: true });
});

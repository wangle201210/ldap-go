const {
  test,
  expect,
  login,
  openLogin
} = require("../support/fixtures");

function ldifRecord(e2e, suffix = "original") {
  return [
    `dn: uid=tc009-${suffix},${e2e.peopleDN}`,
    "changetype: add",
    "objectClass: top",
    "objectClass: person",
    `cn: TC009 ${suffix}`,
    "sn: Safety",
    "",
  ].join("\n");
}

test("TC009 LDIF unknown outcome blocks semantic retries and a 401 leaves login unobscured", async ({ page, e2e }) => {
  await openLogin(page, e2e);
  await login(page, e2e);

  let attempts = 0;
  await page.route("**/api/import", async (route) => {
    attempts += 1;
    await new Promise((resolve) => setTimeout(resolve, 150));
    await route.abort("connectionreset");
  });

  await page.locator("#import-button").click();
  const original = ldifRecord(e2e);
  await page.locator("#import-content").fill(original);
  await page.locator("#import-form button[type='submit']").click();
  await page.locator("#confirm-submit").click();

  await expect(page.locator("#import-content")).toBeDisabled();
  await expect(page.locator("#import-form button[type='submit']")).toBeDisabled();
  await expect(page.locator("#import-error")).toContainText(/unknown result|cannot directly retry|结果未知|不能直接重试/i);
  await expect(page.locator("#import-form button[type='submit']")).toBeEnabled();
  expect(attempts).toBe(1);

  await page.locator("#import-content").fill(`${original}\n\n# non-semantic review note\n`);
  await page.locator("#import-form button[type='submit']").click();
  await expect(page.locator("#confirm-dialog")).not.toBeVisible();
  await expect(page.locator("#import-error")).toContainText(/unknown result|cannot directly retry|结果未知|不能直接重试/i);
  expect(attempts).toBe(1);

  const changed = ldifRecord(e2e, "changed");
  await page.locator("#import-content").fill(changed);
  await page.locator("#import-form button[type='submit']").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await expect(page.locator("#confirm-message")).toContainText(/previous batch|上一批次/i);
  await page.locator("#confirm-cancel").click();
  expect(attempts).toBe(1);

  await page.unroute("**/api/import");
  await page.route("**/api/import", (route) => route.fulfill({
    status: 401,
    contentType: "application/json",
    body: JSON.stringify({ error: { code: "session_expired", message: "expired" } })
  }));
  await page.locator("#import-form button[type='submit']").click();
  await page.locator("#confirm-submit").click();
  await expect(page.locator("#login-dialog")).toBeVisible();
  await expect(page.locator("#import-dialog")).not.toBeVisible();
  await page.waitForTimeout(200);
  await expect(page.locator("#import-dialog")).not.toBeVisible();
});

test("TC009 CSV unknown outcome freezes controls and requires a semantic change", async ({ page, e2e }) => {
  await openLogin(page, e2e);
  await login(page, e2e);

  let attempts = 0;
  await page.route("**/api/csv-import", async (route) => {
    attempts += 1;
    await new Promise((resolve) => setTimeout(resolve, 150));
    await route.abort("connectionreset");
  });

  await page.locator("#account-button").click();
  await page.locator("#menu-import-csv").click();
  await page.locator("#csv-import-base").fill(e2e.peopleDN);
  await page.locator("#csv-import-mapping").fill("username=uid\nfull_name=cn\nsurname=sn");
  const original = "username,full_name,surname\ntc009-csv,TC009 CSV,Safety\n";
  await page.locator("#csv-import-content").fill(original);
  await page.locator("#csv-import-form button[type='submit']").click();

  await expect(page.locator("#csv-import-base")).toBeDisabled();
  await expect(page.locator("#csv-import-content")).toBeDisabled();
  await expect(page.locator("#csv-import-error")).toContainText(/may already exist|direct retry is disabled|可能已存在|禁止直接重试/i);
  await expect(page.locator("#csv-import-form button[type='submit']")).toBeEnabled();
  expect(attempts).toBe(1);

  await page.locator("#csv-import-content").fill(`${original}\n\n`);
  await page.locator("#csv-import-form button[type='submit']").click();
  await expect(page.locator("#confirm-dialog")).not.toBeVisible();
  expect(attempts).toBe(1);

  await page.locator("#csv-import-mapping").fill("username=uid\nfull_name=displayName\nsurname=sn");
  await page.locator("#csv-import-form button[type='submit']").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await expect(page.locator("#confirm-message")).toContainText(/previous batch|上一批次/i);
  await page.locator("#confirm-cancel").click();
  expect(attempts).toBe(1);
});

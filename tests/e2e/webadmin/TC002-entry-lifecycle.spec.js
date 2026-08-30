const {
  test,
  expect,
  cleanupEntry,
  fillAttribute,
  fillPersonDialog,
  findAttributeRow,
  login,
  openEntryFromResults,
  openLogin,
  rowForDN,
  runSearch
} = require("../support/fixtures");

async function expectOK(responsePromise, operation) {
  const response = await responsePromise;
  const body = await response.text();
  expect(response.ok(), `${operation}: ${response.status()} ${body}`).toBeTruthy();
  return response;
}

test("TC002 entry lifecycle creates, reads, edits, renames, resets password, and deletes", async ({ page, browser, e2e }, testInfo) => {
  const uid = `user-${e2e.runID}`;
  const renamedUID = `${uid}-renamed`;
  const originalDN = `uid=${uid},${e2e.peopleDN}`;
  const renamedDN = `uid=${renamedUID},${e2e.peopleDN}`;
  const newPassword = `Updated-${e2e.runID}!`;
  const values = {
    uid,
    cn: `E2E User ${e2e.runID}`,
    sn: "Lifecycle",
    mail: `${uid}@example.test`,
    description: "created by TC002"
  };

  await openLogin(page, e2e);
  await login(page, e2e);

  try {
    await page.locator("#new-entry-button").click();
    await expect(page.locator("#entry-dialog")).toBeVisible();
    await fillPersonDialog(page, originalDN, values);
    await page.screenshot({ path: testInfo.outputPath("tc002-create-dialog.png") });
    const createResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries") && response.request().method() === "POST"
    );
    await page.locator("#entry-form button[type='submit']").click();
    await expectOK(createResponse, "create entry");
    await expect(page.locator("#entry-dialog")).not.toBeVisible();
    await expect(page.locator("#detail-dn")).toHaveText(originalDN);
    await fillAttribute(page, "#attribute-list", "description", "edited by TC002");

    const editResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries") && response.request().method() === "PATCH"
    );
    await page.locator("#save-entry").click();
    await expectOK(editResponse, "edit entry");
    await expect(page.locator("#detail-dn")).toHaveText(originalDN);

    await runSearch(page, { base: originalDN, scope: "base" });
    await openEntryFromResults(page, originalDN);
    const descriptionRow = await findAttributeRow(page, "#attribute-list", "description");
    await expect(descriptionRow.locator(".attribute-values, .schema-value-control").first()).toHaveValue("edited by TC002");
    await page.screenshot({ path: testInfo.outputPath("tc002-created-detail.png"), fullPage: true });

    await page.locator("#new-entry-button").click();
    await fillPersonDialog(page, originalDN, values);
    const duplicateResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries") && response.request().method() === "POST"
    );
    await page.locator("#entry-form button[type='submit']").click();
    const duplicate = await duplicateResponse;
    expect(duplicate.ok(), `duplicate entry unexpectedly succeeded: ${await duplicate.text()}`).toBeFalsy();
    await expect(page.locator("#entry-form-error")).toBeVisible();
    await expect(page.locator("#entry-form button[type='submit']")).toBeEnabled();
    await page.screenshot({ path: testInfo.outputPath("tc002-create-error-recovered.png") });
    await page.locator("#entry-form .modal-actions .close-dialog").click();

	await fillAttribute(page, "#attribute-list", "description", "unsaved rename guard");
	await page.locator("#rename-button").click();
	await expect(page.locator("#confirm-dialog")).toBeVisible();
	await page.locator("#confirm-cancel").click();
	await expect(page.locator("#rename-dialog")).not.toBeVisible();
	await expect((await findAttributeRow(page, "#attribute-list", "description")).locator(".attribute-values")).toHaveValue("unsaved rename guard");
	await page.locator("#rename-button").click();
	await page.locator("#confirm-submit").click();
	await expect(page.locator("#rename-dialog")).toBeVisible();
	await expect((await findAttributeRow(page, "#attribute-list", "description")).locator(".attribute-values")).toHaveValue("edited by TC002");

    await page.locator("#rename-rdn").fill(`uid=${renamedUID}`);
    await page.locator("#rename-superior").fill(e2e.peopleDN);
    const renameResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries/rename") && response.request().method() === "POST"
    );
    await page.locator("#rename-form button[type='submit']").click();
    await expectOK(renameResponse, "rename entry");
    await expect(page.locator("#rename-dialog")).not.toBeVisible();
    await expect(page.locator("#detail-dn")).toHaveText(renamedDN);

    await page.locator("#password-button").click();
    await page.locator("#new-password").fill(newPassword);
    await page.locator("#confirm-password").fill(`${newPassword}-mismatch`);
    await page.locator("#password-form button[type='submit']").click();
    await expect(page.locator("#password-error")).toBeVisible();
    await expect(page.locator("#password-form button[type='submit']")).toBeEnabled();
    await page.locator("#confirm-password").fill(newPassword);
    const passwordResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/password-modify") && response.request().method() === "POST"
    );
    await page.locator("#password-form button[type='submit']").click();
    await expectOK(passwordResponse, "reset password");
    await expect(page.locator("#password-dialog")).not.toBeVisible();

    const userContext = await browser.newContext({ locale: "en-US" });
    try {
      const userPage = await userContext.newPage();
      await openLogin(userPage, e2e);
      await login(userPage, e2e, { dn: renamedDN, password: newPassword }, { waitForWorkspace: false });
      await expect(userPage.locator("#account-dn")).toHaveText(renamedDN);
    } finally {
      await userContext.close();
    }

    await page.locator("#delete-button").click();
    await expect(page.locator("#confirm-dialog")).toBeVisible();
    const deleteResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries") && response.request().method() === "DELETE"
    );
    await page.locator("#confirm-submit").click();
    await expectOK(deleteResponse, "delete entry");
    await expect(page.locator("#confirm-dialog")).not.toBeVisible();

    await runSearch(page, { base: e2e.peopleDN, scope: "sub", filter: `(uid=${renamedUID})` });
    await expect(rowForDN(page, renamedDN)).toHaveCount(0);
    await expect(page.locator("#content-state")).toBeVisible();
  } finally {
    await cleanupEntry(e2e, renamedDN);
    await cleanupEntry(e2e, originalDN);
  }
});

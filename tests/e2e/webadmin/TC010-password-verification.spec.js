const {
  test,
  expect,
  login,
  openEntryFromResults,
  runSearch
} = require("../support/fixtures");

async function openFixturePasswordDialog(page, e2e) {
  await runSearch(page, {
    base: e2e.peopleDN,
    scope: "sub",
    filter: `(uid=${e2e.fixtureUID})`,
    size: 10
  });
  await openEntryFromResults(page, e2e.fixtureDN);
  await page.locator("#password-button").click();
  await expect(page.locator("#password-dialog")).toBeVisible();
}

async function resetPassword(page, e2e, password, oldPassword = "", storageMethod = "policy") {
  if (!await page.locator("#password-dialog").isVisible()) {
    await openFixturePasswordDialog(page, e2e);
  }
  await page.locator("#current-password").fill(oldPassword);
  await page.locator("#new-password").fill(password);
  await page.locator("#confirm-password").fill(password);
	await page.locator("#password-hash-scheme").selectOption(storageMethod);
	const endpoint = storageMethod === "policy" ? "/api/password-modify" : "/api/password-set-hash";
  const responsePromise = page.waitForResponse((response) =>
	response.url().endsWith(endpoint) && response.request().method() === "POST"
  );
  await page.locator("#password-form button[type='submit']").click();
  const response = await responsePromise;
	const responseText = await response.text();
	expect(response.ok(), `password reset response: ${response.status()} ${responseText}`).toBeTruthy();
  await expect(page.locator("#password-dialog")).not.toBeVisible();
	return { requestBody: response.request().postDataJSON(), responseText };
}

test("TC010 verifies the current password and changes it with old_password", async ({ page, browser, e2e }) => {
  const changedPassword = `Verified-${e2e.runID}!`;
  let passwordNeedsRestore = false;

  await login(page, e2e);
  await openFixturePasswordDialog(page, e2e);

  try {
    const currentPassword = page.locator("#current-password");
    const verifyButton = page.locator("#verify-current-password");
    const verifyStatus = page.locator("#password-verify-status");

    await expect(verifyButton).toBeDisabled();
    await currentPassword.fill(e2e.secondaryPassword);
    const correctResponsePromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/password-verify") && response.request().method() === "POST"
    );
    await verifyButton.click();
    const correctResponse = await correctResponsePromise;
    const correctBody = await correctResponse.json();
    expect(correctResponse.request().postDataJSON()).toEqual({
      user_identity: e2e.fixtureDN,
      password: e2e.secondaryPassword
    });
    expect(correctResponse.ok(), `correct verification response: ${correctResponse.status()} ${JSON.stringify(correctBody)}`).toBeTruthy();
    expect(correctBody).toEqual(expect.objectContaining({ verified: true }));
    await expect(verifyStatus).toHaveAttribute("data-state", "verified");
    await expect(verifyStatus).toContainText("Current password verified");

    await currentPassword.fill(`Wrong-${e2e.runID}!`);
    const wrongResponsePromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/password-verify") && response.request().method() === "POST"
    );
    await verifyButton.click();
    const wrongResponse = await wrongResponsePromise;
    const wrongBody = await wrongResponse.json();
    expect(wrongResponse.ok(), `wrong verification response: ${wrongResponse.status()} ${JSON.stringify(wrongBody)}`).toBeTruthy();
    expect(wrongBody).toEqual(expect.objectContaining({ verified: false }));
    await expect(verifyStatus).toHaveAttribute("data-state", "rejected");
    await expect(verifyStatus).toContainText("Current password is incorrect");
    await expect(currentPassword).toHaveAttribute("aria-invalid", "true");

    await currentPassword.fill(e2e.secondaryPassword);
    passwordNeedsRestore = true;
	const { requestBody: modifyBody } = await resetPassword(page, e2e, changedPassword, e2e.secondaryPassword);
    expect(modifyBody).toEqual({
      user_identity: e2e.fixtureDN,
      new_password: changedPassword,
      old_password: e2e.secondaryPassword
    });
    const userContext = await browser.newContext();
    const userPage = await userContext.newPage();
    try {
      await login(userPage, e2e, { dn: e2e.fixtureDN, password: changedPassword }, { waitForWorkspace: false });
    } finally {
      await userContext.close();
    }

    await openFixturePasswordDialog(page, e2e);
	const { requestBody: administratorResetBody } = await resetPassword(page, e2e, e2e.secondaryPassword);
    expect(administratorResetBody).toEqual({
      user_identity: e2e.fixtureDN,
      new_password: e2e.secondaryPassword
    });
    passwordNeedsRestore = false;
  } finally {
    if (passwordNeedsRestore) {
      if (await page.locator("#password-dialog").isVisible()) {
        await page.locator("#password-dialog .close-dialog").last().click();
      }
      await openFixturePasswordDialog(page, e2e);
      await resetPassword(page, e2e, e2e.secondaryPassword);
    }
  }
});

test("TC010 selects PBKDF2-SM3 for one password change and restores server policy", async ({ page, browser, e2e }) => {
	const changedPassword = `PBKDF2-SM3-${e2e.runID}!`;
	let passwordNeedsRestore = false;

	await login(page, e2e);
	await openFixturePasswordDialog(page, e2e);

	try {
	  const storage = page.locator("#password-hash-scheme");
	  await expect(storage).toHaveValue("policy");
	  await expect(storage.locator('option[value="{PBKDF2-SM3}"]')).toHaveText("PBKDF2-SM3 (SM3 recommended)");
	  await storage.selectOption("{PBKDF2-SM3}");
	  await expect(page.locator("#password-hash-warning")).toBeVisible();
	  await expect(page.locator("#password-hash-warning")).toContainText("password-administrator permission");

	  passwordNeedsRestore = true;
	  const direct = await resetPassword(page, e2e, changedPassword, e2e.secondaryPassword, "{PBKDF2-SM3}");
	  expect(direct.requestBody).toEqual({
		user_identity: e2e.fixtureDN,
		new_password: changedPassword,
		old_password: e2e.secondaryPassword,
		hash_scheme: "{PBKDF2-SM3}"
	  });
	  expect(direct.responseText).not.toContain(changedPassword);
	  expect(direct.responseText).not.toMatch(/"(?:hash|password_hash|userPassword|user_password)"\s*:/i);
	  expect(direct.responseText).not.toMatch(/\{PBKDF2-SM3\}\d+\$/);

	  const changedContext = await browser.newContext();
	  const changedPage = await changedContext.newPage();
	  try {
		await login(changedPage, e2e, { dn: e2e.fixtureDN, password: changedPassword }, { waitForWorkspace: false });
	  } finally {
		await changedContext.close();
	  }

	  await openFixturePasswordDialog(page, e2e);
	  await expect(page.locator("#password-hash-scheme")).toHaveValue("policy");
	  const restored = await resetPassword(page, e2e, e2e.secondaryPassword);
	  expect(restored.requestBody).toEqual({
		user_identity: e2e.fixtureDN,
		new_password: e2e.secondaryPassword
	  });
	  passwordNeedsRestore = false;

	  const restoredContext = await browser.newContext();
	  const restoredPage = await restoredContext.newPage();
	  try {
		await login(restoredPage, e2e, { dn: e2e.fixtureDN, password: e2e.secondaryPassword }, { waitForWorkspace: false });
	  } finally {
		await restoredContext.close();
	  }
	} finally {
	  if (passwordNeedsRestore) {
		if (await page.locator("#password-dialog").isVisible()) {
		  await page.locator("#password-dialog .close-dialog").last().click();
		}
		await openFixturePasswordDialog(page, e2e);
		await resetPassword(page, e2e, e2e.secondaryPassword);
	  }
	}
});

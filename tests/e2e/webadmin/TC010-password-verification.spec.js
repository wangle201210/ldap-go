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

async function resetPassword(page, e2e, password, oldPassword = "") {
  if (!await page.locator("#password-dialog").isVisible()) {
    await openFixturePasswordDialog(page, e2e);
  }
  await page.locator("#current-password").fill(oldPassword);
  await page.locator("#new-password").fill(password);
  await page.locator("#confirm-password").fill(password);
  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/password-modify") && response.request().method() === "POST"
  );
  await page.locator("#password-form button[type='submit']").click();
  const response = await responsePromise;
  expect(response.ok(), `password reset response: ${response.status()} ${await response.text()}`).toBeTruthy();
  await expect(page.locator("#password-dialog")).not.toBeVisible();
  return response.request().postDataJSON();
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
    const modifyBody = await resetPassword(page, e2e, changedPassword, e2e.secondaryPassword);
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
    const administratorResetBody = await resetPassword(page, e2e, e2e.secondaryPassword);
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

const {
  test,
  expect,
  login,
  openEntryFromResults,
  openLogin,
  rowForDN,
  runSearch
} = require("../support/fixtures");

const viewports = [
  { width: 1440, height: 900 },
  { width: 900, height: 800 },
  { width: 390, height: 844 },
  { width: 320, height: 568 }
];

async function expectNoHorizontalOverflow(page, label) {
  await expect.poll(async () => page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth
  })), { message: `${label} must fit the viewport` }).toEqual(expect.objectContaining({
    viewport: page.viewportSize().width,
    document: expect.any(Number),
    body: expect.any(Number)
  }));

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth
  }));
  expect(dimensions.document, `${label}: document overflow`).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.body, `${label}: body overflow`).toBeLessThanOrEqual(dimensions.viewport + 1);
}

async function expectOnlyPane(page, expectedPane) {
  const visibility = await page.locator("#navigation-pane, #main-content, #context-pane").evaluateAll((panes) =>
    Object.fromEntries(panes.map((pane) => [pane.id, Boolean(pane.offsetWidth || pane.offsetHeight || pane.getClientRects().length)]))
  );
  expect(visibility).toEqual({
    "navigation-pane": expectedPane === "navigation-pane",
    "main-content": expectedPane === "main-content",
    "context-pane": expectedPane === "context-pane"
  });
}

async function expectDialogContract(page, selector) {
  const dialog = page.locator(selector);
  await expect(dialog).toBeVisible();

  const descriptionIDs = String(await dialog.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter(Boolean);
  expect(descriptionIDs, `${selector} needs aria-describedby`).not.toHaveLength(0);
  for (const id of descriptionIDs) {
    await expect(page.locator(`#${id}`), `${selector} describes missing #${id}`).toHaveCount(1);
  }

  await expect.poll(() => dialog.evaluate((element) => element.contains(document.activeElement)), {
    message: `${selector} must receive initial focus`
  }).toBeTruthy();
}

async function closeDialog(page, selector) {
  const dialog = page.locator(selector);
  const cancel = dialog.locator(".close-dialog, #confirm-cancel").last();
  await cancel.click();
  await expect(dialog).not.toBeVisible();
}

async function expectButtonTextFits(locator, label) {
  await expect(locator).toBeVisible();
  const geometry = await locator.evaluate((element) => ({
    clientWidth: element.clientWidth,
    clientHeight: element.clientHeight,
    scrollWidth: element.scrollWidth,
    scrollHeight: element.scrollHeight
  }));
  expect(geometry.scrollWidth, `${label} text is horizontally clipped`).toBeLessThanOrEqual(geometry.clientWidth + 1);
  expect(geometry.scrollHeight, `${label} text is vertically clipped`).toBeLessThanOrEqual(geometry.clientHeight + 1);
}

async function expectEditorFooterAfterAttributes(page) {
  const layout = await page.locator("#entry-editor").evaluate((editor) => {
    const footer = editor.querySelector(".editor-footer").getBoundingClientRect();
    const rows = Array.from(editor.querySelectorAll("#attribute-list > .attribute-row"), (row) => row.getBoundingClientRect());
    return {
      footerTop: footer.top,
      lastRowBottom: rows.length ? rows[rows.length - 1].bottom : footer.top,
      overlaps: rows.filter((row) => footer.left < row.right && footer.right > row.left && footer.top < row.bottom && footer.bottom > row.top).length
    };
  });
  expect(layout.footerTop).toBeGreaterThanOrEqual(layout.lastRowBottom - 1);
  expect(layout.overlaps).toBe(0);
}

async function openFixtureOnMobile(page, e2e) {
  await page.locator('[data-mobile-view="navigation"]').click();
  await expect(page.locator("#workspace")).toHaveAttribute("data-mobile-view", "navigation");

  await runSearch(page, {
    base: e2e.peopleDN,
    scope: "sub",
    filter: `(uid=${e2e.fixtureUID})`,
    size: 10
  });

  await expect(page.locator("#workspace")).toHaveAttribute("data-mobile-view", "content");
  await expectOnlyPane(page, "main-content");
  await expect(rowForDN(page, e2e.fixtureDN)).toBeVisible();
  await openEntryFromResults(page, e2e.fixtureDN);
  await expect(page.locator("#detail-dn")).toHaveText(e2e.fixtureDN);
  await expect(page.locator("#detail-view")).toBeVisible();
  await expectEditorFooterAfterAttributes(page);
}

async function expectChineseMobileActions(page) {
  await page.locator('#language-switch [data-language="zh-CN"]').click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");

  const clone = page.locator("#mobile-clone-button");
  const more = page.locator("#mobile-entry-more > summary");
  const remove = page.locator("#mobile-delete-button");

  await expect.soft(clone, "clone text must be Chinese").toContainText("克隆");
  await expect.soft(clone, "clone aria-label must be Chinese").toHaveAttribute("aria-label", /克隆/, { timeout: 2_000 });
  await expect.soft(clone, "clone title must be Chinese").toHaveAttribute("title", /克隆/, { timeout: 2_000 });
  await expect.soft(more, "more text must be Chinese").toContainText("更多");
  await expect.soft(more, "more aria-label must be Chinese").toHaveAttribute("aria-label", /更多/, { timeout: 2_000 });
  await expect.soft(more, "more title must be Chinese").toHaveAttribute("title", /更多/, { timeout: 2_000 });

  await more.click();
  await expect.soft(remove, "delete text must be Chinese").toContainText("删除");
  await expect.soft(remove, "delete aria-label must be Chinese").toHaveAttribute("aria-label", /删除/, { timeout: 2_000 });
  await expect.soft(remove, "delete title must be Chinese").toHaveAttribute("title", /删除/, { timeout: 2_000 });

  for (const [locator, label] of [
    [page.locator("#mobile-rename-button"), "rename"],
    [page.locator("#mobile-password-button"), "password"],
    [clone, "clone"],
    [more, "more"],
    [remove, "delete"]
  ]) {
    await expectButtonTextFits(locator, label);
  }
}

async function expectMobileCreateDialogFits(page) {
	const more = page.locator("#mobile-entry-more");
	if (await more.getAttribute("open") !== null) await more.locator("summary").click();
	await page.locator("#new-entry-button").click();
	await expectDialogContract(page, "#entry-dialog");
	await expect(page.locator("#entry-form .modal-actions button[type='submit']")).toBeVisible();
	const geometry = await page.locator("#entry-dialog").evaluate((dialog) => ({
	  left: dialog.getBoundingClientRect().left,
	  right: dialog.getBoundingClientRect().right,
	  top: dialog.getBoundingClientRect().top,
	  bottom: dialog.getBoundingClientRect().bottom,
	  viewportWidth: window.innerWidth,
	  viewportHeight: window.innerHeight,
	  attributeClientWidth: dialog.querySelector("#new-entry-attribute-list").clientWidth,
	  attributeScrollWidth: dialog.querySelector("#new-entry-attribute-list").scrollWidth
	}));
	expect(geometry.left).toBeGreaterThanOrEqual(-1);
	expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth + 1);
	expect(geometry.top).toBeGreaterThanOrEqual(-1);
	expect(geometry.bottom).toBeLessThanOrEqual(geometry.viewportHeight + 1);
	expect(geometry.attributeScrollWidth).toBeLessThanOrEqual(geometry.attributeClientWidth + 1);
	const classes = await page.locator("#new-entry-classes").inputValue();
	expect(classes).toContain("\n");
	expect(classes).not.toContain("\\n");
	await closeDialog(page, "#entry-dialog");
}

async function expectMobilePasswordDialogFits(page, testInfo) {
	await page.locator("#mobile-password-button").click();
	await expectDialogContract(page, "#password-dialog");
	await expect(page.locator("label[for='current-password']")).toContainText("当前密码");
	const verify = page.locator("#verify-current-password");
	await expect(verify).toHaveAttribute("aria-label", "验证当前密码");
	await expect(verify).toHaveAttribute("title", "验证当前密码");
	await expect(verify).toBeDisabled();
	await page.locator("#current-password").fill("layout-check");
	await expect(verify).toBeEnabled();
	await expectButtonTextFits(verify, "verify current password");
	const geometry = await page.locator("#password-dialog").evaluate((dialog) => {
	  const dialogBox = dialog.getBoundingClientRect();
	  const controls = dialog.querySelector(".password-verify-controls");
	  return {
		left: dialogBox.left,
		right: dialogBox.right,
		top: dialogBox.top,
		bottom: dialogBox.bottom,
		viewportWidth: window.innerWidth,
		viewportHeight: window.innerHeight,
		controlsClientWidth: controls.clientWidth,
		controlsScrollWidth: controls.scrollWidth
	  };
	});
	expect(geometry.left).toBeGreaterThanOrEqual(-1);
	expect(geometry.right).toBeLessThanOrEqual(geometry.viewportWidth + 1);
	expect(geometry.top).toBeGreaterThanOrEqual(-1);
	expect(geometry.bottom).toBeLessThanOrEqual(geometry.viewportHeight + 1);
	expect(geometry.controlsScrollWidth).toBeLessThanOrEqual(geometry.controlsClientWidth + 1);
	await page.screenshot({
	  path: testInfo.outputPath(`tc006-password-${geometry.viewportWidth}x${geometry.viewportHeight}.png`),
	  fullPage: true
	});
	await closeDialog(page, "#password-dialog");
}

async function expectToastDoesNotBlockHeader(page) {
	await page.locator("#copy-entry-dn").click();
	const toast = page.locator("#toast-region .toast").last();
	await expect(toast).toBeVisible();
	const overlaps = await toast.evaluate((element) => {
	  const toastBox = element.getBoundingClientRect();
	  return ["new-entry-button", "refresh-content"].filter((id) => {
		const box = document.getElementById(id).getBoundingClientRect();
		return toastBox.left < box.right && toastBox.right > box.left && toastBox.top < box.bottom && toastBox.bottom > box.top;
	  });
	});
	expect(overlaps).toEqual([]);
	await toast.locator("button").click();
}

async function expectAccountMenuKeyboard(page) {
	await page.locator("#account-button").click();
	const menu = page.locator("#account-menu");
	const first = page.locator("#menu-import");
	const second = page.locator("#menu-import-csv");
	await expect(first).toBeFocused();
	await expect(first).toHaveAttribute("tabindex", "0");
	await page.keyboard.press("ArrowDown");
	await expect(second).toBeFocused();
	await expect(first).toHaveAttribute("tabindex", "-1");
	await expect(second).toHaveAttribute("tabindex", "0");
	await page.keyboard.press("Tab");
	await expect(menu).toBeHidden();
	await expect(page.locator("#account-button")).toHaveAttribute("aria-expanded", "false");
}

async function exerciseDialogContracts(page, e2e) {
  const brokenDescriptions = await page.locator("dialog[aria-describedby]").evaluateAll((dialogs) =>
    dialogs.flatMap((dialog) => String(dialog.getAttribute("aria-describedby") || "")
      .split(/\s+/)
      .filter(Boolean)
      .filter((id) => !document.getElementById(id))
      .map((id) => `${dialog.id}:${id}`))
  );
  expect(brokenDescriptions).toEqual([]);

  await page.locator("#new-entry-button").click();
  await expectDialogContract(page, "#entry-dialog");
  await closeDialog(page, "#entry-dialog");

  await page.locator("#import-button").click();
  await expectDialogContract(page, "#import-dialog");
  await closeDialog(page, "#import-dialog");

  await page.locator("#account-button").click();
  await page.locator("#menu-import-csv").click();
  await expectDialogContract(page, "#csv-import-dialog");
  await closeDialog(page, "#csv-import-dialog");

  await runSearch(page, {
    base: e2e.peopleDN,
    scope: "sub",
    filter: `(uid=${e2e.fixtureUID})`,
    size: 10
  });
  await openEntryFromResults(page, e2e.fixtureDN);
  await expectEditorFooterAfterAttributes(page);

  await page.locator("#rename-button").click();
  await expectDialogContract(page, "#rename-dialog");
  await closeDialog(page, "#rename-dialog");

  await page.locator("#password-button").click();
  await expectDialogContract(page, "#password-dialog");
	await page.locator("#new-password").fill("one-value");
	await page.locator("#confirm-password").fill("different-value");
	await page.locator("#password-form button[type='submit']").click();
	await expect(page.locator("#password-error")).toBeVisible();
	await expect(page.locator("#confirm-password")).toHaveAttribute("aria-invalid", "true");
	await expect(page.locator("#confirm-password")).toHaveAttribute("aria-describedby", /(?:^|\s)password-error(?:\s|$)/);
  await closeDialog(page, "#password-dialog");

  await page.locator("#delete-button").click();
  await expectDialogContract(page, "#confirm-dialog");
  await closeDialog(page, "#confirm-dialog");

  await page.locator("#list-view-button").click();
  await rowForDN(page, e2e.fixtureDN).locator('input[type="checkbox"]').check();
  await expect(page.locator("#bulk-toolbar")).toBeVisible();
  await page.locator("#bulk-modify-button").click();
  await expectDialogContract(page, "#bulk-modify-dialog");
  await closeDialog(page, "#bulk-modify-dialog");

  await expect(page.locator("#new-password")).not.toHaveAttribute("minlength", /.+/);
  await expect(page.locator("#confirm-password")).not.toHaveAttribute("minlength", /.+/);
}

for (const viewport of viewports) {
  test(`TC006 responsive/a11y/i18n at ${viewport.width}x${viewport.height}`, async ({ page, e2e }, testInfo) => {
    await page.setViewportSize(viewport);
    await openLogin(page, e2e);
    await expectDialogContract(page, "#login-dialog");
    await login(page, e2e);
    await expectNoHorizontalOverflow(page, `${viewport.width}x${viewport.height} workspace`);

    if (viewport.width === 1440) {
      await expect(page.locator(".mobile-view-switch")).toBeHidden();
      await expect(page.locator("#navigation-pane")).toBeVisible();
      await expect(page.locator("#main-content")).toBeVisible();
      await expect(page.locator("#context-pane")).toBeVisible();
      await exerciseDialogContracts(page, e2e);
	  await expectAccountMenuKeyboard(page);
    } else if (viewport.width === 900) {
      await expect(page.locator(".mobile-view-switch")).toBeVisible();
	  await expect(page.locator("#workspace")).not.toHaveAttribute("aria-label", /.+/);
	  await expect(page.locator("#workspace")).not.toHaveAttribute("title", /.+/);
      await expectOnlyPane(page, "main-content");

      await page.locator('[data-mobile-view="navigation"]').click();
      await expectOnlyPane(page, "navigation-pane");
      await expect(page.locator("#navigation-pane")).toBeFocused();

      await page.locator('[data-mobile-view="context"]').click();
      await expectOnlyPane(page, "context-pane");
      await expect(page.locator("#context-pane")).toBeFocused();

      await page.locator('[data-mobile-view="content"]').click();
      await expectOnlyPane(page, "main-content");
      await expect(page.locator("#main-content")).toBeFocused();
      await expectNoHorizontalOverflow(page, "900px single-pane workspace");
    } else {
      await openFixtureOnMobile(page, e2e);
	  await expectChineseMobileActions(page);
	  await expectMobilePasswordDialogFits(page, testInfo);
	  await expectToastDoesNotBlockHeader(page);
	  await expectMobileCreateDialogFits(page);
      await expectNoHorizontalOverflow(page, `${viewport.width}px mobile detail`);
    }
	await page.screenshot({ path: testInfo.outputPath(`tc006-${viewport.width}x${viewport.height}.png`), fullPage: true });
  });
}

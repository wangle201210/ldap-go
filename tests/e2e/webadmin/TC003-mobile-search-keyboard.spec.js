const { test, expect, login, openLogin, rowForDN } = require("../support/fixtures");

for (const viewport of [
  { width: 390, height: 844 },
  { width: 320, height: 568 }
]) {
  test(`TC003 mobile/search/keyboard works at ${viewport.width}x${viewport.height}`, async ({ page, e2e }, testInfo) => {
    await page.setViewportSize(viewport);
    await openLogin(page, e2e);
    await login(page, e2e);

    await page.locator('[data-mobile-view="navigation"]').click();
    await expect(page.locator("#workspace")).toHaveAttribute("data-mobile-view", "navigation");
    await page.locator("#tree-tab").focus();
    await page.keyboard.press("ArrowRight");
    await expect(page.locator("#search-tab")).toBeFocused();
    await expect(page.locator("#search-tab")).toHaveAttribute("aria-selected", "true");

	    const searchBase = page.locator("#search-base");
	    await searchBase.click();
	    await expect(searchBase).toBeFocused();
	    await searchBase.press("ControlOrMeta+A");
	    await page.keyboard.type(e2e.peopleDN);
	    const searchFilter = page.locator("#search-filter");
	    await searchFilter.click();
	    await expect(searchFilter).toBeFocused();
	    await searchFilter.press("ControlOrMeta+A");
	    await page.keyboard.type(`(uid=${e2e.fixtureUID})`);
    await page.locator("#search-scope").selectOption("sub");
    await page.locator("#search-size").fill("10");
    await page.locator("#search-attributes").fill("objectClass,uid,cn,sn,description");
    const searchResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/search") && response.request().method() === "POST"
    );
    await page.locator("#search-filter").press("Enter");
    expect((await searchResponse).ok()).toBeTruthy();

    const mobileView = await page.locator("#workspace").getAttribute("data-mobile-view");
    expect.soft(mobileView, "mobile search should reveal its results").toBe("content");
    if (mobileView !== "content") {
      await page.locator('[data-mobile-view="content"]').click();
    }

    const row = rowForDN(page, e2e.fixtureDN);
    await expect(row).toBeVisible();
    await row.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#detail-dn")).toHaveText(e2e.fixtureDN);
    await expect(page.locator("#detail-view")).toBeVisible();
    const focusMoved = await page.evaluate(() => {
      const active = document.activeElement;
      return Boolean(active && (active.id === "main-content" || active.closest("#detail-view")));
    });
    expect.soft(focusMoved, "keyboard navigation should move focus into the visible detail view").toBeTruthy();

    const dimensions = await page.evaluate(() => ({ width: window.innerWidth, scrollWidth: document.documentElement.scrollWidth }));
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.width);
    await page.screenshot({ path: testInfo.outputPath(`tc003-${viewport.width}x${viewport.height}.png`), fullPage: true });
  });
}

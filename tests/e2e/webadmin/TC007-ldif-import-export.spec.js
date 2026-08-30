const fs = require("node:fs/promises");
const {
  test,
  expect,
  cleanupEntry,
  findAttributeRow,
  login,
  openEntryFromResults,
  openLogin,
  rowForDN,
  runSearch
} = require("../support/fixtures");

async function submitLDIF(page, content) {
  await page.locator("#import-button").click();
  await expect(page.locator("#import-dialog")).toBeVisible();
  await page.locator("#import-content").fill(content);
  await page.locator("#import-form button[type='submit']").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();

  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/import") && response.request().method() === "POST"
  );
  await page.locator("#confirm-submit").click();
  return responsePromise;
}

function addRecord({ dn, uid, cn, sn, description }) {
  return [
    `dn: ${dn}`,
    "changetype: add",
    "objectClass: top",
    "objectClass: person",
    "objectClass: organizationalPerson",
    "objectClass: inetOrgPerson",
    `uid: ${uid}`,
    `cn: ${cn}`,
    `sn: ${sn}`,
    `description: ${description}`,
    ""
  ].join("\n");
}

test("TC007 LDIF import/export reports structured partial results without retrying", async ({ page, e2e }) => {
  const importedUID = `ldif-primary-${e2e.runID}`;
  const appliedUID = `ldif-applied-${e2e.runID}`;
  const notAttemptedUID = `ldif-skipped-${e2e.runID}`;
  const importedDN = `uid=${importedUID},${e2e.peopleDN}`;
  const appliedDN = `uid=${appliedUID},${e2e.peopleDN}`;
  const notAttemptedDN = `uid=${notAttemptedUID},${e2e.peopleDN}`;
  const importedDescription = `TC007 exported ${e2e.runID}`;

  await openLogin(page, e2e);
  await login(page, e2e);

  try {
    const importResponse = await submitLDIF(page, addRecord({
      dn: importedDN,
      uid: importedUID,
      cn: `LDIF Primary ${e2e.runID}`,
      sn: "Primary",
      description: importedDescription
    }));
    const importBody = await importResponse.json();

    expect(importResponse.ok(), JSON.stringify(importBody)).toBeTruthy();
    expect(importBody).toMatchObject({
      applied: 1,
      failed: 0,
      unknown: 0,
      aborted: false,
      abort_reason: "",
      results: [{
        record: 1,
        dn: importedDN,
        operation: "add",
        success: true,
        status: "applied"
      }]
    });
    await expect(page.locator("#import-dialog")).not.toBeVisible();

    await runSearch(page, {
      base: importedDN,
      scope: "base",
      filter: `(uid=${importedUID})`,
      attributes: "objectClass,uid,cn,sn,description"
    });
    await expect(rowForDN(page, importedDN)).toHaveCount(1);
    await openEntryFromResults(page, importedDN);
    const descriptionRow = await findAttributeRow(page, "#attribute-list", "description");
    await expect(descriptionRow.locator(".attribute-values, .schema-value-control").first()).toHaveValue(importedDescription);

	    const downloadPromise = page.waitForEvent("download");
	    await page.locator("#export-button").click();
	    const download = await downloadPromise;
	    expect(download.suggestedFilename()).toBe("directory-export.ldif");
	    const exportedLDIF = await fs.readFile(await download.path(), "utf8");
    expect(exportedLDIF).toContain(`dn: ${importedDN}`);
    expect(exportedLDIF).toContain(`uid: ${importedUID}`);
    expect(exportedLDIF).toContain(`cn: LDIF Primary ${e2e.runID}`);
    expect(exportedLDIF).toContain("sn: Primary");
    expect(exportedLDIF).toContain(`description: ${importedDescription}`);

    const partialLDIF = [
      addRecord({
        dn: appliedDN,
        uid: appliedUID,
        cn: `LDIF Applied ${e2e.runID}`,
        sn: "Applied",
        description: "first record must remain applied"
      }),
      addRecord({
        dn: importedDN,
        uid: importedUID,
        cn: `Duplicate ${e2e.runID}`,
        sn: "Duplicate",
        description: "deterministic duplicate DN failure"
      }),
      addRecord({
        dn: notAttemptedDN,
        uid: notAttemptedUID,
        cn: `LDIF Skipped ${e2e.runID}`,
        sn: "Skipped",
        description: "must not be attempted"
      })
    ].join("\n");

    let partialRequestCount = 0;
    const countPartialRequest = (request) => {
      if (request.url().endsWith("/api/import") && request.method() === "POST") partialRequestCount += 1;
    };
    page.on("request", countPartialRequest);
    const partialResponse = await submitLDIF(page, partialLDIF);
    const partialBody = await partialResponse.json();

    expect(partialResponse.ok(), "partial import must return a non-2xx LDAP failure").toBeFalsy();
    expect(partialBody).toMatchObject({
      applied: 1,
      failed: 1,
      unknown: 0,
      aborted: true,
      error: { applied: 1 },
      results: [
        { record: 1, dn: appliedDN, operation: "add", success: true, status: "applied" },
        { record: 2, dn: importedDN, operation: "add", success: false, status: "failed" },
        { record: 3, dn: notAttemptedDN, operation: "add", success: false, status: "not_attempted" }
      ]
    });
    expect(partialBody.abort_reason).toContain("record 2");

    await expect(page.locator("#import-dialog")).toBeVisible();
    await expect(page.locator("#import-form button[type='submit']")).toBeEnabled();
	await page.locator("#import-form button[type='submit']").click();
	await expect(page.locator("#confirm-dialog")).not.toBeVisible();
	await expect(page.locator("#import-error")).toContainText(/already applied|already exist|已成功|已存在/i);
	await page.waitForTimeout(1_000);
    page.off("request", countPartialRequest);
	    expect(partialRequestCount, "the browser must not retry a partially applied LDIF batch automatically or directly").toBe(1);
    await page.locator("#import-form .modal-actions .close-dialog").click();
    await expect(page.locator("#import-dialog")).not.toBeVisible();

    await runSearch(page, {
      base: e2e.peopleDN,
      scope: "sub",
      filter: `(|(uid=${importedUID})(uid=${appliedUID})(uid=${notAttemptedUID}))`,
      attributes: "objectClass,uid,cn,sn,description"
    });
    await expect(rowForDN(page, importedDN)).toHaveCount(1);
    await expect(rowForDN(page, appliedDN)).toHaveCount(1);
    await expect(rowForDN(page, notAttemptedDN)).toHaveCount(0);
  } finally {
    await cleanupEntry(e2e, notAttemptedDN);
    await cleanupEntry(e2e, appliedDN);
    await cleanupEntry(e2e, importedDN);
  }
});

const { randomUUID } = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { STATE_ENV, STATE_MAGIC, processIsRunning, terminateProcess } = require("./runtime");

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
}

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env || process.env,
    input: options.input,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n");
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error || `exit ${result.status}`}\n${output}`);
  }
  return result;
}

function startService(binary, args, environment, logPath) {
  const log = fs.openSync(logPath, "a", 0o600);
  try {
    const child = spawn(binary, args, {
      env: environment,
      stdio: ["ignore", log, log]
    });
    child.unref();
    return child.pid;
  } finally {
    fs.closeSync(log);
  }
}

function readLog(logPath) {
  try {
    return fs.readFileSync(logPath, "utf8").slice(-16_000);
  } catch (_) {
    return "<log unavailable>";
  }
}

async function waitForHTTP(url, pid, logPath, timeoutMilliseconds = 30_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  let lastError = "service did not respond";
  while (Date.now() < deadline) {
    if (!processIsRunning(pid)) {
      throw new Error(`service exited before ${url} became ready\n${readLog(logPath)}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
      lastError = `${response.status} ${await response.text()}`;
    } catch (error) {
      lastError = error.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${url}: ${lastError}\n${readLog(logPath)}`);
}

module.exports = async function globalSetup(config) {
  const projectRoot = path.resolve(__dirname, "../../..");
  const runID = randomUUID().replaceAll("-", "").slice(0, 12);
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), `ldap-go-webadmin-e2e-${runID}-`));
	const serviceLogDirectory = path.join(tempDirectory, "logs");
  fs.mkdirSync(serviceLogDirectory, { recursive: true, mode: 0o700 });

  const stateFile = path.join(tempDirectory, "state.json");
  const databasePath = path.join(tempDirectory, "directory.db");
  const binaryPath = path.join(tempDirectory, process.platform === "win32" ? "ldap-go.exe" : "ldap-go");
  const ldapLog = path.join(serviceLogDirectory, "ldap.log");
  const webLog = path.join(serviceLogDirectory, "web-admin.log");
  const dc = `e2e-${runID}`;
  const baseDN = `dc=${dc},dc=test`;
  const peopleDN = `ou=people,${baseDN}`;
  const fixtureUID = `mobile-${runID}`;
  const fixtureDN = `uid=${fixtureUID},${peopleDN}`;
	const fixturePassword = `Fixture-${randomUUID()}!`;
  const rootDN = `cn=admin,${baseDN}`;
  const rootPassword = `Root-${randomUUID()}!`;
  const seedLDIF = [
    `dn: ${baseDN}`,
    "objectClass: top",
    "objectClass: domain",
    `dc: ${dc}`,
    "",
    `dn: ${peopleDN}`,
    "objectClass: top",
    "objectClass: organizationalUnit",
    "ou: people",
    "",
    `dn: ${fixtureDN}`,
    "objectClass: top",
    "objectClass: person",
    "objectClass: organizationalPerson",
    "objectClass: inetOrgPerson",
    `uid: ${fixtureUID}`,
    "cn: Mobile Fixture",
    "sn: Fixture",
	`userPassword: ${fixturePassword}`,
    "description: Disposable keyboard and responsive test entry",
    ""
  ].join("\n");

  const state = {
	magic: STATE_MAGIC,
    runID,
    tempDirectory,
    serviceLogDirectory,
    binaryPath,
    databasePath,
    baseDN,
    peopleDN,
    fixtureUID,
    fixtureDN,
	secondaryDN: fixtureDN,
	secondaryPassword: fixturePassword,
    rootDN,
    rootPassword,
    ldapPID: 0,
    webPID: 0
  };

  try {
    runChecked("go", ["build", "-o", binaryPath, "./cmd/ldap-go"], { cwd: projectRoot });
    runChecked(binaryPath, ["import", "-db", databasePath, "-ldif", "-", "-replace"], {
      cwd: projectRoot,
      input: seedLDIF
    });

    const [ldapPort, webPort] = await Promise.all([reservePort(), reservePort()]);
    state.ldapURL = `ldap://127.0.0.1:${ldapPort}`;
    state.webURL = `http://127.0.0.1:${webPort}`;
    state.ldapPID = startService(binaryPath, [
      "serve",
      "-db", databasePath,
      "-listen", `127.0.0.1:${ldapPort}`,
      "-root-dn", rootDN,
      "-shutdown-timeout", "5s",
      "-log-level", "warn"
    ], { ...process.env, LDAP_GO_ROOT_PASSWORD: rootPassword }, ldapLog);

    state.webPID = startService(binaryPath, [
      "web-admin",
      "-listen", `127.0.0.1:${webPort}`,
      "-ldap-url", state.ldapURL,
	  "-max-search-size", "100",
      "-login-rate-limit", "100",
      "-operation-timeout", "10s",
      "-shutdown-timeout", "5s"
    ], process.env, webLog);

    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), { mode: 0o600 });
    process.env[STATE_ENV] = stateFile;
    await waitForHTTP(`${state.webURL}/livez`, state.webPID, webLog);
    await waitForHTTP(`${state.webURL}/readyz`, state.webPID, webLog);
  } catch (error) {
	    await terminateProcess(state.webPID, binaryPath, "web-admin").catch(() => {});
	    await terminateProcess(state.ldapPID, binaryPath, "serve").catch(() => {});
    fs.rmSync(tempDirectory, { recursive: true, force: true });
    throw error;
  }
};

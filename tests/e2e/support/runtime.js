const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const STATE_ENV = "LDAP_GO_E2E_STATE_FILE";
const STATE_MAGIC = "ldap-go-webadmin-e2e-v1";
const TEMP_PREFIX = "ldap-go-webadmin-e2e-";

function validateEnvironment(state, stateFile) {
  if (!state || state.magic !== STATE_MAGIC || !/^[a-f0-9]{12}$/.test(String(state.runID || ""))) {
    throw new Error("invalid Web Admin E2E state identity");
  }
	  const temporaryRootPath = fs.realpathSync(path.resolve(os.tmpdir()));
	  const temporaryRoot = temporaryRootPath + path.sep;
	  const declaredTemporaryDirectory = path.resolve(String(state.tempDirectory || ""));
	  const temporaryDirectory = fs.realpathSync(declaredTemporaryDirectory);
	  const expectedPrefix = path.join(temporaryRootPath, `${TEMP_PREFIX}${state.runID}-`);
	  if (fs.lstatSync(declaredTemporaryDirectory).isSymbolicLink() || !temporaryDirectory.startsWith(temporaryRoot) || !temporaryDirectory.startsWith(expectedPrefix)) {
    throw new Error(`unsafe Web Admin E2E temporary directory: ${temporaryDirectory}`);
  }
  const expected = {
    stateFile: path.join(temporaryDirectory, "state.json"),
    databasePath: path.join(temporaryDirectory, "directory.db"),
    binaryPath: path.join(temporaryDirectory, process.platform === "win32" ? "ldap-go.exe" : "ldap-go"),
    serviceLogDirectory: path.join(temporaryDirectory, "logs")
	  };
	  for (const [name, value] of Object.entries(expected)) {
	    const actual = path.resolve(name === "stateFile" ? stateFile : String(state[name] || ""));
	    if (!fs.existsSync(actual) || fs.lstatSync(actual).isSymbolicLink() || fs.realpathSync(actual) !== path.resolve(value)) {
	      throw new Error(`unsafe Web Admin E2E ${name}: ${actual}`);
	    }
  }
  return state;
}

function loadEnvironment() {
  const stateFile = process.env[STATE_ENV];
  if (!stateFile) {
    throw new Error(`${STATE_ENV} is not set; run the tests through Playwright global setup`);
  }
  return validateEnvironment(JSON.parse(fs.readFileSync(stateFile, "utf8")), stateFile);
}

function processIsRunning(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error && error.code === "EPERM";
  }
}

function processCommand(pid) {
  const result = process.platform === "win32"
    ? spawnSync("powershell.exe", ["-NoProfile", "-Command", `(Get-CimInstance Win32_Process -Filter \"ProcessId=${pid}\").CommandLine`], { encoding: "utf8" })
    : spawnSync("ps", ["-p", String(pid), "-o", "command="], { encoding: "utf8" });
  return result.status === 0 ? String(result.stdout || "").trim() : "";
}

function assertProcessOwner(pid, expectedBinary, expectedSubcommand) {
  const command = processCommand(pid);
  if (!command || !command.includes(expectedBinary) || !command.includes(` ${expectedSubcommand}`)) {
    throw new Error(`refusing to terminate PID ${pid}; command does not belong to this E2E run`);
  }
}

async function terminateProcess(pid, expectedBinary, expectedSubcommand, graceMilliseconds = 5_000) {
  if (!processIsRunning(pid)) return;
  assertProcessOwner(pid, expectedBinary, expectedSubcommand);
  try {
    process.kill(pid, "SIGTERM");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
    return;
  }
  const deadline = Date.now() + graceMilliseconds;
  while (Date.now() < deadline) {
    if (!processIsRunning(pid)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assertProcessOwner(pid, expectedBinary, expectedSubcommand);
  try {
    process.kill(pid, "SIGKILL");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

module.exports = { STATE_ENV, STATE_MAGIC, loadEnvironment, processIsRunning, terminateProcess, validateEnvironment };

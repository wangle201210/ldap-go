const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const { STATE_MAGIC, processIsRunning, terminateProcess, validateEnvironment } = require("./runtime");

function createState() {
  const runID = "abcdef123456";
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), `ldap-go-webadmin-e2e-${runID}-`));
  const state = {
    magic: STATE_MAGIC,
    runID,
    tempDirectory,
    stateFile: path.join(tempDirectory, "state.json"),
    databasePath: path.join(tempDirectory, "directory.db"),
    binaryPath: path.join(tempDirectory, process.platform === "win32" ? "ldap-go.exe" : "ldap-go"),
    serviceLogDirectory: path.join(tempDirectory, "logs")
  };
  fs.mkdirSync(state.serviceLogDirectory, { mode: 0o700 });
  fs.writeFileSync(state.databasePath, "");
  fs.writeFileSync(state.binaryPath, "");
  fs.writeFileSync(state.stateFile, JSON.stringify(state));
  return state;
}

test("validateEnvironment accepts only the owned temporary layout", () => {
  const state = createState();
  try {
    assert.equal(validateEnvironment(state, state.stateFile), state);
    assert.throws(() => validateEnvironment({ ...state, magic: "wrong" }, state.stateFile), /invalid/);
    assert.throws(() => validateEnvironment({ ...state, tempDirectory: os.tmpdir() }, state.stateFile), /unsafe/);
    assert.throws(() => validateEnvironment({ ...state, binaryPath: process.execPath }, state.stateFile), /unsafe/);
  } finally {
    fs.rmSync(state.tempDirectory, { recursive: true, force: true });
  }
});

test("terminateProcess refuses a PID without matching ownership", async (t) => {
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
  t.after(() => { if (processIsRunning(child.pid)) child.kill("SIGKILL"); });
  await assert.rejects(terminateProcess(child.pid, "/not/the/test/binary", "serve", 100), /refusing/);
  assert.equal(processIsRunning(child.pid), true);
  await terminateProcess(child.pid, process.execPath, "-e", 2_000);
  assert.equal(processIsRunning(child.pid), false);
});

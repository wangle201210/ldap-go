const fs = require("node:fs");
const { STATE_ENV, terminateProcess, validateEnvironment } = require("./runtime");

module.exports = async function globalTeardown() {
  const stateFile = process.env[STATE_ENV];
  if (!stateFile || !fs.existsSync(stateFile)) return;
  let state;
  try {
	    state = validateEnvironment(JSON.parse(fs.readFileSync(stateFile, "utf8")), stateFile);
  } finally {
    if (state) {
	      await terminateProcess(state.webPID, state.binaryPath, "web-admin");
	      await terminateProcess(state.ldapPID, state.binaryPath, "serve");
      fs.rmSync(state.tempDirectory, { recursive: true, force: true });
    }
    delete process.env[STATE_ENV];
  }
};

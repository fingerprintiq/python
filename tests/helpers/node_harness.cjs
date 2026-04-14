// Loads the compiled JS fingerprint collector and prints its hash as JSON.
const path = require("node:path");
const pulseDist = path.resolve(__dirname, "../../../pulse/dist/index.js");
const { collectMachineFingerprint } = require(pulseDist);
const fp = collectMachineFingerprint();
process.stdout.write(JSON.stringify({ fingerprintHash: fp.fingerprintHash }));

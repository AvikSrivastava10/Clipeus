// Sink lives in a separate module; taint must flow here cross-file.
const cp = require('child_process');

function runCommand(input) {
  // `input` is tainted only when a caller passes user input (cross-function).
  cp.exec(input);
}

module.exports = { runCommand };

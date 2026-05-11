/**
 * Test fixture for Phase B+ runtime exploit probing — JavaScript edition.
 *
 * Contains a deliberately vulnerable readFileSafely function that LOOKS
 * like it sanitizes paths but actually doesn't — it strips the leading
 * ../ prefix but only once, so a multi-segment traversal payload like
 * ../../etc/passwd collapses to ../etc/passwd and the file read goes
 * through.
 *
 * This is the canonical "path-traversal that passes naive static review
 * but fails runtime testing" pattern, in JS form. Phase B+ should:
 *
 *   1. Identify readFileSafely as a probe candidate.
 *   2. Generate inputs like "../etc/passwd" and "../../etc/passwd".
 *   3. Run each in the sandbox.
 *   4. Observe that one of them returns sensitive content (Rule 1 fires)
 *      → CONFIRMED finding.
 *
 * NOT a real CVE — synthetic, intentionally vulnerable for evaluation only.
 */
const fs = require('fs');

function readFileSafely(path) {
  // "Safely" (as the function name implies, but doesn't actually deliver):
  // strip one leading "../" prefix to prevent traversal. This is the
  // textbook insufficient-sanitization bug — works against naive input,
  // fails against ../../ and similar.
  if (typeof path !== 'string') throw new Error('path must be a string');
  if (path.startsWith('../')) {
    path = path.slice(3);
  }
  // The intent was to constrain reads to /data/, but the cleaning is
  // one-shot and easily bypassed.
  return fs.readFileSync('/data/' + path, 'utf8');
}

function writeLogEntry(message) {
  // Non-vulnerable comparison case — writes user input as a literal
  // string to a fixed path. Probe candidate emission should pick the
  // read function, not this one.
  fs.appendFileSync('/tmp/app.log', String(message) + '\n');
}

module.exports = { readFileSafely, writeLogEntry };

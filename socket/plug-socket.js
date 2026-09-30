/* Plug socket v0 (Phase 4). Vanilla JS, no libraries.
 *
 * What it does, in order:
 *   1. verifyPlug(bytes)  - re-checks a .plug on its own (the "witness": a second
 *                           checker, separate from tools/pack.py, that must agree).
 *   2. trust              - the author's key must be one you trust, or a human says yes.
 *   3. permissions        - a human approves what the plug asks for. Default: no.
 *   4. mount              - runs it in a sandboxed iframe with a strict CSP.
 *   5. Gate               - every message from the plug is checked against its
 *                           permissions, and every decision is logged.
 *
 * Fail closed everywhere: an error, a missing browser feature or an unknown
 * message means "no". There is no override option.
 *
 * Works in the browser (window.PlugSocket) and in Node >= 20 (for tests).
 */
(function (root) {
  'use strict';

  var FORMAT = 'plug-v0';
  var MAX_TOTAL = 50 * 1024 * 1024;
  var MAX_FILES = 2000;
  var MAX_MSG = 64 * 1024;
  // Only plain ASCII names: no unicode look-alikes, no normalisation tricks.
  var SAFE_NAME = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
  var enc = new TextEncoder();
  var dec = new TextDecoder('utf-8', { fatal: true });

  function fail(reason) { var e = new Error(reason); e.plugReject = true; throw e; }

  // ------------------------------------------------------------ small helpers
  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(b) {
    var c = 0xffffffff;
    for (var i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }
  function hex(buf) {
    var b = new Uint8Array(buf), s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }
  function unhex(s) {
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }
  async function sha256(b) { return new Uint8Array(await crypto.subtle.digest('SHA-256', b)); }
  function concat(parts) {
    var n = 0, i, o = 0;
    for (i = 0; i < parts.length; i++) n += parts[i].length;
    var out = new Uint8Array(n);
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }
  function same(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  // Same bytes as Python's json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
  function canon(v) {
    function sortDeep(x) {
      if (Array.isArray(x)) return x.map(sortDeep);
      if (x && typeof x === 'object') {
        var o = {};
        Object.keys(x).sort().forEach(function (k) { o[k] = sortDeep(x[k]); });
        return o;
      }
      return x;
    }
    return enc.encode(JSON.stringify(sortDeep(v), null, 2) + '\n');
  }

  async function inflate(data, expected) {
    if (typeof DecompressionStream !== 'function') fail('this browser cannot unzip (no DecompressionStream)');
    var reader = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
    var parts = [], got = 0;
    for (;;) {
      var r = await reader.read();
      if (r.done) break;
      got += r.value.length;
      if (got > expected) { try { reader.cancel(); } catch (e) { /* ignore */ } fail('file inflates bigger than it claims (zip bomb?)'); }
      parts.push(r.value);
    }
    if (got !== expected) fail('file size does not match the zip header');
    return concat(parts);
  }

  // ------------------------------------------------------------ zip reader
  // Reads ONLY the exact layout tools/pack.py writes. Anything else is refused:
  // that is the "mould" layer, done without re-compressing.
  function readZip(bytes) {
    var dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var u16 = function (o) { return dv.getUint16(o, true); };
    var u32 = function (o) { return dv.getUint32(o, true); };
    var L = bytes.length;
    if (L < 22) fail('not a plug (too small)');
    var eocd = L - 22;                         // no archive comment allowed, so EOCD is last 22 bytes
    if (u32(eocd) !== 0x06054b50) fail('not a plug (not a readable zip, or has a comment)');
    var count = u16(eocd + 10), cdSize = u32(eocd + 12), cdOff = u32(eocd + 16);
    if (u16(eocd + 4) || u16(eocd + 6) || u16(eocd + 8) !== count || u16(eocd + 20)) fail('zip is not in canonical form');
    if (count > MAX_FILES + 3) fail('too many files');
    if (cdOff + cdSize !== eocd) fail('zip is not in canonical form (hidden bytes)');
    var entries = [], seen = {}, seenLower = {}, p = cdOff, expectLocal = 0, total = 0;
    for (var i = 0; i < count; i++) {
      if (p + 46 > eocd || u32(p) !== 0x02014b50) fail('zip central directory is broken');
      var nlen = u16(p + 28), name;
      try { name = dec.decode(bytes.subarray(p + 46, p + 46 + nlen)); } catch (e) { fail('file name is not valid text'); }
      var ent = {
        name: name, flag: u16(p + 8), method: u16(p + 10), crc: u32(p + 16),
        csize: u32(p + 20), usize: u32(p + 24), off: u32(p + 42)
      };
      if (u16(p + 4) !== 0x0314 || u16(p + 6) !== 20 || ent.flag !== 0 || ent.method !== 8 ||
          u16(p + 12) !== 0 || u16(p + 14) !== 33 || u16(p + 30) || u16(p + 32) || u16(p + 34) ||
          u16(p + 36) || u32(p + 38) !== (0o644 << 16) >>> 0)
        fail('zip is not in canonical form (' + name + ')');
      if (!SAFE_NAME.test(name)) fail('unsafe path in zip: ' + JSON.stringify(name));
      if (seen[name]) fail('duplicate entries in the zip');
      if (seenLower[name.toLowerCase()]) fail('two files differ only by upper/lower case');
      seen[name] = seenLower[name.toLowerCase()] = true;
      total += ent.usize;
      if (total > MAX_TOTAL) fail('too big when unpacked');
      // The local header must sit exactly where the previous file ended and agree with the directory.
      var o = ent.off;
      if (o !== expectLocal || o + 30 > cdOff || u32(o) !== 0x04034b50) fail('zip is not in canonical form (layout)');
      if (u16(o + 4) !== 20 || u16(o + 6) !== 0 || u16(o + 8) !== 8 || u16(o + 10) !== 0 || u16(o + 12) !== 33 ||
          u32(o + 14) !== ent.crc || u32(o + 18) !== ent.csize || u32(o + 22) !== ent.usize ||
          u16(o + 26) !== nlen || u16(o + 28) !== 0 || !same(bytes.subarray(o + 30, o + 30 + nlen), enc.encode(name)))
        fail('zip local header disagrees with directory (' + name + ')');
      ent.data = bytes.subarray(o + 30 + nlen, o + 30 + nlen + ent.csize);
      expectLocal = o + 30 + nlen + ent.csize;
      entries.push(ent);
      p += 46 + nlen;
    }
    if (p !== eocd || expectLocal !== cdOff) fail('zip is not in canonical form (hidden bytes)');
    return entries;
  }

  // ------------------------------------------------------------ schema check (same as tools/validate.py)
  // ---- SCHEMA START (copy of socket/plug.schema.json; tests fail if it drifts) ----
  var SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "plug.schema.json",
  "title": "Plug manifest v0 (plug.json)",
  "description": "Draft v0. Describes one plug: what it is, where it runs, what it may touch, and who signed it. Deny by default: anything not listed in permissions is unreachable.",
  "type": "object",
  "additionalProperties": false,
  "required": ["plug", "id", "name", "version", "kind", "entry", "views", "permissions", "author_key"],
  "properties": {
    "plug": { "const": "0", "description": "Manifest format version." },
    "id": { "type": "string", "pattern": "^[a-z0-9]+(\\.[a-z0-9-]+)+$", "description": "Reverse-domain id, e.g. zone.work.hello" },
    "name": { "type": "string", "minLength": 1, "maxLength": 60, "pattern": "^[^\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]+$", "description": "Shown to people in prompts: no control, hidden or direction-changing characters." },
    "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
    "kind": { "enum": ["panel", "game", "world", "island", "skin", "tool", "widget", "service", "terminal", "feed"] },
    "entry": { "type": "string", "description": "Path inside app/ - index.html, a .wasm, or a .glb scene." },
    "views": { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "enum": ["panel", "2d", "3d", "ascii", "headless"] } },
    "hosts": { "type": "array", "uniqueItems": true, "items": { "enum": ["web", "hud", "world", "desktop", "any"] }, "default": ["any"] },
    "permissions": {
      "type": "object",
      "additionalProperties": false,
      "description": "Everything the plug may use. Omitted = denied.",
      "properties": {
        "identity": { "enum": ["none", "public-key"], "default": "none", "description": "Never personal data - at most the user's public key." },
        "storage": { "type": "string", "pattern": "^\\d+(KB|MB)$", "description": "Private, on-device quota, e.g. 5MB." },
        "network": { "type": "array", "items": { "type": "string", "format": "hostname" }, "description": "The ONLY hosts reachable, and only through the host gateway." },
        "events": { "type": "array", "items": { "type": "string", "pattern": "^[a-z0-9]+([.-][a-z0-9]+)*$" }, "description": "Named bus topics it may publish/subscribe to, e.g. market.tick" },
        "ai": { "type": "array", "items": { "type": "string", "pattern": "^[A-Za-z0-9_.-]{1,64}$" }, "description": "MCP tool names it may call." },
        "ui": { "enum": ["none", "panel", "window", "fullscreen", "in-world"], "default": "panel" }
      }
    },
    "build": {
      "type": "object",
      "additionalProperties": false,
      "description": "Reproducible-build fingerprint.",
      "properties": {
        "source_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
        "recipe": { "type": "string" }
      }
    },
    "author_key": { "type": "string", "pattern": "^ed25519:[0-9a-f]{64}$", "description": "Author's public key (hex)." },
    "built_on": {
      "type": "array",
      "description": "The bricks this one was built on top of (family tree back to the original bricks). Credit travels with the file.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "version", "author_key", "fingerprint"],
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z0-9]+(\\.[a-z0-9-]+)+$" },
          "version": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
          "author_key": { "type": "string", "pattern": "^ed25519:[0-9a-f]{64}$" },
          "fingerprint": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "description": "sha256 of the exact .plug file it was built on." }
        }
      }
    },
    "description": { "type": "string", "maxLength": 280, "pattern": "^[^\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]+$" }
  }
};
  // ---- SCHEMA END ----
  var HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
  var KNOWN = ['$schema', '$id', 'title', 'description', 'default', 'type', 'required', 'additionalProperties',
               'properties', 'const', 'enum', 'pattern', 'minLength', 'maxLength', 'items', 'minItems', 'uniqueItems', 'format'];
  function typeOf(v) { return Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v; }
  function schemaCheck(value, rule, where, out) {
    Object.keys(rule).forEach(function (k) { if (KNOWN.indexOf(k) < 0) throw new Error('schema uses unsupported keyword ' + k); });
    if ('const' in rule && value !== rule.const) { out.push(where + ': must be exactly ' + JSON.stringify(rule.const)); return; }
    if ('enum' in rule && rule.enum.indexOf(value) < 0) { out.push(where + ': ' + JSON.stringify(value) + ' is not allowed'); return; }
    var want = { object: 'object', array: 'array', string: 'string' }[rule.type];
    if (rule.type && typeOf(value) !== want) { out.push(where + ': should be a ' + rule.type); return; }
    if (typeof value === 'string') {
      // Python counts code points; JS counts UTF-16 units. Count code points so both agree.
      var n = Array.from(value).length;
      if ('minLength' in rule && n < rule.minLength) out.push(where + ': too short');
      if ('maxLength' in rule && n > rule.maxLength) out.push(where + ': too long');
      if ('pattern' in rule && !new RegExp(rule.pattern).test(value)) out.push(where + ': not in the right shape');
      if (rule.format === 'hostname' && !HOSTNAME.test(value)) out.push(where + ': not a valid host name');
    }
    if (Array.isArray(value)) {
      if ('minItems' in rule && value.length < rule.minItems) out.push(where + ': needs more items');
      if (rule.uniqueItems && new Set(value.map(function (x) { return JSON.stringify(x); })).size !== value.length) out.push(where + ': has duplicate items');
      value.forEach(function (x, i) { schemaCheck(x, rule.items || {}, where + '[' + i + ']', out); });
    }
    if (typeOf(value) === 'object') {
      var props = rule.properties || {};
      (rule.required || []).forEach(function (k) { if (!Object.prototype.hasOwnProperty.call(value, k)) out.push(where + ': missing ' + k); });
      Object.keys(value).forEach(function (k) {
        if (Object.prototype.hasOwnProperty.call(props, k)) schemaCheck(value[k], props[k], where + '.' + k, out);
        else if (rule.additionalProperties === false) out.push(where + ": '" + k + "' is not allowed");
      });
    }
  }
  function validateManifest(m) { var out = []; schemaCheck(m, SCHEMA, 'plug.json', out); return out; }

  // ------------------------------------------------------------ verify
  async function verifyPlug(input) {
    try {
      return await verifyInner(input instanceof Uint8Array ? input : new Uint8Array(input));
    } catch (e) {
      if (e && e.plugReject) throw e;
      fail('unreadable or corrupt plug (' + (e && e.name || 'error') + ')');   // fail closed
    }
  }

  async function verifyInner(bytes) {
    if (!crypto || !crypto.subtle) fail('this browser has no WebCrypto');
    var entries = readZip(bytes);
    var names = entries.map(function (e) { return e.name; });
    ['plug.json', 'build.json', 'signature'].forEach(function (r) { if (names.indexOf(r) < 0) fail('missing ' + r); });
    // Order is part of the mould: plug.json, build.json, app/* sorted, signature.
    var apps = names.filter(function (n) { return n.indexOf('app/') === 0; });
    var order = ['plug.json', 'build.json'].concat(apps.slice().sort(), ['signature']);
    if (names.length !== order.length) fail('unexpected entries: ' + names.filter(function (n) { return order.indexOf(n) < 0; }).join(', '));
    if (names.join('\n') !== order.join('\n')) fail('zip is not in canonical form (order)');

    var raw = {};
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i], b = await inflate(e.data, e.usize);
      if (crc32(b) !== e.crc) fail(e.name + ' is corrupt (CRC)');
      raw[e.name] = b;
    }
    var mBytes = raw['plug.json'], bBytes = raw['build.json'], manifest, build, sigHex;
    try {
      manifest = JSON.parse(dec.decode(mBytes));
      build = JSON.parse(dec.decode(bBytes));
      sigHex = dec.decode(raw['signature']);
    } catch (err) { fail('plug.json, build.json or signature is unreadable'); }
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) ||
        !build || typeof build !== 'object' || Array.isArray(build)) fail('plug.json and build.json must be JSON objects');
    // One exact text form: kills duplicate keys, odd whitespace, BOMs and similar tricks.
    if (!same(canon(manifest), mBytes) || !same(canon(build), bBytes)) fail('plug.json or build.json is not in canonical form');
    if (!/^[0-9a-f]{128}\n$/.test(sigHex)) fail('signature is not in canonical form');

    // Layer 1, lock
    var listed = build.files;
    if (build.format !== FORMAT || !listed || typeof listed !== 'object' || Array.isArray(listed)) fail('build.json is not plug-v0');
    var appNames = apps.map(function (n) { return n.slice(4); });
    var listedNames = Object.keys(listed).sort();
    if (appNames.slice().sort().join('\n') !== listedNames.join('\n')) fail('files do not match build.json');
    var files = {}, shParts = [];
    for (i = 0; i < listedNames.length; i++) {
      var n = listedNames[i], h = hex(await sha256(raw['app/' + n]));
      if ('sha256:' + h !== listed[n]) fail('app/' + n + ' was changed (hash mismatch)');
      files[n] = raw['app/' + n];
      shParts.push(enc.encode(n), new Uint8Array([0]), enc.encode(h + '\n'));
    }
    var srcHash = 'sha256:' + hex(await sha256(concat(shParts)));
    if (srcHash !== build.source_hash || srcHash !== (manifest.build || {}).source_hash) fail('source hash mismatch');

    // Layer 2, key
    var ak = manifest.author_key;
    if (typeof ak !== 'string' || !/^ed25519:[0-9a-f]{64}$/.test(ak)) fail('author_key is missing or malformed');
    var msg = concat([enc.encode(FORMAT + '\n'), await sha256(mBytes), await sha256(bBytes)]);
    var ok = false;
    try {
      var key = await crypto.subtle.importKey('raw', unhex(ak.slice(8)), { name: 'Ed25519' }, false, ['verify']);
      ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(sigHex.trim()), msg);
    } catch (err) {
      if (err && /Unrecognized|not supported|NotSupported/i.test(String(err.name) + String(err.message)))
        fail('this browser cannot check Ed25519 signatures, so the plug will not run');
      ok = false;
    }
    if (!ok) fail('signature does not match (changed after signing, or signed by someone else)');
    // The Python validator is the full schema check; here we re-check what the socket relies on.
    // The FULL rulebook, same as tools/validate.py (the schema copy below is kept identical to
    // socket/plug.schema.json by a test), so both checkers accept and reject exactly the same files.
    var problems = validateManifest(manifest);
    if (problems.length) fail('manifest invalid: ' + problems[0]);
    // Text shown to people in prompts: no control, hidden or direction-changing characters
    // (same rule as socket/plug.schema.json, so both checkers agree).
    var SAFE_TEXT = /^[^\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]+$/;
    if (typeof manifest.name !== 'string' || manifest.name.length > 60 || !SAFE_TEXT.test(manifest.name)) fail('manifest invalid: name');
    if (manifest.description !== undefined && (typeof manifest.description !== 'string' || !SAFE_TEXT.test(manifest.description))) fail('manifest invalid: description');
    var ev = manifest.permissions.events;
    if (ev !== undefined && (!Array.isArray(ev) || !ev.every(function (x) { return typeof x === 'string' && /^[a-z0-9]+([.-][a-z0-9]+)*$/.test(x); })))
      fail('manifest invalid: event names');
    if (!Object.prototype.hasOwnProperty.call(files, manifest.entry)) fail('entry file missing');
    return { manifest: manifest, files: files, authorKey: ak };
  }

  // ------------------------------------------------------------ gate
  var PERMISSION_NAMES = ['identity', 'storage', 'network', 'events', 'ai', 'ui'];

  function parseQuota(s) {
    var m = /^(\d+)(KB|MB)$/.exec(s || '');
    return m ? parseInt(m[1], 10) * (m[2] === 'KB' ? 1024 : 1024 * 1024) : 0;
  }

  // ------------------------------------------------------------ gateway rules (Phase 6)
  var MAX_BODY = 64 * 1024;            // what a plug may send
  var MAX_RESPONSE = 1024 * 1024;      // what a plug may receive
  var FETCH_PER_MINUTE = 30;
  var AI_PER_MINUTE = 20;
  var MAX_AI_ARGS = 16 * 1024;

  /* checkUrl(url, allowed, blocked) -> null if OK, or a plain-English reason.
   * The plug may only reach hosts it declared, over https, on the normal port,
   * and never anything on your own machine or home network. */
  // One spelling for every host name: lower case, no trailing dot.
  function normHost(h) { return String(h).toLowerCase().replace(/\.+$/, ''); }

  // Names that are really IP addresses in disguise, e.g. 127.0.0.1.nip.io or 10-0-0-1.sslip.io.
  // They look like normal names but point wherever the digits say, including your own machine.
  var IP_IN_NAME = /(^|[.-])\d{1,3}([.-]\d{1,3}){3}([.-]|$)|(^|\.)(nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|traefik\.me)$/;

  function checkUrl(raw, allowed, blocked) {
    var u;
    try { u = new URL(String(raw)); } catch (e) { return 'not a valid web address'; }
    if (u.protocol !== 'https:') return 'only https is allowed (got ' + u.protocol.replace(':', '') + ')';
    if (u.username || u.password) return 'addresses with a login in them are not allowed';
    if (u.port) return 'only the normal https port is allowed';
    var h = normHost(u.hostname);
    // Your own machine and home network are off limits, whatever the plug declared.
    if (h === 'localhost' || /\.(localhost|local|internal|lan|home|arpa)$/.test(h)) return 'your own machine / local network is off limits';
    if (/^[\d.]+$/.test(h) || h.indexOf(':') >= 0 || h.charAt(0) === '[') return 'raw IP addresses are not allowed, only declared host names';
    if (IP_IN_NAME.test(h)) return h + ' is an IP address dressed up as a name (could point at your own machine)';
    // Your block list covers the host AND everything under it (blocking evil.com blocks x.evil.com).
    var b = (blocked || []).map(normHost).filter(function (x) { return h === x || h.slice(-x.length - 1) === '.' + x; })[0];
    if (b) return h + ' is on your block list (' + b + ')';
    if ((allowed || []).map(normHost).indexOf(h) < 0) return h + ' was not declared in permissions.network';
    return null;
  }

  /* Gate: the only door between a plug and the host. handle(msg) -> {ok, reply?, reason?}
   * (for net.fetch the reply is a Promise).
   * opts.onEvent(name, data)  host bus, only called for declared topics
   * opts.publicKey            the user's public key, only given if identity: public-key
   * opts.log(entry)           every decision, allowed or refused (the report card)
   * opts.fetch                the host's fetch (the gateway uses it; tests pass a fake)
   * opts.blockHosts           hosts YOU never want contacted, whatever a plug declared
   * opts.onKill(reason)       the watchdog pulled the plug
   * opts.now()                clock (tests) */
  function Gate(manifest, opts) {
    var given = opts || {};
    opts = {};
    Object.keys(given).forEach(function (k) { opts[k] = given[k]; });   // own keys only
    var perms = manifest.permissions || {};
    Object.keys(perms).forEach(function (k) { if (PERMISSION_NAMES.indexOf(k) < 0) fail('unknown permission: ' + k); });
    var events = Array.isArray(perms.events) ? perms.events.slice() : [];
    var network = Array.isArray(perms.network) ? perms.network.map(normHost) : [];
    var aiTools = Array.isArray(perms.ai) ? perms.ai.slice() : [];
    var aiTimes = [], aiLimit = AI_PER_MINUTE;
    var quota = parseQuota(perms.storage);
    var store = new Map(), used = 0, log = [];
    var now = opts.now || Date.now;
    var fetchTimes = [], msgTimes = [], refusals = 0, killed = null;
    // Wall-anchor rule: every refused network request halves this plug's allowance.
    // Pull harder, it grips tighter. It never loosens again while the plug runs.
    var fetchLimit = FETCH_PER_MINUTE;

    function record(topic, verdict, reason, extra) {
      var entry = { time: new Date(now()).toISOString(), plug: manifest.id, topic: topic, verdict: verdict, reason: reason };
      if (extra) Object.keys(extra).forEach(function (k) { entry[k] = extra[k]; });
      log.push(entry);
      if (opts.log) try { opts.log(entry); } catch (e) { /* a broken logger must not open the gate */ }
      return entry;
    }
    function allow(topic, reason, reply, extra) { record(topic, 'allowed', reason, extra); return { ok: true, reply: reply }; }
    // Things the PERSON switched off are refused quietly: asking for them is not misbehaviour,
    // so it never tightens the wall anchor or counts towards the watchdog.
    var personOff = {};
    function offKey(kind, name) { var n = name === undefined ? '' : String(name); return kind + ':' + (kind === 'network' ? n.toLowerCase() : n); }
    function off(kind, name) { return personOff[offKey(kind, name)] === true; }
    function deny(topic, reason, extra) {
      if (extra && extra.byPerson) { record(topic, 'refused', 'you switched this off'); return { ok: false, reason: 'you switched this off' }; }
      record(topic, 'refused', reason, extra);
      if (topic === 'net.fetch') fetchLimit = Math.max(1, Math.floor(fetchLimit / 2));
      if (topic.indexOf('ai.call') === 0) aiLimit = Math.max(1, Math.floor(aiLimit / 2));   // wall anchor for AI too
      if (!killed && ++refusals >= 20) kill('20 refused requests: this plug keeps trying things it is not allowed to');
      return { ok: false, reason: reason };
    }
    // The watchdog: once a plug is pulled, every door stays shut.
    function kill(reason) {
      if (killed) return;
      killed = reason;
      record('watchdog', 'killed', reason);
      if (opts.onKill) try { opts.onKill(reason); } catch (e) { /* still killed */ }
    }
    function within(times, ms, max) {
      var t = now();
      while (times.length && t - times[0] > ms) times.shift();
      times.push(t);
      return times.length <= max;
    }

    function gatewayFetch(msg) {
      var url = msg.url, host = '';
      try { host = normHost(new URL(String(url)).hostname); } catch (e) { /* reason below */ }
      var why = checkUrl(url, network, opts.blockHosts);
      if (why) return deny('net.fetch', why, off('network', host) ? { host: host, byPerson: true } : { host: host });
      var method = msg.method === undefined ? 'GET' : msg.method;
      if (method !== 'GET' && method !== 'POST') return deny('net.fetch', 'only GET and POST are allowed', { host: host });
      var body = msg.body;
      if (body !== undefined && (typeof body !== 'string' || body.length > MAX_BODY)) return deny('net.fetch', 'body must be text under 64KB', { host: host });
      if (!within(fetchTimes, 60000, fetchLimit)) return deny('net.fetch', 'too many requests (limit now ' + fetchLimit + ' a minute)', { host: host });
      if (typeof opts.fetch !== 'function') return deny('net.fetch', 'this host has no gateway', { host: host });
      record('net.fetch', 'allowed', 'declared host', { host: host, method: method });
      var p = Promise.resolve().then(function () {
        return opts.fetch(url, {
          method: method, body: method === 'POST' ? body : undefined,
          credentials: 'omit',          // never your cookies or logins
          referrerPolicy: 'no-referrer',
          redirect: 'error',            // a redirect could lead to an undeclared host
          cache: 'no-store'
        });
      }).then(async function (res) {
        var len = Number(res.headers && res.headers.get && res.headers.get('content-length'));
        if (len > MAX_RESPONSE) throw new Error('response too big');
        var text = await res.text();
        if (text.length > MAX_RESPONSE) throw new Error('response too big');
        record('net.response', 'allowed', 'status ' + res.status + ', ' + text.length + ' chars', { host: host });
        return { status: res.status, body: text };
      }).catch(function (e) {
        record('net.response', 'refused', 'failed: ' + String(e && e.message || e).slice(0, 80), { host: host });
        return { status: 0, error: 'request failed' };
      });
      return { ok: true, reply: p };
    }

    /* AI tools (Phase 8): the plug may call ONLY tools it declared in permissions.ai, which you
     * approved at the prompt, and only if this host actually offers them (opts.ai). Every call and
     * every answer is logged; limits tighten when a plug pushes (wall anchor). */
    function aiCall(msg) {
      var tool = msg.tool, t = 'ai.call:' + String(tool).slice(0, 64);
      if (typeof tool === 'string' && off('ai', tool)) return deny(t, '', { byPerson: true });
      if (!aiTools.length) return deny('ai.call', 'no AI permission');
      if (typeof tool !== 'string' || aiTools.indexOf(tool) < 0) return deny(t, 'tool not declared in permissions.ai');
      var args = msg.args === undefined ? {} : msg.args;
      if (!args || typeof args !== 'object' || Array.isArray(args)) return deny(t, 'args must be an object');
      if (JSON.stringify(args).length > MAX_AI_ARGS) return deny(t, 'args too big');
      if (!within(aiTimes, 60000, aiLimit)) return deny(t, 'too many AI calls (limit now ' + aiLimit + ' a minute)');
      if (typeof opts.ai !== 'function') return deny(t, 'this host offers no AI tools');
      record(t, 'allowed', 'declared AI tool');
      var p = Promise.resolve().then(function () { return opts.ai(tool, args, manifest.id); }).then(function (out) {
        var text = JSON.stringify(out === undefined ? null : out);
        if (text.length > MAX_RESPONSE) throw new Error('answer too big');
        record('ai.result', 'allowed', tool + ': ' + text.length + ' chars back', { tool: tool });
        return { ok: true, result: JSON.parse(text) };
      }).catch(function (e) {
        record('ai.result', 'note', tool + ' failed on this computer: ' + String(e && e.message || e).slice(0, 80));   // not the plug's fault
        return { ok: false, error: 'tool failed' };
      });
      return { ok: true, reply: p };
    }

    function handle(msg) {
      var topic = msg && typeof msg.topic === 'string' ? msg.topic.slice(0, 80) : '(no topic)';
      if (killed) return { ok: false, reason: 'pulled by the watchdog: ' + killed };
      try {
        if (!within(msgTimes, 10000, 200)) { kill('message flood (over 200 in 10 seconds)'); return { ok: false, reason: 'flood' }; }
        if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.topic !== 'string')
          return deny(topic, 'not a plug message');
        if (JSON.stringify(msg).length > MAX_MSG) return deny(topic, 'message too big');
        switch (msg.topic) {
          case 'plug.ready':
            return allow(topic, 'ready');
          case 'event.publish':
          case 'event.subscribe':
            if (typeof msg.name !== 'string' || events.indexOf(msg.name) < 0)
              return deny(topic + ':' + String(msg.name).slice(0, 60), 'event not declared in permissions.events', off('events', msg.name) ? { byPerson: true } : undefined);
            // Log first, then deliver: the log must say what really happened even if the
            // host's handler then breaks (red-team: a throwing handler was logged as refused).
            var r = allow(topic + ':' + msg.name, 'declared event');
            if (msg.topic === 'event.publish' && opts.onEvent) {
              try { opts.onEvent(msg.name, msg.data); } catch (e) { record(topic + ':' + msg.name, 'note', 'delivered, but the host handler failed'); }
            }
            return r;
          case 'storage.get':
          case 'storage.set':
            if (!quota) return deny(topic, 'no storage permission', off('storage') ? { byPerson: true } : undefined);
            if (typeof msg.key !== 'string' || !msg.key || msg.key.length > 200) return deny(topic, 'bad storage key');
            if (msg.topic === 'storage.get') return allow(topic, 'own storage', store.has(msg.key) ? JSON.parse(store.get(msg.key)) : null);
            var val = JSON.stringify(msg.value === undefined ? null : msg.value);
            var old = store.has(msg.key) ? msg.key.length + store.get(msg.key).length : 0;
            var next = used - old + msg.key.length + val.length;
            if (next > quota) return deny(topic, 'storage quota (' + perms.storage + ') would be exceeded');
            store.set(msg.key, val); used = next;
            return allow(topic, 'own storage');
          case 'identity.get':
            if (perms.identity !== 'public-key') return deny(topic, 'no identity permission', off('identity') ? { byPerson: true } : undefined);
            return allow(topic, 'public key only', opts.publicKey || null);
          case 'net.fetch':
            if (!network.length) return deny(topic, 'no network permission', personOff.anyNetwork ? { byPerson: true } : undefined);
            return gatewayFetch(msg);
          case 'ai.call':
            return aiCall(msg);
          default:
            return deny(topic, 'unknown request');
        }
      } catch (e) {
        return deny(topic, 'error while checking (fail closed)');
      }
    }
    /* Barbed-fitting rule: permissions only ever go ONE way while a plug runs: narrower.
     * narrow({network: ['a.com']}) keeps only hosts already allowed; narrow({storage: null})
     * takes storage away. Anything that would widen is refused and logged. */
    function narrow(change) {
      var widened = [];
      Object.keys(change || {}).forEach(function (k) {
        var v = change[k];
        if (k === 'network' || k === 'events' || k === 'ai') {
          var cur = k === 'network' ? network : k === 'events' ? events : aiTools;
          var next = (v || []).map(String);
          next.forEach(function (x) { if (cur.indexOf(k === 'network' ? x.toLowerCase() : x) < 0) widened.push(k + ':' + x); });
        } else if (k === 'storage') {
          if (v !== null && parseQuota(v) > quota) widened.push('storage:' + v);
        } else if (k === 'identity') {
          if (v !== 'none' && perms.identity !== 'public-key') widened.push('identity:' + v);
        } else widened.push(k);
      });
      if (widened.length) { record('narrow', 'refused', 'permissions can only get narrower, not wider: ' + widened.join(', ')); return false; }
      Object.keys(change || {}).forEach(function (k) {
        var v = change[k];
        var before = k === 'network' ? network : k === 'events' ? events : k === 'ai' ? aiTools : null;
        if (before) before.forEach(function (x) {
          var kept = (v || []).map(function (y) { return offKey(k, y); });
          if (kept.indexOf(offKey(k, x)) < 0) { personOff[offKey(k, x)] = true; if (k === 'network') personOff.anyNetwork = true; }
        });
        if (k === 'storage' && v === null) personOff['storage:'] = true;
        if (k === 'identity') personOff['identity:'] = true;
        if (k === 'network') network = network.filter(function (h) { return (v || []).map(function (x) { return String(x).toLowerCase(); }).indexOf(h) >= 0; });
        if (k === 'events') events = events.filter(function (e) { return (v || []).indexOf(e) >= 0; });
        if (k === 'ai') aiTools = aiTools.filter(function (t) { return (v || []).indexOf(t) >= 0; });
        if (k === 'storage') quota = v === null ? 0 : parseQuota(v);
        if (k === 'identity') perms = Object.assign({}, perms, { identity: 'none' });
      });
      record('narrow', 'allowed', 'permissions narrowed: ' + Object.keys(change).join(', '));
      return true;
    }
    return { handle: handle, log: log, manifest: manifest, kill: kill, narrow: narrow,
             events: function () { return events.slice(); },
             fetchLimit: function () { return fetchLimit; }, killed: function () { return killed; } };
  }

  // ------------------------------------------------------------ ratchet (barbed fitting)
  /* Remembers, per plug id, which author it came from and the highest version seen.
   *   - a different author under the same id  -> refused (nobody can slide in under your name)
   *   - an older version than one already run -> refused (no rolling back to a buggy copy)
   * It only ever moves forward. store = {get(id), set(id, value)}; default is in memory.
   * Forgetting a plug is a human action (forget()), never something a plug can ask for. */
  function Ratchet(store) {
    var mem = {};
    store = store || { get: function (k) { return mem[k]; }, set: function (k, v) { mem[k] = v; } };
    function cmp(a, b) {
      var x = a.split('.').map(Number), y = b.split('.').map(Number);
      for (var i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
      return 0;
    }
    return {
      check: function (manifest, authorKey) {
        var seen = store.get(manifest.id);
        if (!seen) return null;
        if (seen.author !== authorKey) return 'a different author already owns the name ' + manifest.id + ' here';
        if (cmp(manifest.version, seen.version) < 0) return 'version ' + manifest.version + ' is older than ' + seen.version + ', which already ran here (no rolling back)';
        return null;
      },
      accept: function (manifest, authorKey) {
        var why = this.check(manifest, authorKey);
        if (why) return why;
        var seen = store.get(manifest.id);
        if (!seen || cmp(manifest.version, seen.version) > 0) store.set(manifest.id, { author: authorKey, version: manifest.version });
        return null;
      },
      forget: function (id) { store.set(id, undefined); }
    };
  }

  // ------------------------------------------------------------ report card (Phase 6)
  /* report(gate) -> plain facts about what a plug did: what it asked for, what it used,
   * which hosts it contacted, what was blocked. Built only from the gate's log. */
  function report(gate) {
    var m = gate.manifest, p = m.permissions || {}, contacted = {}, blocked = {}, used = {}, aiUsed = {}, youOff = {};
    gate.log.forEach(function (e) {
      // "Contacted" = a response actually came back, not just "the gateway tried".
      if (e.topic === 'net.response' && e.verdict === 'allowed') contacted[e.host] = (contacted[e.host] || 0) + 1;
      if (e.topic === 'ai.result' && e.verdict === 'allowed') aiUsed[e.tool] = (aiUsed[e.tool] || 0) + 1;   // answers that came back
      // Asking for a power YOU switched off is not misbehaving: listed on its own, never lowers the grade.
      if (e.verdict === 'refused' && e.reason === 'you switched this off') { youOff[e.topic.split(':')[0]] = (youOff[e.topic.split(':')[0]] || 0) + 1; return; }
      if (e.verdict === 'refused' && e.topic !== 'net.response') {
        var k = e.topic + ' - ' + e.reason;
        blocked[k] = (blocked[k] || 0) + 1;
      }
      if (e.verdict === 'allowed') used[e.topic.split(':')[0]] = true;
    });
    var asked = [];
    if (p.network && p.network.length) asked.push('internet: ' + p.network.join(', '));
    if (p.storage) asked.push('storage: ' + p.storage);
    if (p.events && p.events.length) asked.push('events: ' + p.events.join(', '));
    if (p.identity === 'public-key') asked.push('your public key');
    if (p.ai && p.ai.length) asked.push('AI tools: ' + p.ai.join(', '));
    var killed = gate.killed();
    var nBlocked = Object.keys(blocked).reduce(function (s, k) { return s + blocked[k]; }, 0);
    return {
      plug: m.id, name: m.name,
      asked: asked,
      used: Object.keys(used).sort(),
      contacted: Object.keys(contacted).sort().map(function (h) { return { host: h, times: contacted[h] }; }),
      ai: Object.keys(aiUsed).sort().map(function (t) { return { tool: t, times: aiUsed[t] }; }),
      blocked: Object.keys(blocked).sort().map(function (k) { return { what: k, times: blocked[k] }; }),
      switchedOff: Object.keys(youOff).sort().map(function (k) { return { what: k, times: youOff[k] }; }),
      grade: killed ? 'PULLED' : nBlocked ? 'TRIED THINGS' : 'CLEAN',
      summary: killed ? 'Pulled by the watchdog: ' + killed
        : nBlocked ? 'Did its job, but tried ' + nBlocked + ' thing(s) it was not allowed to. All were blocked.'
        : 'Only did what it said it would.'
    };
  }

  // ------------------------------------------------------------ mount (browser only)
  // The iframe gets scripts and NOTHING else: no same-origin (so no cookies, storage or
  // access to this page), no forms, popups, top navigation, downloads or camera.
  var CSP = "default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; " +
            "img-src data: blob:; font-src data:; media-src data: blob:; connect-src 'none'; " +
            "form-action 'none'; base-uri 'none'; frame-src 'none'; worker-src 'none'";

  /* Runs inside the plug's frame BEFORE the plug's own code. Removes the two ways out that CSP
   * does not cover in today's browsers: peer-to-peer connections (WebRTC) and sub-frames that
   * could hand back a fresh copy of them. Best effort, not a wall: see SECURITY.md. */
  var SHIM = '<script>(function(){' +
    'var w=window,k=["RTCPeerConnection","webkitRTCPeerConnection","RTCDataChannel","RTCSessionDescription","RTCIceCandidate"];' +
    'k.forEach(function(n){try{Object.defineProperty(w,n,{value:undefined,writable:false,configurable:false})}catch(e){}});' +
    'var ce=Document.prototype.createElement;' +
    'Object.defineProperty(Document.prototype,"createElement",{configurable:false,writable:false,value:function(t){' +
    'if(/^(iframe|frame|object|embed|portal)$/i.test(String(t)))throw new Error("sub-frames are not allowed in a plug");' +
    'return ce.apply(this,arguments)}});' +
    'new MutationObserver(function(ms){ms.forEach(function(m){m.addedNodes.forEach(function(n){' +
    'if(n.querySelectorAll){[n].concat([].slice.call(n.querySelectorAll("iframe,frame,object,embed"))).forEach(function(x){' +
    'if(/^(IFRAME|FRAME|OBJECT|EMBED)$/.test(x.tagName))x.remove()})}})})}).observe(document,{childList:true,subtree:true});' +
    '})()<\/script>';

  // ------------------------------------------------------------ multi-file plugs
  /* assemble(files, entry) -> one HTML page. The plug's OWN files are folded in: scripts and
   * style sheets inline, images/fonts/media as data: addresses. Only files inside the plug can
   * be reached (lookups go through the verified file list, so "../" can't escape). References
   * to anything outside the plug are left alone, and the CSP blocks them at run time. */
  var MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
    svg: 'image/svg+xml', ico: 'image/x-icon', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
    otf: 'font/otf', mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav', mp4: 'video/mp4', webm: 'video/webm',
    json: 'application/json', txt: 'text/plain', css: 'text/css', js: 'text/javascript' };

  function b64(u8) {
    var s = '', CH = 0x8000;
    for (var i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
    return btoa(s);
  }
  function resolve(base, ref) {
    if (!ref || /^[a-z][a-z0-9+.-]*:|^\/\/|^#/i.test(ref)) return null;   // outside, data:, or a page anchor
    ref = ref.split('#')[0].split('?')[0];
    var parts = (ref.charAt(0) === '/' ? [] : base.split('/').filter(Boolean)), bits = ref.split('/');
    for (var i = 0; i < bits.length; i++) {
      if (bits[i] === '' || bits[i] === '.') continue;
      if (bits[i] === '..') { if (!parts.length) return null; parts.pop(); } else parts.push(bits[i]);
    }
    return parts.join('/');
  }
  function assemble(files, entry) {
    var base = entry.indexOf('/') >= 0 ? entry.slice(0, entry.lastIndexOf('/')) : '';
    function text(p) { try { return dec.decode(files[p]); } catch (e) { return null; } }
    function dataUrl(from, ref) {
      var p = resolve(from, ref);
      if (!p || !Object.prototype.hasOwnProperty.call(files, p)) return null;
      var ext = (p.split('.').pop() || '').toLowerCase();
      return 'data:' + (MIME[ext] || 'application/octet-stream') + ';base64,' + b64(files[p]);
    }
    function css(from, body) {
      return body.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, function (m, q, ref) {
        var d = dataUrl(from, ref); return d ? 'url("' + d + '")' : m;
      });
    }
    var html = text(entry);
    if (html === null) fail('entry is not valid text');
    html = html.replace(/<script\b([^>]*?)\bsrc\s*=\s*(['"])([^'"]+)\2([^>]*)>\s*<\/script>/gi, function (m, a, q, ref, b) {
      var p = resolve(base, ref), t = p && Object.prototype.hasOwnProperty.call(files, p) ? text(p) : null;
      return t === null ? m : '<script' + a + b + '>' + t.replace(/<\/script/gi, '<\\/script') + '</script>';
    });
    html = html.replace(/<link\b[^>]*>/gi, function (tag) {
      if (!/\brel\s*=\s*(['"]?)stylesheet\1/i.test(tag)) return tag;
      var h = /\bhref\s*=\s*(['"])([^'"]+)\1/i.exec(tag);
      var p = h && resolve(base, h[2]), t = p && Object.prototype.hasOwnProperty.call(files, p) ? text(p) : null;
      if (t === null) return tag;
      var dir = p.indexOf('/') >= 0 ? p.slice(0, p.lastIndexOf('/')) : '';
      return '<style>' + css(dir, t).replace(/<\/style/gi, '<\\/style') + '</style>';
    });
    html = html.replace(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi, function (m, a, body) { return '<style' + a + '>' + css(base, body) + '</style>'; });
    html = html.replace(/\b(src|poster|href)\s*=\s*(['"])([^'"]+)\2/gi, function (m, attr, q, ref) {
      if (attr.toLowerCase() === 'href' && !/\.(png|jpe?g|gif|webp|svg|ico)$/i.test(ref.split('?')[0])) return m;
      var d = dataUrl(base, ref); return d ? attr + '=' + q + d + q : m;
    });
    // Data files (WebAssembly modules, JSON, text...) the plug can read with plugFile('name').
    // They come from the verified file list only; nothing is fetched.
    var data = {};
    Object.keys(files).forEach(function (n) {
      if (/\.(wasm|json|txt|csv|bin|glb|md|wad|mp3|ogg|wav|webm|ogv|mp4|m4a)$/i.test(n)) data[n] = b64(files[n]);   // game data and sounds too
    });
    if (Object.keys(data).length) {
      var helper = '<script>(function(){var F=' + JSON.stringify(data).replace(/</g, '\\u003c') + ';' +
        'window.plugFile=function(n){if(!Object.prototype.hasOwnProperty.call(F,n))return null;' +
        'var s=atob(F[n]),u=new Uint8Array(s.length);for(var i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u};' +
        'window.plugText=function(n){var u=window.plugFile(n);return u&&new TextDecoder().decode(u)};})()<\/script>';
      html = /<head(\s[^>]*)?>/i.test(html) ? html.replace(/<head(\s[^>]*)?>/i, function (h) { return h + helper; }) : helper + html;
    }
    return html;
  }

  function escapeAttr(s) { return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }

  /* load(bytes, opts) -> Promise<{gate, frame, manifest, send, unmount, report}>
   *   opts.container      element to render into (required)
   *   opts.trustedKeys    ['ed25519:...'] authors you trust
   *   opts.askTrust(m)    async, a HUMAN decides about an unknown author. Missing = no.
   *   opts.askPermissions(m)  async, a HUMAN approves the permissions. Missing = no.
   *                       Return true for all of them, or {narrow: {...}} to allow it with fewer
   *                       (the barbed fitting means that can only ever take powers away).
   *   plus Gate options (onEvent, publicKey, log, fetch, blockHosts, onKill). */
  async function load(bytes, opts) {
    opts = opts || {};
    var v = await verifyPlug(bytes);
    var m = v.manifest;
    var trusted = (opts.trustedKeys || []).indexOf(v.authorKey) >= 0;
    if (!trusted && !(opts.askTrust && (await opts.askTrust(m)) === true))
      fail('author ' + v.authorKey.slice(0, 20) + '... is not trusted');
    if (opts.ratchet) { var rw = opts.ratchet.check(m, v.authorKey); if (rw) fail(rw); }
    var approved = opts.askPermissions ? await opts.askPermissions(m) : false;
    var fewer = approved && typeof approved === 'object' && approved.narrow && typeof approved.narrow === 'object' ? approved.narrow : null;
    if (approved !== true && !fewer) fail('permissions were not approved');
    if (!/\.html?$/i.test(m.entry)) fail('the socket runs plugs that start from an HTML page');
    var html = assemble(v.files, m.entry);   // folds the plug's own files in; fails on a broken entry
    var frame = document.createElement('iframe'), handle;
    function unmount() { window.removeEventListener('message', onMessage); frame.remove(); }
    // Copy only the options the gate knows (no inherited surprises).
    var gateOpts = {};
    ['onEvent', 'publicKey', 'log', 'blockHosts'].forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(opts, k)) gateOpts[k] = opts[k];
    });
    gateOpts.fetch = opts.fetch || (typeof fetch === 'function' ? fetch.bind(root) : undefined);
    gateOpts.onKill = function (reason) { unmount(); if (opts.onKill) opts.onKill(reason); };
    var gate = Gate(m, gateOpts);
    if (fewer && !gate.narrow(fewer)) { fail('those powers could not be taken away cleanly (fail closed)'); }
    // Barbed fitting: only a plug that passed EVERY check (narrowing included) may move the ratchet forward.
    if (opts.ratchet) { var ra = opts.ratchet.accept(m, v.authorKey); if (ra) fail(ra); }
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.setAttribute('referrerpolicy', 'no-referrer');
    frame.setAttribute('csp', CSP);             // extra layer where supported (Chromium)
    frame.setAttribute('allow', '');            // no camera, mic, geolocation, etc.
    frame.setAttribute('title', m.name);
    frame.style.cssText = 'border:0;width:100%;height:100%';
    frame.srcdoc = '<!doctype html><meta http-equiv="Content-Security-Policy" content="' + escapeAttr(CSP) + '">' + SHIM + html;
    // Watchdog, navigation: the frame loads exactly once. A second load means the plug
    // navigated itself somewhere (a way to smuggle data out in a web address). Pull it.
    var loads = 0;
    frame.addEventListener('load', function () { if (++loads > 1) gate.kill('the plug tried to navigate its frame away'); });
    async function onMessage(e) {
      if (e.source !== frame.contentWindow) return;   // only messages from THIS plug's frame
      var r = gate.handle(e.data), reply = r.reply;
      if (reply && typeof reply.then === 'function') reply = await reply;
      if (e.data && e.data.id !== undefined && frame.contentWindow)
        frame.contentWindow.postMessage({ topic: 'reply', id: e.data.id, ok: r.ok, reply: reply, reason: r.reason }, '*');
    }
    window.addEventListener('message', onMessage);
    opts.container.textContent = '';
    opts.container.appendChild(frame);
    return {
      gate: gate, frame: frame, manifest: m, unmount: unmount,
      report: function () { return report(gate); },
      // Host -> plug, only on declared event names.
      send: function (name, data) {
        if (gate.killed() || gate.events().indexOf(name) < 0) { gate.log.push({ time: new Date().toISOString(), plug: m.id, topic: 'host->' + name, verdict: 'refused', reason: 'plug did not declare this event' }); return false; }
        frame.contentWindow.postMessage({ topic: 'event', name: name, data: data }, '*');
        return true;
      }
    };
  }

  var api = { AI_PER_MINUTE: AI_PER_MINUTE, verifyPlug: verifyPlug, validateManifest: validateManifest, assemble: assemble, SCHEMA: SCHEMA, Gate: Gate, Ratchet: Ratchet, load: load, report: report, checkUrl: checkUrl, CSP: CSP, _canon: canon };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PlugSocket = api;
})(typeof self !== 'undefined' ? self : this);

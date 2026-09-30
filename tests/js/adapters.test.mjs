// Phase 8 adapters (socket side): AI tools and WebAssembly. Run: node --test tests/js/adapters.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const S = require('../../socket/plug-socket.js');

const M = { id: 'zone.work.ai', name: 'AI', permissions: { ai: ['summarise'] } };
const echo = async (tool, args) => ({ tool, got: args });

test('AI: a declared tool the host offers goes through, and is logged', async () => {
  const g = S.Gate(M, { ai: echo });
  const r = g.handle({ topic: 'ai.call', tool: 'summarise', args: { text: 'hi' } });
  assert.equal(r.ok, true);
  assert.deepEqual(await r.reply, { ok: true, result: { tool: 'summarise', got: { text: 'hi' } } });
  assert.ok(g.log.some(e => e.topic === 'ai.call:summarise' && e.verdict === 'allowed'));
  assert.deepEqual(S.report(g).ai, [{ tool: 'summarise', times: 1 }]);
});

test('AI: every way to reach a tool it should not is refused, and the tool never runs', () => {
  let ran = 0;
  const g = S.Gate(M, { ai: async () => { ran++; } });
  const bad = [
    { topic: 'ai.call', tool: 'delete_files' },          // not declared
    { topic: 'ai.call', tool: 'SUMMARISE' },             // not the same name
    { topic: 'ai.call' },                                // no tool
    { topic: 'ai.call', tool: 'summarise', args: [1] },  // args must be an object
    { topic: 'ai.call', tool: 'summarise', args: { t: 'x'.repeat(20000) } },   // too big
  ];
  for (const m of bad) assert.equal(g.handle(m).ok, false, JSON.stringify(m).slice(0, 60));
  assert.equal(ran, 0);
  assert.equal(S.Gate({ id: 'a.b', permissions: {} }, { ai: echo }).handle({ topic: 'ai.call', tool: 'summarise' }).ok, false, 'no AI permission at all');
  assert.equal(S.Gate(M, {}).handle({ topic: 'ai.call', tool: 'summarise' }).ok, false, 'host offers no AI tools');
});

test('AI: rate limit, and it tightens when pushed (wall anchor)', () => {
  let t = 0;
  const g = S.Gate(M, { ai: echo, now: () => t });
  for (let i = 0; i < S.AI_PER_MINUTE; i++) assert.equal(g.handle({ topic: 'ai.call', tool: 'summarise' }).ok, true);
  assert.equal(g.handle({ topic: 'ai.call', tool: 'summarise' }).ok, false, 'over the limit');
  t += 61000;
  let ok = 0;
  for (let i = 0; i < S.AI_PER_MINUTE; i++) if (g.handle({ topic: 'ai.call', tool: 'summarise' }).ok) ok++;
  assert.ok(ok < S.AI_PER_MINUTE, 'after pushing, the allowance is smaller than before');
});

test('AI: the report card counts only answers that came back, and a broken tool is not the plug fault', async () => {
  const g = S.Gate(M, { ai: async () => { throw new Error('offline'); } });
  await g.handle({ topic: 'ai.call', tool: 'summarise' }).reply;
  const r = S.report(g);
  assert.deepEqual(r.ai, [], 'nothing came back, so nothing is counted');
  assert.equal(r.grade, 'CLEAN', 'the plug did nothing wrong');
  const ok = S.Gate(M, { ai: echo });
  await ok.handle({ topic: 'ai.call', tool: 'summarise' }).reply;
  assert.deepEqual(S.report(ok).ai, [{ tool: 'summarise', times: 1 }]);
});

test('AI: a failing tool is a clean answer, not a crash', async () => {
  const g = S.Gate(M, { ai: async () => { throw new Error('offline'); } });
  assert.deepEqual(await g.handle({ topic: 'ai.call', tool: 'summarise' }).reply, { ok: false, error: 'tool failed' });
});

// The smallest possible WebAssembly module: exports add(a, b).
const ADD_WASM = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 7, 7, 1,
  3, 97, 100, 100, 0, 0, 10, 9, 1, 7, 0, 32, 0, 32, 1, 106, 11]);

test('WebAssembly: the CSP allows compiling wasm but still blocks eval', () => {
  assert.match(S.CSP, /script-src 'unsafe-inline' 'wasm-unsafe-eval';/);
  assert.doesNotMatch(S.CSP, /'unsafe-eval'/, 'plain eval stays blocked');
});

test('WebAssembly: a plug can read its own .wasm with plugFile() and run it', async () => {
  const enc = new TextEncoder();
  const html = S.assemble({ 'index.html': enc.encode('<!doctype html><head><title>x</title></head><p>hi</p>'), 'add.wasm': ADD_WASM }, 'index.html');
  const helper = /<script>(\(function\(\)\{var F=[\s\S]*?)<\/script>/.exec(html);
  assert.ok(helper, 'helper script injected');
  const ctx = { window: {}, atob, TextDecoder, Uint8Array, Object };
  vm.runInNewContext(helper[1], ctx);
  const bytes = ctx.window.plugFile('add.wasm');
  const { instance } = await WebAssembly.instantiate(bytes);
  assert.equal(instance.exports.add(2, 40), 42);
  assert.equal(ctx.window.plugFile('../secret'), null, 'only the plug\'s own files');
  assert.equal(ctx.window.plugFile('index.html'), null, 'only data files are offered');
});

test('the data helper goes in <head>, never inside a <header> tag', () => {
  const enc = new TextEncoder();
  const html = S.assemble({ 'index.html': enc.encode('<header>top</header><p>x</p>'), 'd.json': enc.encode('{}') }, 'index.html');
  assert.match(html, /^<script>/, 'no <head>: helper goes first');
  assert.match(html, /<header>top<\/header>/, 'header tag left intact');
});

test('WebAssembly: plugs with no data files get no helper', () => {
  const html = S.assemble({ 'index.html': new TextEncoder().encode('<p>hi</p>') }, 'index.html');
  assert.doesNotMatch(html, /plugFile/);
});

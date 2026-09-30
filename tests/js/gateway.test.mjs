// Phase 6 tests: gateway, watchdog, report card. Run: node --test tests/js/gateway.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const S = require('../../socket/plug-socket.js');

const M = { id: 'zone.work.weather', name: 'Weather', permissions: { network: ['api.example.com'], events: ['weather.now'] } };

function fakeFetch(calls, body = '{"temp":12}') {
  return async (url, init) => {
    calls.push({ url, init });
    return { status: 200, headers: { get: () => String(body.length) }, text: async () => body };
  };
}

test('declared https host goes through, safely', async () => {
  const calls = [];
  const g = S.Gate(M, { fetch: fakeFetch(calls) });
  const r = g.handle({ topic: 'net.fetch', url: 'https://api.example.com/today' });
  assert.equal(r.ok, true);
  assert.deepEqual(await r.reply, { status: 200, body: '{"temp":12}' });
  assert.equal(calls.length, 1);
  const init = calls[0].init;
  assert.equal(init.credentials, 'omit', 'never your cookies');
  assert.equal(init.redirect, 'error', 'no redirecting to undeclared hosts');
  assert.equal(init.referrerPolicy, 'no-referrer');
});

test('every way to reach somewhere else is refused, and nothing is fetched', () => {
  const calls = [];
  const g = S.Gate(M, { fetch: fakeFetch(calls), blockHosts: ['api.example.com'.replace('api', 'blocked')] });
  const bad = {
    'undeclared host': 'https://evil.example/x',
    'look-alike subdomain': 'https://api.example.com.evil.example/x',
    'sub of declared': 'https://x.api.example.com/',
    'http not https': 'http://api.example.com/',
    'login in url': 'https://user:pw@api.example.com/',
    'odd port': 'https://api.example.com:8443/',
    'localhost': 'https://localhost/',
    'local network name': 'https://printer.local/',
    'raw ip': 'https://192.168.1.1/',
    'ipv6': 'https://[::1]/',
    'decimal ip': 'https://3232235777/',
    'file': 'file:///C:/Windows/win.ini',
    'javascript': 'javascript:alert(1)',
    'data': 'data:text/html,hi',
    'junk': 'not a url',
    'not a string': 12,
  };
  for (const [name, url] of Object.entries(bad)) {
    const r = g.handle({ topic: 'net.fetch', url });
    assert.equal(r.ok, false, name);
    assert.ok(r.reason, name + ' needs a plain reason');
  }
  assert.equal(calls.length, 0, 'the gateway never even tried');
});

test('red-team fixes: disguised IPs, block list spelling and subdomains, host spelling', async () => {
  for (const h of ['127.0.0.1.nip.io', '192.168.1.1.sslip.io', '10-0-0-1.sslip.io', 'app.localtest.me', 'x.lvh.me']) {
    assert.match(S.checkUrl('https://' + h + '/', [h]) || '', /dressed up/, h + ' even when declared');
  }
  assert.match(S.checkUrl('https://api.example.com/', ['api.example.com'], ['API.Example.com.']), /block list/);
  assert.match(S.checkUrl('https://x.evil.com/', ['x.evil.com'], ['evil.com']), /block list/);
  assert.equal(S.checkUrl('https://notevil.com/', ['notevil.com'], ['evil.com']), null, 'block evil.com must not block notevil.com');
  assert.equal(S.checkUrl('https://api.example.com/', ['API.example.com.']), null, 'declared spelling does not matter');
  const calls = [];
  const g = S.Gate({ id: 'a.b', permissions: { network: ['api.example.com'] } }, { fetch: async () => { throw new Error('dns'); } });
  await g.handle({ topic: 'net.fetch', url: 'https://api.example.com./x' }).reply;
  const r = S.report(g);
  assert.deepEqual(r.contacted, [], 'a failed request is not "contacted"');
});

test("the user's block list beats the plug's declaration", () => {
  const calls = [];
  const g = S.Gate(M, { fetch: fakeFetch(calls), blockHosts: ['api.example.com'] });
  const r = g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' });
  assert.equal(r.ok, false);
  assert.match(r.reason, /block list/);
});

test('no network permission = no gateway at all', () => {
  const g = S.Gate({ id: 'a.b', permissions: {} }, { fetch: () => { throw new Error('must not be called'); } });
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, false);
});

test('methods and bodies are limited', () => {
  const g = S.Gate(M, { fetch: fakeFetch([]) });
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/', method: 'DELETE' }).ok, false);
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/', method: 'POST', body: { a: 1 } }).ok, false);
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/', method: 'POST', body: 'hi' }).ok, true);
});

test('rate limit: 30 a minute, then refused', () => {
  let t = 0;
  const g = S.Gate(M, { fetch: fakeFetch([]), now: () => t });
  for (let i = 0; i < 30; i++) assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, true);
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, false);
  t += 61000;
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, true, 'fine again a minute later');
});

test('a failing or oversized response does not crash, and is logged', async () => {
  const g = S.Gate(M, { fetch: async () => { throw new Error('offline'); } });
  assert.deepEqual(await g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).reply, { status: 0, error: 'request failed' });
  const big = S.Gate(M, { fetch: async () => ({ status: 200, headers: { get: () => '99999999' }, text: async () => '' }) });
  assert.equal((await big.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).reply).status, 0);
  assert.ok(big.log.some(e => e.topic === 'net.response' && /too big/.test(e.reason)));
});

test('watchdog: 20 refusals pulls the plug, and then everything is shut', () => {
  let killedWith = null;
  const g = S.Gate(M, { fetch: fakeFetch([]), onKill: r => { killedWith = r; } });
  for (let i = 0; i < 20; i++) g.handle({ topic: 'wallet.send' });
  assert.ok(killedWith, 'watchdog fired');
  const r = g.handle({ topic: 'event.publish', name: 'weather.now' });
  assert.equal(r.ok, false, 'even declared things are refused once pulled');
  assert.match(r.reason, /watchdog/);
});

test('watchdog: a message flood pulls the plug', () => {
  let killed = false;
  const g = S.Gate(M, { onKill: () => { killed = true; }, now: () => 0 });
  for (let i = 0; i < 201; i++) g.handle({ topic: 'plug.ready' });
  assert.equal(killed, true);
});

test('report card tells the truth, built only from the log', async () => {
  const g = S.Gate(M, { fetch: fakeFetch([]) });
  assert.equal(S.report(g).grade, 'CLEAN');
  await g.handle({ topic: 'net.fetch', url: 'https://api.example.com/a' }).reply;
  await g.handle({ topic: 'net.fetch', url: 'https://api.example.com/b' }).reply;
  g.handle({ topic: 'net.fetch', url: 'https://evil.example/' });
  const r = S.report(g);
  assert.deepEqual(r.contacted, [{ host: 'api.example.com', times: 2 }]);
  assert.equal(r.blocked.length, 1);
  assert.match(r.blocked[0].what, /evil\.example was not declared/);
  assert.equal(r.grade, 'TRIED THINGS');
  assert.deepEqual(r.asked, ['internet: api.example.com', 'events: weather.now']);
  assert.ok(!r.contacted.some(c => c.host === 'evil.example'), 'blocked hosts are never listed as contacted');
});

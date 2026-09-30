// Every page's inline script must at least parse. (Guards against edits that break a string or
// slip in a hidden line-break character.) Run: node --test tests/js/pages.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PAGES = ['ui/index.html', 'ui/landing.html', 'ui/desktop.html'].concat(
  readdirSync(join(root, 'examples')).filter((d) => existsSync(join(root, 'examples', d, 'app', 'index.html'))).map((d) => 'examples/' + d + '/app/index.html'));
const SCRIPTS = ['socket/plug-socket.js', 'socket/host-kit.js', 'socket/wiring.js',
  'examples/gallery/app/app.js', 'examples/component/app/brick-counter.js'];

test('inline scripts in every page parse', () => {
  for (const p of PAGES) {
    const html = readFileSync(join(root, p), 'utf8');
    const re = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
    let m, n = 0;
    while ((m = re.exec(html))) {
      n++;
      assert.doesNotThrow(() => new vm.Script(m[1], { filename: p + ' script ' + n }), p + ' script ' + n);
    }
  }
});

test('script files parse', () => {
  for (const p of SCRIPTS) {
    const src = readFileSync(join(root, p), 'utf8');
    assert.doesNotThrow(() => new vm.Script(src, { filename: p }), p);
  }
});

test('the dashboard still has its token placeholder for the helper', () => {
  assert.match(readFileSync(join(root, 'ui/index.html'), 'utf8'), /var TOKEN = '__WORKZONE_TOKEN__';/);
});

test('risky dashboard actions only go through press-and-hold (scripts cannot press it)', () => {
  const html = readFileSync(join(root, 'ui/index.html'), 'utf8');
  for (const path of ['/api/key/new', '/api/build', '/api/update-check', '/api/devices/scan', '/api/devices/set']) {
    assert.ok(!html.includes("api('" + path + "'"), path + ' is never called directly');
    assert.ok(html.includes("risky('" + path + "'"), path + ' goes through risky()');
  }
  assert.match(html, /if \(!e\.isTrusted \|\| t\) return;/, 'faked clicks and key presses are ignored');
});

test('no plug uses a <form>: forms are blocked inside the box, so it would silently do nothing', () => {
  for (const p of PAGES.filter((x) => x.startsWith('examples/'))) {
    assert.doesNotMatch(readFileSync(join(root, p), 'utf8'), /<form\b/i, p);
  }
});

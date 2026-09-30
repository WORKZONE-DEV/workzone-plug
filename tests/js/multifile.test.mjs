// Multi-file plugs. Run: node --test tests/js/multifile.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const S = require('../../socket/plug-socket.js');
const enc = new TextEncoder();
const F = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'string' ? enc.encode(v) : v]));

test('the gallery example (page + css + js + image) packs, verifies and assembles', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mf-'));
  try {
    const out = join(dir, 'g.plug');
    execFileSync('python', ['-c', `import sys;sys.path.insert(0,r'${join(here, '..', '..', 'tools')}');import pack;open(r'${out}','wb').write(pack.build(r'${join(here, '..', '..', 'examples', 'gallery')}', bytes(range(32))))`]);
    const v = await S.verifyPlug(new Uint8Array(readFileSync(out)));
    assert.deepEqual(Object.keys(v.files).sort(), ['app.js', 'img/brick.svg', 'index.html', 'style.css']);
    const html = S.assemble(v.files, v.manifest.entry);
    assert.match(html, /<style>body\{/, 'style sheet folded in');
    assert.match(html, /gallery\.next/, 'script folded in');
    assert.match(html, /src="data:image\/svg\+xml;base64,/, 'image turned into a data address');
    assert.doesNotMatch(html, /src="app\.js"|href="style\.css"|src="img\/brick\.svg"/, 'no loose references left');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('only the plug\'s own files can be reached ("../" cannot climb out)', () => {
  const files = F({ 'index.html': '<img src="../../secret.png"><img src="/etc/passwd"><script src="../x.js"></script>', 'a.png': 'x' });
  const html = S.assemble(files, 'index.html');
  assert.match(html, /src="\.\.\/\.\.\/secret\.png"/, 'left untouched (and the CSP blocks it)');
  assert.match(html, /<script src="\.\.\/x\.js"><\/script>/);
});

test('outside addresses are left alone (the CSP blocks them at run time)', () => {
  const files = F({ 'index.html': '<script src="https://evil.example/x.js"></script><img src="//evil.example/b.gif"><a href="javascript:alert(1)">x</a>' });
  const html = S.assemble(files, 'index.html');
  assert.match(html, /https:\/\/evil\.example\/x\.js/);
  assert.match(html, /\/\/evil\.example\/b\.gif/);
});

test('a script file cannot break out of its script tag', () => {
  const files = F({ 'index.html': '<script src="a.js"></script>', 'a.js': 'var s = "</script><img src=x onerror=alert(1)>";' });
  const html = S.assemble(files, 'index.html');
  assert.equal((html.match(/<\/script>/gi) || []).length, 1, 'only the real closing tag remains');
});

test('css url() inside a sub-folder resolves relative to that sheet', () => {
  const files = F({ 'index.html': '<link rel="stylesheet" href="css/s.css">', 'css/s.css': 'b{background:url(../img/a.png)}', 'img/a.png': 'PNG' });
  const html = S.assemble(files, 'index.html');
  assert.match(html, /url\("data:image\/png;base64,UE5H"\)/);
});

test('entry in a sub-folder resolves its own relative files', () => {
  const files = F({ 'site/index.html': '<script src="main.js"></script>', 'site/main.js': 'var ok=1' });
  assert.match(S.assemble(files, 'site/index.html'), /<script ?>var ok=1<\/script>/);
});

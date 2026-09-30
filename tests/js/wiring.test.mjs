// Top-brick rule tests. Run: node --test tests/js/wiring.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { Wiring } = require('../../socket/wiring.js');

function table() {
  const w = Wiring();
  w.register('clock', ['time.tick']);
  w.register('chart', ['time.tick', 'price.tick']);
  w.register('feed', ['price.tick']);
  w.register('mute', []);
  ['clock', 'chart', 'feed', 'mute'].forEach(id => w.setOn(id, true));
  return w;
}

test('all three must agree: A declared, B declared, person linked', () => {
  const w = table();
  assert.deepEqual(w.route('clock', 'time.tick'), [], 'not linked yet: nothing gets through');
  assert.equal(w.link('clock', 'chart', 'time.tick'), null);
  assert.deepEqual(w.route('clock', 'time.tick'), ['chart']);
});

test('each missing piece blocks the link (both ways)', () => {
  const w = table();
  assert.match(w.link('clock', 'feed', 'time.tick'), /never said it would listen/, 'receiver did not declare it');
  assert.match(w.link('feed', 'chart', 'time.tick'), /never said it would send/, 'sender did not declare it');
  assert.match(w.link('clock', 'clock', 'time.tick'), /itself/);
  assert.match(w.link('clock', 'ghost', 'time.tick'), /on the table/);
  assert.equal(w.link('clock', 'chart', 'time.tick'), null);
  assert.match(w.link('clock', 'chart', 'time.tick'), /already/);
});

test('a sender cannot route an event it never declared, even if a link exists for another event', () => {
  const w = table();
  w.link('chart', 'feed', 'price.tick');
  assert.deepEqual(w.route('chart', 'secret.data'), []);
  assert.deepEqual(w.route('chart', 'price.tick'), ['feed']);
});

test('switching a brick OFF stops delivery; ON brings it back', () => {
  const w = table();
  w.link('clock', 'chart', 'time.tick');
  w.setOn('chart', false);
  assert.deepEqual(w.route('clock', 'time.tick'), []);
  w.setOn('chart', true);
  assert.deepEqual(w.route('clock', 'time.tick'), ['chart']);
});

test('unlink and removing a brick clean up its links', () => {
  const w = table();
  w.link('clock', 'chart', 'time.tick');
  w.link('feed', 'chart', 'price.tick');
  assert.equal(w.unlink('clock', 'chart', 'time.tick'), true);
  assert.equal(w.unlink('clock', 'chart', 'time.tick'), false, 'already gone');
  w.unregister('chart');
  assert.deepEqual(w.links(), []);
  assert.deepEqual(w.route('feed', 'price.tick'), []);
});

test('shared() lists only events both bricks declared', () => {
  const w = table();
  assert.deepEqual(w.shared('clock', 'chart'), ['time.tick']);
  assert.deepEqual(w.shared('chart', 'feed'), ['price.tick']);
  assert.deepEqual(w.shared('clock', 'feed'), []);
  assert.deepEqual(w.shared('mute', 'chart'), []);
});

test('links() hands out copies: changing them changes nothing', () => {
  const w = table();
  w.link('clock', 'chart', 'time.tick');
  const copy = w.links();
  copy[0].to = 'feed';
  copy.push({ from: 'feed', to: 'chart', event: 'time.tick' });
  assert.deepEqual(w.route('clock', 'time.tick'), ['chart']);
  assert.equal(w.links().length, 1);
});

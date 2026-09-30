/* Host kit: the bits every host page needs around plug-socket.js.
 * Plain-words pop-ups (default answer: No), a log view, and a file fingerprint so
 * you can see exactly which file is running.
 *
 *   HostKit.attach({ slot, log, fileInput, hostName, trustedKeys })
 *   -> { loadBytes(bytes), current() }
 */
(function (root) {
  'use strict';

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text) e.textContent = text;
    return e;
  }

  var dlg = null;
  function ask(text) {
    if (!dlg) {
      dlg = el('dialog', { class: 'hk-ask' });
      var p = el('p', { class: 'hk-text' });
      var f = el('form', { method: 'dialog', class: 'hk-row' });
      f.appendChild(el('button', { value: 'no' }, 'No'));
      f.appendChild(el('button', { value: 'yes', class: 'hk-yes' }, 'Allow'));
      dlg.appendChild(p); dlg.appendChild(f);
      document.body.appendChild(dlg);
    }
    return new Promise(function (resolve) {
      dlg.querySelector('.hk-text').textContent = text;
      dlg.returnValue = 'no';
      dlg.onclose = function () { resolve(dlg.returnValue === 'yes'); };
      dlg.showModal();
    });
  }

  function describe(m) {
    var p = m.permissions;
    return [
      'Network: ' + (p.network && p.network.length ? 'only ' + p.network.join(', ') : 'none'),
      'Storage: ' + (p.storage || 'none'),
      'Events: ' + ((p.events || []).join(', ') || 'none'),
      'Identity: ' + (p.identity === 'public-key' ? 'your public key only' : 'none'),
      'AI tools: ' + ((p.ai || []).join(', ') || 'none')
    ].join('\n');
  }

  async function fingerprint(bytes) {
    var h = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), s = '';
    for (var i = 0; i < 8; i++) s += (h[i] < 16 ? '0' : '') + h[i].toString(16);
    return s;
  }

  function attach(o) {
    var current = null;
    function line(text, cls) {
      var d = el('div', cls ? { class: cls } : {}, text);
      o.log.appendChild(d); o.log.scrollTop = 1e9;
    }
    async function loadBytes(bytes) {
      bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      if (current) { current.unmount(); current = null; }
      line(o.hostName + ': file sha256 ' + (await fingerprint(bytes)) + '...');
      try {
        current = await PlugSocket.load(bytes, {
          container: o.slot,
          trustedKeys: o.trustedKeys || [],
          askTrust: function (m) { return ask('"' + m.name + '" is signed by an author ' + o.hostName + ' does not know yet:\n' + m.author_key.slice(0, 30) + '...\n\nTrust this author?'); },
          askPermissions: function (m) { return ask('"' + m.name + '" wants:\n\n' + describe(m) + '\n\nAllow?'); },
          onEvent: function (name, data) { line('bus <- ' + name + ' ' + JSON.stringify(data).slice(0, 200)); },
          log: function (e) { line(e.time.slice(11, 19) + ' ' + e.verdict.toUpperCase() + ' ' + e.topic + ' (' + e.reason + ')', e.verdict); }
        });
        line('mounted ' + current.manifest.id + ' ' + current.manifest.version + ' in ' + o.hostName);
        if (o.onMount) o.onMount(current);
      } catch (e) {
        line('REJECTED: ' + e.message, 'refused');
      }
    }
    if (o.fileInput) o.fileInput.onchange = async function (e) {
      var f = e.target.files[0]; if (f) loadBytes(new Uint8Array(await f.arrayBuffer()));
    };
    // Drag a .plug file onto the slot to plug it in.
    o.slot.addEventListener('dragover', function (e) { e.preventDefault(); });
    o.slot.addEventListener('drop', async function (e) {
      e.preventDefault();
      var f = e.dataTransfer.files[0]; if (f) loadBytes(new Uint8Array(await f.arrayBuffer()));
    });
    return { loadBytes: loadBytes, current: function () { return current; } };
  }

  root.HostKit = { attach: attach, ask: ask, describe: describe, fingerprint: fingerprint };
})(this);

// A web component: a reusable custom HTML tag, <brick-counter>. Any page can use it,
// and inside a plug it follows the plug's rules (it can only speak through declared events).
class BrickCounter extends HTMLElement {
  connectedCallback() {
    var n = parseInt(this.getAttribute('start') || '0', 10);
    var root = this.attachShadow({ mode: 'open' });
    root.innerHTML = '<style>button{background:#ff6fae;border:0;border-radius:8px;padding:6px 14px;font:600 16px system-ui;cursor:pointer}' +
      'span{display:inline-block;min-width:3ch;text-align:center;color:#7be0ad}</style>' +
      '<button id="minus">-</button> <span id="n"></span> bricks <button id="plus">+</button>';
    var show = function () {
      root.getElementById('n').textContent = n;
      parent.postMessage({ topic: 'event.publish', name: 'count.changed', data: n }, '*');
    };
    root.getElementById('minus').onclick = function () { n = Math.max(0, n - 1); show(); };
    root.getElementById('plus').onclick = function () { n++; show(); };
    show();
  }
}
customElements.define('brick-counter', BrickCounter);
parent.postMessage({ topic: 'plug.ready' }, '*');

// Its own script, in its own file. Talks to the host only through the declared event.
var n = 1;
addEventListener('message', function (e) {
  var m = e.data;
  if (m && m.topic === 'event' && (m.name === 'gallery.next' || m.name === 'clock.tick')) {
    n = n % 3 + 1;
    document.getElementById('n').textContent = n;
    parent.postMessage({ topic: 'event.publish', name: 'gallery.next', data: n }, '*');
  }
});
parent.postMessage({ topic: 'plug.ready' }, '*');

/* Wiring: how bricks connect (the top-brick rule).
 *
 *   Authors decide what a brick CAN say and hear  (permissions.events in plug.json)
 *   People decide which bricks are CONNECTED       (links made here, by the person)
 *   Plugs decide nothing about other plugs         (a plug can't create or change links)
 *
 * A message from brick A called "x" reaches brick B only if:
 *   A declared "x", B declared "x", and the person linked A -> B for "x".
 * Remove any one of the three and nothing gets through.
 *
 * Pure logic, no DOM: works in the browser (window.PlugWiring) and in Node (tests).
 */
(function (root) {
  'use strict';

  function Wiring() {
    var bricks = {};   // id -> { events: [...], on: bool }
    var links = [];    // { from, to, event }

    function declared(id, ev) { return !!bricks[id] && bricks[id].events.indexOf(ev) >= 0; }

    return {
      /* The host registers each brick with the events its (verified) manifest declares. */
      register: function (id, events) {
        bricks[id] = { events: (events || []).slice(), on: false };
      },
      unregister: function (id) {
        delete bricks[id];
        links = links.filter(function (l) { return l.from !== id && l.to !== id; });
      },
      setOn: function (id, on) { if (bricks[id]) bricks[id].on = !!on; },
      isOn: function (id) { return !!bricks[id] && bricks[id].on; },

      /* Events two bricks could be linked on: declared by BOTH. */
      shared: function (a, b) {
        if (!bricks[a] || !bricks[b] || a === b) return [];
        return bricks[a].events.filter(function (e) { return bricks[b].events.indexOf(e) >= 0; });
      },

      /* Only the PERSON calls this (from the dashboard). Returns null or a plain reason. */
      link: function (from, to, ev) {
        if (from === to) return 'a brick cannot be linked to itself';
        if (!bricks[from] || !bricks[to]) return 'both bricks must be on the table';
        if (!declared(from, ev)) return from + ' never said it would send "' + ev + '"';
        if (!declared(to, ev)) return to + ' never said it would listen to "' + ev + '"';
        if (links.some(function (l) { return l.from === from && l.to === to && l.event === ev; })) return 'already linked';
        links.push({ from: from, to: to, event: ev });
        return null;
      },
      unlink: function (from, to, ev) {
        var before = links.length;
        links = links.filter(function (l) { return !(l.from === from && l.to === to && l.event === ev); });
        return links.length < before;
      },
      links: function () { return links.map(function (l) { return { from: l.from, to: l.to, event: l.event }; }); },

      /* Where does a message from `from` called `ev` go? Only to linked bricks that are ON. */
      route: function (from, ev) {
        if (!declared(from, ev)) return [];
        return links.filter(function (l) {
          return l.from === from && l.event === ev && declared(l.to, ev) && bricks[l.to].on;
        }).map(function (l) { return l.to; });
      }
    };
  }

  var api = { Wiring: Wiring };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PlugWiring = api;
})(typeof self !== 'undefined' ? self : this);

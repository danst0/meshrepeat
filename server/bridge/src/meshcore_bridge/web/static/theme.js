// MeshCore Spiegel — Theme-Toggle. Cycle: auto → light → dark.
// data-theme-Attribut auf <html>. Wert in localStorage 'meshcore.theme'.
// Pre-Paint-Script in <head> setzt das Attribut bereits VOR dem ersten Paint,
// damit kein FOUC entsteht — diese Datei kümmert sich nur um den Button.
(function () {
  "use strict";
  var KEY = "meshcore.theme";
  var ORDER = ["auto", "light", "dark"];
  var LABELS = { auto: "Auto", light: "Hell", dark: "Dunkel" };
  var ICONS = { auto: "◑", light: "☀", dark: "☾" };
  var html = document.documentElement;

  function current() {
    var v = null;
    try { v = localStorage.getItem(KEY); } catch (e) {}
    return v === "light" || v === "dark" ? v : "auto";
  }

  function apply(t) {
    if (t === "auto") html.removeAttribute("data-theme");
    else html.setAttribute("data-theme", t);
    var btns = document.querySelectorAll("[data-theme-toggle]");
    btns.forEach(function (b) {
      b.textContent = ICONS[t];
      b.title = "Theme: " + LABELS[t] + " (klicken zum Wechseln)";
      b.setAttribute("aria-label", "Theme umschalten — aktuell " + LABELS[t]);
    });
  }

  function next() {
    var t = current();
    var i = ORDER.indexOf(t);
    var n = ORDER[(i + 1) % ORDER.length];
    try { localStorage.setItem(KEY, n); } catch (e) {}
    apply(n);
  }

  document.addEventListener("DOMContentLoaded", function () {
    apply(current());
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", next);
    });
  });
})();

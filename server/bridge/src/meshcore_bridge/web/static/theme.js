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

  // Globaler Kopier-Handler: jedes [data-copy]-Element kopiert seinen Wert ins
  // Clipboard (delegiert, damit auch per-Zeile gerenderte Buttons greifen).
  // Kurzes visuelles Feedback; Fehler werden geschluckt (Clipboard kann z.B.
  // ohne Secure Context blockiert sein).
  function attachCopy() {
    document.addEventListener("click", function (ev) {
      var el = ev.target.closest("[data-copy]");
      if (!el) return;
      var text = el.getAttribute("data-copy");
      if (!text) return;
      try {
        navigator.clipboard.writeText(text);
        var prev = el.textContent;
        el.textContent = "✓";
        setTimeout(function () { el.textContent = prev; }, 1000);
      } catch (e) { /* Clipboard blockiert; Tooltip mit vollem Wert reicht */ }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    apply(current());
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.addEventListener("click", next);
    });
    attachCopy();
  });
})();

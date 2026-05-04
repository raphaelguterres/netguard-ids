/* NetGuard theme toggle — persistent dark/light switch */
(function () {
  "use strict";

  var STORAGE_KEY = "netguard-theme";

  function getStored() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
  }

  function setStored(value) {
    try { localStorage.setItem(STORAGE_KEY, value); } catch (e) {}
  }

  function getInitial() {
    var stored = getStored();
    if (stored === "light" || stored === "dark") return stored;
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
    return "dark";
  }

  function applyBodyClass(theme) {
    if (!document.body) return;
    if (theme === "light") {
      document.body.classList.add("theme-light");
      document.body.classList.remove("theme-dark");
    } else {
      document.body.classList.add("theme-dark");
      document.body.classList.remove("theme-light");
    }
  }

  function applyTheme(theme) {
    var root = document.documentElement;
    root.setAttribute("data-theme", theme === "light" ? "light" : "dark");
    if (document.body) {
      applyBodyClass(theme);
    } else {
      document.addEventListener("DOMContentLoaded", function () { applyBodyClass(theme); });
    }
  }

  applyTheme(getInitial());

  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function toggleTheme() {
    var next = currentTheme() === "light" ? "dark" : "light";
    applyTheme(next);
    setStored(next);
  }

  function buildButton() {
    var btn = document.createElement("button");
    btn.className = "theme-toggle";
    btn.type = "button";
    btn.setAttribute("aria-label", "Toggle dark / light theme");
    btn.setAttribute("title", "Tema dia / noite");
    var moonSvg = '<svg class="icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" /></svg>';
    var sunSvg = '<svg class="icon-sun" viewBox="0 0 24 24" aria-hidden="true">' +
      '<circle cx="12" cy="12" r="4" />' +
      '<line x1="12" y1="2"  x2="12" y2="4" />' +
      '<line x1="12" y1="20" x2="12" y2="22" />' +
      '<line x1="2"  y1="12" x2="4"  y2="12" />' +
      '<line x1="20" y1="12" x2="22" y2="12" />' +
      '<line x1="4.93" y1="4.93" x2="6.34" y2="6.34" />' +
      '<line x1="17.66" y1="17.66" x2="19.07" y2="19.07" />' +
      '<line x1="4.93" y1="19.07" x2="6.34" y2="17.66" />' +
      '<line x1="17.66" y1="6.34" x2="19.07" y2="4.93" />' +
      '</svg>';
    btn.innerHTML = moonSvg + sunSvg;
    btn.addEventListener("click", toggleTheme);
    return btn;
  }

  function mountButton() {
    if (document.querySelector(".theme-toggle")) return;
    var slot = document.querySelector("[data-theme-slot]") ||
               document.querySelector(".site-actions") ||
               document.querySelector(".hdr-r") ||
               document.querySelector("header .site-actions") ||
               document.querySelector("header");
    if (!slot) return;
    slot.insertBefore(buildButton(), slot.firstChild);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountButton);
  } else {
    mountButton();
  }

  if (window.matchMedia) {
    try {
      window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", function (e) {
        if (!getStored()) applyTheme(e.matches ? "light" : "dark");
      });
    } catch (e) {}
  }
})();

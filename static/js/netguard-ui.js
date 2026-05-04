(function () {
  "use strict";

  function maskSecret(value) {
    var text = String(value || "");
    if (text.length <= 10) return "********";
    return text.slice(0, 6) + "..." + text.slice(-4);
  }

  function copyText(text) {
    if (!text) return Promise.resolve(false);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; });
    }
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "readonly");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    ta.remove();
    return Promise.resolve(ok);
  }

  function announce(message) {
    var toast = document.querySelector("[data-netguard-toast]");
    if (!toast) {
      toast = document.createElement("div");
      toast.setAttribute("data-netguard-toast", "true");
      toast.setAttribute("role", "status");
      toast.style.cssText = [
        "position:fixed",
        "right:18px",
        "bottom:18px",
        "z-index:9999",
        "padding:10px 14px",
        "border:1px solid var(--border,#263241)",
        "border-radius:10px",
        "background:var(--panel,#111821)",
        "color:var(--text,#eef3f8)",
        "box-shadow:0 12px 30px rgba(0,0,0,.24)",
        "opacity:0",
        "transform:translateY(6px)",
        "transition:opacity .18s ease, transform .18s ease"
      ].join(";");
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    requestAnimationFrame(function () {
      toast.style.opacity = "1";
      toast.style.transform = "translateY(0)";
    });
    window.clearTimeout(announce._timer);
    announce._timer = window.setTimeout(function () {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(6px)";
    }, 2200);
  }

  function initCopyButtons() {
    document.addEventListener("click", function (event) {
      var btn = event.target.closest("[data-copy]");
      if (!btn) return;
      var text = btn.getAttribute("data-copy") || "";
      copyText(text).then(function (ok) {
        announce(ok ? "Copied to clipboard" : "Copy failed");
      });
    });
  }

  function initSecretMasking() {
    document.querySelectorAll("[data-secret],[data-token],[data-api-key]").forEach(function (el) {
      var raw = el.getAttribute("data-secret") || el.getAttribute("data-token") || el.getAttribute("data-api-key") || el.textContent;
      el.textContent = maskSecret(raw);
      el.classList.add("ng-secret");
      el.setAttribute("title", "Secret masked");
    });
  }

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
      return ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;"
      })[char];
    });
  }

  function isSafeReadRoute(route) {
    var text = String(route || "");
    var lower = text.toLowerCase();
    var allowed = text.indexOf("/soc") === 0 || text.indexOf("/soc-preview") === 0 || text === "/admin/inbox";
    var blocked = ["/api/", "/delete", "/reset", "/rotate", "/revoke", "/disable", "/actions", "/status"].some(function (marker) {
      return lower.indexOf(marker) !== -1;
    });
    return allowed && !blocked;
  }

  function isEntryRoute() {
    var path = window.location.pathname.replace(/\/+$/, "") || "/";
    return path === "/" || path === "/dashboard" || path === "/admin";
  }

  function findRecommendationTarget() {
    return document.querySelector("[data-guided-entry]") ||
      document.querySelector(".soc-page") ||
      document.querySelector("#main") ||
      document.querySelector("#app") ||
      document.querySelector(".container") ||
      document.body;
  }

  function mountRecommendation(card) {
    var target = findRecommendationTarget();
    if (!target) return;
    if (target.hasAttribute && target.hasAttribute("data-guided-entry")) {
      target.innerHTML = "";
      target.appendChild(card);
      return;
    }
    target.insertBefore(card, target.firstChild);
  }

  function renderRecommendation(recommendation) {
    if (!recommendation || !isEntryRoute() || !isSafeReadRoute(recommendation.route)) return;
    if (document.querySelector("[data-netguard-recommendation]")) return;

    var priority = String(recommendation.priority || "info").toLowerCase();
    var route = String(recommendation.route || "/soc");
    var label = String(recommendation.label || "Review overview");
    var reason = String(recommendation.reason || "No critical activity detected.");
    var card = document.createElement("section");
    card.className = "ng-recommendation priority-" + priority;
    card.setAttribute("data-netguard-recommendation", "true");
    card.setAttribute("aria-label", "Recommended next action");
    card.innerHTML = [
      "<div>",
      "<div class=\"soc-stat-label\">Recommended Next Action</div>",
      "<h2>", esc(label), "</h2>",
      "<p>", esc(reason), "</p>",
      "<div class=\"soc-flow-steps\" aria-label=\"SOC workflow\">",
      "<span class=\"is-active\">Overview</span><span>Operator Inbox</span><span>Host Triage</span><span>Incident</span><span>Resolution</span>",
      "</div>",
      "</div>",
      "<div class=\"ng-recommendation-actions\">",
      "<a class=\"soc-action-button soc-action-button-primary\" href=\"", esc(route), "\">", esc(label), "</a>",
      "</div>"
    ].join("");
    mountRecommendation(card);

    var shouldRedirect = Boolean(recommendation.auto_redirect) && (priority === "critical" || priority === "high");
    if (!shouldRedirect) return;

    var actionBox = card.querySelector(".ng-recommendation-actions");
    var countdown = document.createElement("span");
    var cancel = document.createElement("button");
    var seconds = 8;
    countdown.className = "ng-countdown";
    countdown.textContent = "Auto-open in " + seconds + "s";
    cancel.className = "ng-recommendation-cancel";
    cancel.type = "button";
    cancel.textContent = "Stay here";
    actionBox.appendChild(countdown);
    actionBox.appendChild(cancel);

    var timer = window.setInterval(function () {
      seconds -= 1;
      countdown.textContent = "Auto-open in " + seconds + "s";
      if (seconds <= 0) {
        window.clearInterval(timer);
        window.location.assign(route);
      }
    }, 1000);

    cancel.addEventListener("click", function () {
      window.clearInterval(timer);
      countdown.textContent = "Auto-open cancelled";
      cancel.remove();
      announce("Automatic navigation cancelled");
    });
  }

  function initOperationalRecommendation() {
    if (!isEntryRoute()) return;
    fetch("/api/recommended-route", {
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (payload) {
        renderRecommendation(payload && payload.recommendation);
      })
      .catch(function () {
        // Keep legacy pages usable even when the operator endpoint is unavailable.
      });
  }

  function init() {
    initCopyButtons();
    initSecretMasking();
    initOperationalRecommendation();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

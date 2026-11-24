// Honet UI helpers: live refresh, confirmation modal, toasts, print.
// No browser dialogs (confirm/alert): everything uses Bootstrap modals.
(function () {
  "use strict";

  var main = document.getElementById("main");
  var dirty = false; // the user typed into a form on this page

  // Drop ?msg= so a reload or refresh does not repeat the message.
  if (location.search.indexOf("msg=") >= 0 && window.history.replaceState) {
    var u = new URL(location.href);
    u.searchParams.delete("msg");
    history.replaceState(null, "", u.pathname + u.search + u.hash);
  }

  // Show the error modal and success toast the server rendered.
  function showOnLoad() {
    if (!window.bootstrap) return;
    document.querySelectorAll(".modal[data-show-on-load]").forEach(function (el) {
      bootstrap.Modal.getOrCreateInstance(el).show();
    });
    document.querySelectorAll(".toast[data-show-on-load]").forEach(function (el) {
      bootstrap.Toast.getOrCreateInstance(el, { delay: 4000 }).show();
    });
  }

  // Confirmation: a form with data-confirm opens the modal; Confirm submits it.
  var pending = null;
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute("data-confirm");
    if (!msg || form.dataset.confirmed === "1") return;
    e.preventDefault();
    var modal = document.getElementById("confirm-modal");
    if (!modal || !window.bootstrap) return; // never submit unconfirmed
    pending = { form: form, submitter: e.submitter || null };
    document.getElementById("confirm-text").textContent = msg;
    bootstrap.Modal.getOrCreateInstance(modal).show();
  });

  var ok = document.getElementById("confirm-ok");
  if (ok) {
    ok.addEventListener("click", function () {
      if (!pending) return;
      var p = pending;
      pending = null;
      bootstrap.Modal.getOrCreateInstance(document.getElementById("confirm-modal")).hide();
      p.form.dataset.confirmed = "1";
      if (p.form.requestSubmit) p.form.requestSubmit(p.submitter || undefined);
      else p.form.submit();
    });
    document.getElementById("confirm-modal").addEventListener("hidden.bs.modal", function () {
      pending = null;
    });
  }

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-print]")) window.print();
  });

  // Live refresh of <main>.
  document.addEventListener("input", function (e) {
    if (e.target.closest("form")) dirty = true;
  });

  function busy() {
    if (document.hidden || dirty) return true;
    if (document.querySelector(".modal.show")) return true;
    var a = document.activeElement;
    return !!(a && a.closest && a.closest("main") && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName));
  }

  function setUnread(n) {
    var link = document.getElementById("nav-events");
    if (!link) return;
    var badge = link.querySelector(".badge");
    if (n > 0) {
      if (!badge) {
        badge = document.createElement("span");
        badge.className = "badge text-bg-danger";
        link.appendChild(document.createTextNode(" "));
        link.appendChild(badge);
      }
      badge.textContent = String(n);
    } else if (badge) {
      badge.remove();
    }
  }

  function status(text) {
    var el = document.getElementById("live-status");
    if (el) el.textContent = text;
  }

  function refresh() {
    if (busy()) return;
    fetch(location.pathname + location.search, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "X-Honet-Partial": "1" }
    }).then(function (r) {
      if (r.status === 401) { location.reload(); return null; }
      if (!r.ok) { status("live (update failed)"); return null; }
      var n = parseInt(r.headers.get("X-Honet-Unread") || "", 10);
      if (!isNaN(n)) setUnread(n);
      return r.text();
    }).then(function (html) {
      if (html === null || html === undefined || busy()) return;
      main.innerHTML = html;
      status("live · updated " + new Date().toLocaleTimeString());
    }).catch(function () {
      status("live (offline)");
    });
  }

  var every = parseInt(document.body.getAttribute("data-live") || "0", 10);
  if (main && every > 0) {
    setInterval(refresh, every * 1000);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) refresh();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", showOnLoad);
  } else {
    showOnLoad();
  }
})();

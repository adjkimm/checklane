/* Checklane M1 audit widget. No frameworks. */
(function () {
  "use strict";

  var currentReport = null;
  var statusTimer = null;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---------------- score ring ---------------- */
  function scoreRing(score) {
    var r = 54, c = 2 * Math.PI * r;
    var color = score >= 70 ? "#1e7e46" : score >= 55 ? "#b7791f" : "#b3362b";
    return '<svg class="score-ring" width="130" height="130" viewBox="0 0 130 130">' +
      '<circle cx="65" cy="65" r="' + r + '" fill="none" stroke="#e2e9f0" stroke-width="12"/>' +
      '<circle cx="65" cy="65" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="12"' +
      ' stroke-linecap="round" stroke-dasharray="' + (c * score / 100).toFixed(1) + ' ' + c.toFixed(1) + '"' +
      ' transform="rotate(-90 65 65)"/>' +
      '<text x="65" y="62" text-anchor="middle" font-size="30" font-weight="700" fill="#16202b">' + score + '</text>' +
      '<text x="65" y="84" text-anchor="middle" font-size="12" fill="#5b6b7c">/ 100</text>' +
      '</svg>';
  }

  var PRICE_DISPLAY = "$9"; // updated from /api/config on load

  /* ---------------- report rendering ---------------- */
  /* Free version: the main score only. The full report unlocks after payment,
     or visitors can send a pre-sales question through the message box. */
  function buyBox(domain) {
    return '<div class="gate"><h3>Get the full report</h3>' +
      "<p>Your score is free. The full report has every check and every fix, " +
      "ranked by what matters most for <strong>" + esc(domain) + "</strong>.</p>" +
      '<div class="peek"><p class="peek-cap">A peek inside the report:</p>' +
      '<ul class="fix-preview"><li><span class="sev sev-high">High</span> Add structured product data <span class="redact">████████████</span></li>' +
      '<li><span class="sev sev-medium">Medium</span> Publish your sitemap <span class="redact">████████</span></li>' +
      '<li><span class="sev sev-low">Low</span> Fix canonical links <span class="redact">██████</span></li></ul>' +
      '<p class="micro">The full report names every check and ranks every fix.</p></div>' +
      '<button type="button" class="btn btn-large" id="buy-btn">Buy the full report: ' +
      esc(PRICE_DISPLAY) + "</button>" +
      '<p class="micro">Secure payment via Stripe. Your report opens right after payment, and a receipt with the report link is emailed to you. If you close the tab, use the email link or the &ldquo;lost your report?&rdquo; link below. 7-day satisfaction guarantee: not happy? Full refund, no questions asked. <a href="/refund">Read the guarantee</a>.</p>' +
      '<p class="micro">Lost your report? <a href="/lost-report">Get it re-sent</a> &middot; <a href="/terms">Terms</a> &middot; <a href="/privacy">Privacy</a> &middot; <a href="/refund">Refund policy</a></p>' +
      '<div class="field-err" id="buy-err"></div></div>';
  }

  function messageBox(domain) {
    return '<div class="gate gate-alt"><h3>Questions first?</h3>' +
      "<p>Have a question before you buy? Send us a message and we&rsquo;ll get back to you.</p>" +
      '<form id="message-form" autocomplete="on">' +
      '<div class="row2"><div><label for="message-name">Your name</label>' +
      '<input id="message-name" name="name" type="text" placeholder="Jordan Lee"></div>' +
      "<div><label for='message-email'>Email</label>" +
      '<input id="message-email" name="email" type="email" placeholder="you@yourstore.com"></div></div>' +
      '<div><label for="message-text">Message</label>' +
      '<textarea id="message-text" name="message" placeholder="What would you like to know about your score?"></textarea></div>' +
      '<div class="field-err" id="message-err"></div>' +
      '<button type="submit" class="btn">Send message</button></form>' +
      '<p class="micro" id="message-done" hidden>Message sent. We&rsquo;ll get back to you soon.</p></div>';
  }

  function scoreCard(report, minimal) {
    var ctas = minimal ? "" : buyBox(report.domain) + messageBox(report.domain);
    return '<div class="report-card">' +
      '<div class="score-row">' + scoreRing(report.score) +
      '<div class="score-meta"><h3><span class="grade grade-' + report.grade + '">' +
      report.grade + "</span>" + esc(report.domain) + "</h3>" +
      "<p>" + esc(report.summary) + "</p>" +
      "<p class=\"scoring-note\">Scoring updated Sep 2026: we now grade AI discoverability too, so this score isn\u2019t directly comparable to earlier audits.</p></div></div>" +
      ctas +
      "</div>";
  }

  /* The paid full report is served by /report as a print-ready HTML page
     (Download PDF button). It is never rendered inline here. */

  /* ---------------- audit flow ---------------- */
  var STATUS_LINES = [
    "Opening your homepage\u2026",
    "Checking your sitemap and site rules\u2026",
    "Reading your product info\u2026",
    "Visiting as nine AI crawlers and fetchers\u2026",
    "Seeing if AI can read your pages\u2026",
    "Building your fix list\u2026"
  ];

  function setStatus(i) {
    var el = $("audit-status");
    el.hidden = false;
    el.innerHTML =
      '<div class="loading-card">' +
      '<div class="spinner" aria-hidden="true"></div>' +
      '<h3>Checking your store\u2026</h3>' +
      '<div class="progress-track" aria-hidden="true"><div class="progress-bar"></div></div>' +
      '<p class="status-line">' + esc(STATUS_LINES[i % STATUS_LINES.length]) + '</p>' +
      '<p class="micro">This usually takes about a minute.</p>' +
      '</div>';
  }

  function runAudit(domain) {
    var resultEl = $("audit-result");
    var statusEl = $("audit-status");
    resultEl.hidden = true;
    resultEl.innerHTML = "";
    var i = 0;
    setStatus(i);
    clearInterval(statusTimer);
    statusTimer = setInterval(function () { i++; setStatus(i); }, 4000);

    fetch("/api/audit?domain=" + encodeURIComponent(domain))
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        clearInterval(statusTimer);
        statusEl.hidden = true;
        if (!res.ok || res.j.error) {
          resultEl.hidden = false;
          resultEl.innerHTML = '<div class="err"><strong>Couldn\u2019t check your store:</strong> ' +
            esc((res.j && res.j.error) || "unknown error") + "</div>";
          return;
        }
        currentReport = res.j;
        resultEl.hidden = false;
        resultEl.innerHTML = scoreCard(currentReport);
        wireBuyButton();
        wireMessageForm();
        resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (err) {
        clearInterval(statusTimer);
        statusEl.hidden = true;
        resultEl.hidden = false;
        resultEl.innerHTML = '<div class="err"><strong>Couldn\u2019t check your store:</strong> ' +
          esc(String(err)) + "</div>";
      });
  }

  function wireBuyButton() {
    var btn = $("buy-btn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      btn.disabled = true;
      var label = btn.innerHTML;
      btn.textContent = "Opening secure checkout\u2026";
      $("buy-err").textContent = "";
      fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_token: currentReport ? currentReport.report_token : ""
        })
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (!res.ok || !res.j.url) {
            btn.disabled = false;
            btn.innerHTML = label;
            $("buy-err").textContent = (res.j && res.j.error) ||
              "couldn't start checkout. Please try again";
            return;
          }
          window.location.href = res.j.url;
        })
        .catch(function (err) {
          btn.disabled = false;
          btn.innerHTML = label;
          $("buy-err").textContent = "Something went wrong: " + err;
        });
    });
  }

  function wireMessageForm() {
    var form = $("message-form");
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      btn.textContent = "Sending\u2026";
      $("message-err").textContent = "";
      var payload = {
        name: $("message-name").value,
        email: $("message-email").value,
        message: $("message-text").value,
        domain: currentReport ? currentReport.domain : ""
      };
      fetch("/api/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          btn.disabled = false;
          btn.textContent = "Send message";
          if (!res.ok) {
            var f = (res.j && res.j.fields) || {};
            var first = f.name || f.email || f.message ||
              (res.j && res.j.error) || "please check the form";
            $("message-err").textContent = first;
            return;
          }
          form.hidden = true;
          $("message-done").hidden = false;
        })
        .catch(function (err) {
          btn.disabled = false;
          btn.textContent = "Send message";
          $("message-err").textContent = "Something went wrong: " + err;
        });
    });
  }

  /* ---------------- init ---------------- */
  document.addEventListener("DOMContentLoaded", function () {
    // Public config (report price). Falls back to the $29 default above.
    fetch("/api/config").then(function (r) { return r.json(); }).then(function (cfg) {
      if (cfg && cfg.price_display) PRICE_DISPLAY = cfg.price_display;
    }).catch(function () {});

    $("audit-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var d = $("audit-domain").value.trim();
      if (!d) return;
      runAudit(d);
    });

    // Beta waiting list form (landing-page section).
    var betaForm = $("beta-form");
    if (betaForm) {
      betaForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var btn = betaForm.querySelector("button[type=submit]");
        btn.disabled = true;
        $("beta-err").textContent = "";
        fetch("/api/beta", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: $("beta-name").value,
            email: $("beta-email").value
          })
        })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            btn.disabled = false;
            if (!res.ok) {
              var f = (res.j && res.j.fields) || {};
              var first = f.name || f.email ||
                (res.j && res.j.error) || "please check the form";
              $("beta-err").textContent = first;
              return;
            }
            betaForm.hidden = true;
            $("beta-done").hidden = false;
          })
          .catch(function (err) {
            btn.disabled = false;
            $("beta-err").textContent = "Something went wrong: " + err;
          });
      });
    }

    // Services message form (landing-page section) -> /api/message.
    var svcForm = $("svc-form");
    if (svcForm) {
      svcForm.addEventListener("submit", function (e) {
        e.preventDefault();
        var btn = svcForm.querySelector("button[type=submit]");
        btn.disabled = true;
        btn.textContent = "Sending\u2026";
        $("svc-err").textContent = "";
        fetch("/api/message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: $("svc-name").value,
            email: $("svc-email").value,
            message: $("svc-text").value,
            domain: ""
          })
        })
          .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
          .then(function (res) {
            btn.disabled = false;
            btn.textContent = "Message us";
            if (!res.ok) {
              var f = (res.j && res.j.fields) || {};
              var first = f.name || f.email || f.message ||
                (res.j && res.j.error) || "please check the form";
              $("svc-err").textContent = first;
              return;
            }
            svcForm.hidden = true;
            $("svc-done").hidden = false;
          })
          .catch(function (err) {
            btn.disabled = false;
            btn.textContent = "Message us";
            $("svc-err").textContent = "Something went wrong: " + err;
          });
      });
    }

    // Returning from Stripe Checkout after a completed payment.
    // The full report lives at /report (print-ready HTML with a Download PDF
    // button); the server re-verifies the payment there.
    var params = new URLSearchParams(window.location.search);
    var sessionId = params.get("session_id");
    if (params.get("paid") && sessionId) {
      window.history.replaceState({}, "", "/");
      window.location = "/report?session_id=" + encodeURIComponent(sessionId);
    }

  });
})();

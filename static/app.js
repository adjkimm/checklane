/* Checklane M1 audit widget. No frameworks. */
(function () {
  "use strict";

  var FREEMAIL = { "gmail.com": 1, "yahoo.com": 1, "hotmail.com": 1, "outlook.com": 1,
    "aol.com": 1, "icloud.com": 1, "live.com": 1, "msn.com": 1,
    "protonmail.com": 1, "pm.me": 1 };

  var currentReport = null;
  var currentLeadId = null;
  var statusTimer = null;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function isFreemail(email) {
    var parts = String(email).toLowerCase().split("@");
    return parts.length === 2 && !!FREEMAIL[parts[1]];
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

  /* ---------------- report rendering ---------------- */
  function renderCategories(report) {
    return report.categories.map(function (cat) {
      var pct = cat.max ? Math.round(100 * cat.score / cat.max) : 0;
      var checks = cat.checks.map(function (ch) {
        var pill = '<span class="pill pill-' + ch.status + '">' + ch.status + "</span>";
        var fix = ch.fix ? '<p class="cfix"><strong>Fix:</strong> ' + esc(ch.fix) + "</p>" : "";
        return '<div class="check-row"><span class="cname">' + esc(ch.name) + "</span>" + pill +
          '<p class="cdetail">' + esc(ch.detail) + "</p>" + fix + "</div>";
      }).join("");
      return '<div class="cat"><div class="cat-head"><span>' + esc(cat.name) +
        "</span><span>" + cat.score + " / " + cat.max + "</span></div>" +
        '<div class="bar"><span style="width:' + pct + '%"></span></div>' +
        '<div class="cat-checks">' + checks + "</div></div>";
    }).join("");
  }

  function renderFixes(report) {
    if (!report.fixes || !report.fixes.length) {
      return '<p>No failing checks. Nice work — your store is in strong shape.</p>';
    }
    return "<ul class='fix-preview'>" + report.fixes.map(function (f) {
      return "<li><span class='sev sev-" + f.severity + "'>" + f.severity + "</span>" +
        "<strong>" + esc(f.check) + ".</strong> " + esc(f.fix) + "</li>";
    }).join("") + "</ul>";
  }

  function reportCard(report, opts) {
    opts = opts || {};
    var top3 = (report.fixes || []).slice(0, 3);
    var preview = top3.length
      ? "<h4>Top fixes</h4><ul class='fix-preview'>" + top3.map(function (f) {
          return "<li><span class='sev sev-" + f.severity + "'>" + f.severity + "</span>" +
            "<strong>" + esc(f.check) + ".</strong> " + esc(f.fix) + "</li>";
        }).join("") + "</ul>"
      : "";
    var body = '<div class="report-card">' +
      '<div class="score-row">' + scoreRing(report.score) +
      '<div class="score-meta"><h3><span class="grade grade-' + report.grade + '">' +
      report.grade + "</span>" + esc(report.domain) + "</h3>" +
      "<p>" + esc(report.summary) + "</p></div></div>" +
      renderCategories(report);
    if (!opts.full) {
      body += preview;
      body += '<div class="gate"><h3>Get the full report + fix list</h3>' +
        "<p>Enter your details and we&rsquo;ll unlock every check and the complete " +
        "ranked fix list for <strong>" + esc(report.domain) + "</strong>.</p>" +
        '<form id="lead-form" autocomplete="on">' +
        '<div><label for="lead-name">Your name</label>' +
        '<input id="lead-name" name="name" type="text" placeholder="Jordan Lee"></div>' +
        '<div class="row2"><div><label for="lead-business">Business name</label>' +
        '<input id="lead-business" name="business" type="text" placeholder="Blue Pine Goods"></div>' +
        "<div><label for='lead-email'>Work email</label>" +
        '<input id="lead-email" name="email" type="email" placeholder="you@yourstore.com"></div></div>' +
        '<div id="freemail-hint" class="freemail-hint" hidden>Heads up: our merchant ' +
        "counting uses business-domain emails — a Gmail/Yahoo address won&rsquo;t " +
        "count as a verifiable merchant. Use name@yourstore.com if you have one.</div>" +
        '<div class="field-err" id="lead-err"></div>' +
        '<button type="submit" class="btn">Unlock full report</button></form></div>';
    } else {
      body += "<h4>Ranked fix list</h4>" + renderFixes(report);
      body += '<div class="beta-box"><h3>Founding merchant beta</h3>' +
        '<p class="price">$29<span style="font-size:1rem;font-weight:400">/mo</span></p>' +
        "<p>Agent console — weekly checks of whether your products surface in AI " +
        "shopping answers, plus detected agent traffic on your own store. And the " +
        "Checklane authentication badge: an earned, verifiable identity credential " +
        "for your storefront. Cancel anytime.</p>" +
        '<label class="opt"><input type="checkbox" id="beta-opt"> ' +
        "<span><strong>Notify me</strong> when the founding-merchant beta opens. " +
        "No charge until you subscribe.</span></label>" +
        '<button class="btn" id="beta-btn">Request beta invite</button>' +
        '<p class="micro" id="beta-done" hidden style="color:#9fd9cd">You&rsquo;re on the list. ' +
        "We&rsquo;ll reach out when the beta opens.</p></div>";
    }
    return body + "</div>";
  }

  /* ---------------- audit flow ---------------- */
  var STATUS_LINES = [
    "Fetching your homepage\u2026",
    "Reading robots.txt and sitemap\u2026",
    "Checking structured product data\u2026",
    "Testing access as six AI-agent user agents\u2026",
    "Scoring machine-readability\u2026",
    "Compiling your fix list\u2026"
  ];

  function setStatus(i) {
    var el = $("audit-status");
    el.hidden = false;
    el.innerHTML = "<strong>Auditing\u2026</strong> " + esc(STATUS_LINES[i % STATUS_LINES.length]);
  }

  function runAudit(domain) {
    var resultEl = $("audit-result");
    var statusEl = $("audit-status");
    resultEl.hidden = true;
    resultEl.innerHTML = "";
    var i = 0;
    setStatus(i);
    clearInterval(statusTimer);
    statusTimer = setInterval(function () { i++; setStatus(i); }, 6000);

    fetch("/api/audit?domain=" + encodeURIComponent(domain))
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        clearInterval(statusTimer);
        statusEl.hidden = true;
        if (!res.ok || res.j.error) {
          resultEl.hidden = false;
          resultEl.innerHTML = '<div class="err"><strong>Audit failed:</strong> ' +
            esc((res.j && res.j.error) || "unknown error") + "</div>";
          return;
        }
        currentReport = res.j;
        currentLeadId = null;
        resultEl.hidden = false;
        resultEl.innerHTML = reportCard(currentReport, { full: false });
        wireLeadForm();
        resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (err) {
        clearInterval(statusTimer);
        statusEl.hidden = true;
        resultEl.hidden = false;
        resultEl.innerHTML = '<div class="err"><strong>Audit failed:</strong> ' +
          esc(String(err)) + "</div>";
      });
  }

  function wireLeadForm() {
    var form = $("lead-form");
    if (!form) return;
    var emailInput = $("lead-email");
    emailInput.addEventListener("input", function () {
      $("freemail-hint").hidden = !isFreemail(emailInput.value);
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true;
      $("lead-err").textContent = "";
      var payload = {
        name: $("lead-name").value,
        business: $("lead-business").value,
        email: $("lead-email").value,
        domain: currentReport.domain
      };
      fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          btn.disabled = false;
          if (!res.ok) {
            var f = (res.j && res.j.fields) || {};
            var first = f.name || f.business || f.email || f.domain ||
              (res.j && res.j.error) || "please check the form";
            $("lead-err").textContent = first;
            return;
          }
          currentLeadId = res.j.lead_id;
          var note = res.j.note
            ? '<p class="micro" style="color:#7a5c14">' + esc(res.j.note) + "</p>" : "";
          $("audit-result").innerHTML = note + reportCard(currentReport, { full: true });
          wireBetaBox();
          $("audit-result").scrollIntoView({ behavior: "smooth", block: "start" });
        })
        .catch(function (err) {
          btn.disabled = false;
          $("lead-err").textContent = "Something went wrong: " + err;
        });
    });
  }

  function wireBetaBox() {
    var btn = $("beta-btn");
    if (!btn) return;
    btn.addEventListener("click", function () {
      if (!$("beta-opt").checked) {
        btn.textContent = "Tick the checkbox first";
        setTimeout(function () { btn.textContent = "Request beta invite"; }, 1600);
        return;
      }
      btn.disabled = true;
      fetch("/api/beta", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lead_id: currentLeadId })
      }).then(function () {
        $("beta-done").hidden = false;
        btn.textContent = "Invite requested";
      }).catch(function () {
        btn.disabled = false;
        btn.textContent = "Try again";
      });
    });
  }

  /* ---------------- init ---------------- */
  document.addEventListener("DOMContentLoaded", function () {
    $("audit-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var d = $("audit-domain").value.trim();
      if (!d) return;
      runAudit(d);
    });

    // Anonymized sample report (static JSON, rendered read-only).
    fetch("/sample-report").then(function (r) { return r.json(); }).then(function (rep) {
      $("sample-report").innerHTML = reportCard(rep, { full: true });
      var beta = $("sample-report").querySelector(".beta-box");
      if (beta) beta.remove(); // sample has no beta CTA
    }).catch(function () {
      $("sample-report").innerHTML = '<p class="loading">Sample report unavailable in this demo.</p>';
    });
  });
})();

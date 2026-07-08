(function () {
  "use strict";

  // Transforms the Overview table on CTF challenge pages into a compact
  // horizontal metadata card. The ## Overview heading is kept for the ToC.
  // Only runs on pages 4 segments deep under /ctfs/ (i.e. not event index pages).

  function transform() {
    var parts = window.location.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (parts.length < 4 || parts[0] !== "ctfs") return;

    var headers = document.querySelectorAll(".md-content__inner h2");
    var h2 = null;
    for (var i = 0; i < headers.length; i++) {
      if (headers[i].textContent.trim() === "Overview") { h2 = headers[i]; break; }
    }
    if (!h2) return;

    var table = h2.nextElementSibling;
    if (!table || table.tagName !== "TABLE") return;

    var order = [];
    var meta  = {};
    table.querySelectorAll("tr").forEach(function (row) {
      var cells = row.querySelectorAll("td");
      if (cells.length === 2) {
        var key = cells[0].textContent.replace(/\*/g, "").trim();
        if (key) { meta[key] = cells[1].innerHTML.trim(); order.push(key); }
      }
    });

    var card = document.createElement("div");
    card.className = "challenge-card";

    card.innerHTML = order.map(function (key) {
      return (
        '<span class="challenge-card__item">' +
          '<span class="challenge-card__key">' + key + '</span>' +
          '<span class="challenge-card__val">' + meta[key] + '</span>' +
        '</span>'
      );
    }).join('<span class="challenge-card__sep">·</span>');

    table.replaceWith(card);
  }

  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(transform);
  } else if (document.readyState !== "loading") {
    transform();
  } else {
    document.addEventListener("DOMContentLoaded", transform);
  }
})();

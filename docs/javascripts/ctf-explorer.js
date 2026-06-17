(function () {
  "use strict";

  // ── Explorer filter ────────────────────────────────────────────────────────
  // Handles .ctf-explorer blocks: search + event dropdown + category chips.

  function buildExplorer(root) {
    if (root.dataset.explorerReady) return;
    var list = root.querySelector("ul");
    if (!list) return;
    var items = Array.prototype.slice.call(list.children);
    if (!items.length) return;
    root.dataset.explorerReady = "1";

    var events = [];
    var eventTitles = {};
    var cats = [];

    items.forEach(function (li) {
      var a = li.querySelector("a[data-event]");
      li._event      = a ? a.getAttribute("data-event") : "";
      li._eventTitle = a ? (a.getAttribute("data-event-title") || li._event) : "";
      li._cat        = a ? a.getAttribute("data-category") : "";
      li._text       = (li.textContent || "").toLowerCase();

      if (li._event && events.indexOf(li._event) < 0) {
        events.push(li._event);
        eventTitles[li._event] = li._eventTitle;
      }
      if (li._cat && cats.indexOf(li._cat) < 0) cats.push(li._cat);

      if (li._cat || li._eventTitle) {
        var tag = document.createElement("span");
        tag.className = "explorer-meta";
        tag.textContent = [li._cat, li._eventTitle].filter(Boolean).join(" · ");
        li.appendChild(tag);
      }

      li.style.cursor = "pointer";
      li.addEventListener("click", function (e) {
        if (e.target.closest && e.target.closest("a")) return;
        var link = li.querySelector("a");
        if (link) link.click();
      });
    });
    cats.sort();

    var activeEvent = "all";
    var activeCat   = "all";
    var catChipEls  = {};

    var bar = document.createElement("div");
    bar.className = "ctf-toolbar explorer-toolbar";

    var topRow = document.createElement("div");
    topRow.className = "explorer-top-row";

    var search = document.createElement("input");
    search.type = "search";
    search.className = "ctf-search";
    search.placeholder = "Search challenges…";
    search.setAttribute("aria-label", "Search challenges");
    topRow.appendChild(search);

    if (events.length > 1) {
      var sel = document.createElement("select");
      sel.className = "explorer-event-select";
      sel.setAttribute("aria-label", "Filter by event");
      var optAll = document.createElement("option");
      optAll.value = "all";
      optAll.textContent = "All Events";
      sel.appendChild(optAll);
      events.forEach(function (slug) {
        var opt = document.createElement("option");
        opt.value = slug;
        opt.textContent = eventTitles[slug] || slug;
        sel.appendChild(opt);
      });
      sel.addEventListener("change", function () { activeEvent = sel.value; render(); });
      topRow.appendChild(sel);
    }

    bar.appendChild(topRow);

    if (cats.length) {
      var catRow = document.createElement("div");
      catRow.className = "ctf-chips";
      ["all"].concat(cats).forEach(function (cat) {
        var b = document.createElement("button");
        b.type = "button";
        b.className = "ctf-chip";
        b.textContent = cat === "all" ? "All" : cat;
        b.addEventListener("click", function () { activeCat = cat; render(); });
        catRow.appendChild(b);
        catChipEls[cat] = b;
      });
      bar.appendChild(catRow);
    }

    root.insertBefore(bar, root.firstChild);

    var empty = document.createElement("p");
    empty.className = "ctf-empty";
    empty.textContent = "No challenges match.";
    empty.hidden = true;
    root.appendChild(empty);

    function render() {
      var q = search.value.trim().toLowerCase();
      var shown = 0;
      items.forEach(function (li) {
        var ok = (activeEvent === "all" || li._event === activeEvent) &&
                 (activeCat  === "all" || li._cat   === activeCat)   &&
                 (!q || li._text.indexOf(q) >= 0);
        li.hidden = !ok;
        if (ok) shown++;
      });
      empty.hidden = shown > 0;
      Object.keys(catChipEls).forEach(function (k) {
        catChipEls[k].classList.toggle("on", k === activeCat);
      });
    }

    search.addEventListener("input", render);
    render();
  }

  // ── Boot ──────────────────────────────────────────────────────────────────

  function boot() {
    document.querySelectorAll(".ctf-explorer").forEach(buildExplorer);
  }

  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(boot);
  } else if (document.readyState !== "loading") {
    boot();
  } else {
    document.addEventListener("DOMContentLoaded", boot);
  }
})();

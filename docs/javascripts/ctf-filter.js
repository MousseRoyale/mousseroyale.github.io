(function () {
  "use strict";

  // Reusable CTF challenge index. Any `.ctf-index` block that wraps a Markdown
  // list of challenge links gets a search box + category chips prepended.
  // Authoring (directory-agnostic, scales as challenges are added):
  //
  //   <div class="ctf-index" markdown>
  //   - [Title](path.md){ data-category="Web" data-keywords="sqli auth" } — short summary.
  //   </div>
  //
  // Categories are derived from the links' data-category, so a new category
  // appears as a chip automatically the moment a challenge uses it.

  function build(root) {
    if (root.dataset.ctfReady) return;          // guard against re-runs
    var list = root.querySelector("ul");
    if (!list) return;
    var items = Array.prototype.slice.call(list.children);
    if (!items.length) return;
    root.dataset.ctfReady = "1";

    var cats = [];
    items.forEach(function (li) {
      var a = li.querySelector("a[data-category]");
      li._cat = a ? a.getAttribute("data-category") : "";
      li._text = (li.textContent || "").toLowerCase();
      if (li._cat && cats.indexOf(li._cat) < 0) cats.push(li._cat);
    });
    cats.sort();

    var bar = document.createElement("div");
    bar.className = "ctf-toolbar";

    var search = document.createElement("input");
    search.type = "search";
    search.className = "ctf-search";
    search.placeholder = "Search challenges\u2026";
    search.setAttribute("aria-label", "Search challenges");

    var chips = document.createElement("div");
    chips.className = "ctf-chips";

    var active = "All";
    var chipEls = {};
    function addChip(label) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "ctf-chip";
      b.textContent = label;
      b.addEventListener("click", function () { active = label; render(); });
      chips.appendChild(b);
      chipEls[label] = b;
    }
    ["All"].concat(cats).forEach(addChip);

    bar.appendChild(search);
    if (cats.length) bar.appendChild(chips);
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
        var ok = (active === "All" || li._cat === active) &&
                 (!q || li._text.indexOf(q) >= 0);
        li.hidden = !ok;
        if (ok) shown++;
      });
      empty.hidden = shown > 0;
      Object.keys(chipEls).forEach(function (l) {
        chipEls[l].classList.toggle("on", l === active);
      });
    }

    search.addEventListener("input", render);
    render();
  }

  function boot() {
    document.querySelectorAll(".ctf-index").forEach(build);
  }

  // Material instant navigation swaps the DOM without a full reload.
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(boot);
  } else if (document.readyState !== "loading") {
    boot();
  } else {
    document.addEventListener("DOMContentLoaded", boot);
  }
})();

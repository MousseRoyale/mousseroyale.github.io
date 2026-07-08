(function () {
  "use strict";

  // Source of Truth §2 — Prompt-Aware Clipboard Logic.
  //
  // In simulated terminal / shell-session code blocks the "Copy" button must
  // hand back ONLY the clean, executable command string: never the prompt
  // prefix, never the command output.
  //
  // Implementation: we pre-compute the clean text and attach it to Material's
  // existing copy button via ClipboardJS's `data-clipboard-text`, which takes
  // priority over `data-clipboard-target`. This reuses the global, theme-owned
  // copy utility (and keeps its native "Copied" feedback) instead of bolting a
  // bespoke copier onto the page — fully decoupled from page content.
  //
  // Pygments emits:
  //   .gp  generic prompt  ($, #, or a custom PS1)
  //   .go  generic output  (everything the command printed)
  // An explicit `.command-text` wrapper, if present, is honoured first.

  function codeFor(btn) {
    var sel = btn.getAttribute("data-clipboard-target");
    if (sel) {
      var node = document.querySelector(sel);
      if (node) return node.tagName === "CODE" ? node : (node.querySelector("code") || node);
    }
    var wrap = btn.closest(".highlight, pre") || btn.parentElement;
    return wrap ? wrap.querySelector("code") : null;
  }

  // Returns the clean command string, or null when this block is not a shell
  // session — in which case Material's default whole-block copy is left alone.
  function cleanCommand(code) {
    if (!code) return null;

    // 1. Explicit opt-in: author-marked command spans.
    var explicit = code.querySelectorAll(".command-text");
    if (explicit.length) {
      return Array.prototype.map.call(explicit, function (n) { return n.textContent; })
        .join("\n").replace(/[ \t]+$/gm, "").replace(/\n{2,}/g, "\n").trim();
    }

    // 2. Shell session: only act if there is a prompt or output to strip.
    if (!code.querySelector(".gp, .go")) return null;

    var clone = code.cloneNode(true);
    Array.prototype.forEach.call(clone.querySelectorAll(".gp, .go"), function (n) {
      n.parentNode.removeChild(n);
    });

    return clone.textContent
      .split("\n")
      .map(function (line) { return line.replace(/[ \t]+$/, ""); })
      .filter(function (line) { return line.trim() !== ""; })
      .join("\n")
      .trim();
  }

  function prime(target) {
    var btn = target && target.closest ? target.closest(".md-clipboard") : null;
    if (!btn) return;
    var text = cleanCommand(codeFor(btn));
    if (text) btn.setAttribute("data-clipboard-text", text);
    else btn.removeAttribute("data-clipboard-text");
  }

  // Prime on activation, before ClipboardJS reads the attribute on click.
  document.addEventListener("pointerdown", function (e) { prime(e.target); }, true);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") prime(e.target);
  }, true);
})();

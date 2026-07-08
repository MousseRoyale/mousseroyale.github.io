/*
 * command-highlight.js
 * ---------------------
 * Site-wide command-line colouring for terminal (console) code blocks.
 *
 * Material/pymdownx does NOT put a `language-*` class on the rendered block,
 * so we detect a terminal session by the thing that is reliably there: the
 * Pygments prompt span (`.gp`, e.g. "$ "). Any code block containing a prompt
 * is treated as a shell session; its command lines get coloured, its output
 * (`.go`) is left alone.
 *
 * What it does: after a page renders, it wraps the bare command tokens in
 * <span> elements with one of three classes — .cmd-name, .cmd-opt, .cmd-arg —
 * which extra.css then colours.
 *
 * Why it's safe to live in docs/javascripts/:
 *   - Progressive enhancement only. It WRAPS existing text; it never adds or
 *     removes characters, so the Copy button's output is byte-for-byte
 *     unchanged. If the script doesn't load, blocks keep the normal theme.
 *   - Idempotent (re-running is a no-op) and scoped to prompt blocks only, so
 *     it never touches your python/yaml/etc. code.
 *   - Heuristic, not a bash parser: first word = command, -x/--xyz = option,
 *     the rest = arguments. A small wrapper list (sudo, env, ...) passes the
 *     command-name role through to the next word.
 */
(function () {
  "use strict";

  var OPTION = /^-{1,2}[^\s=]/;     // -sV, -p, --min-rate, --color=auto
  var SPLIT = /(\s+)/;              // split but keep the whitespace chunks

  // Wrappers that precede the "real" command: colour them as the command name
  // but let the next word also claim command-name (so `sudo nmap` colours both
  // sensibly, with nmap as the command).
  var PASSTHROUGH = { sudo: 1, doas: 1, env: 1, time: 1, command: 1, exec: 1,
                      nice: 1, ionice: 1, watch: 1, xargs: 1, sh: 1, bash: 1 };

  function isWhitespace(s) { return /^\s+$/.test(s); }

  function wrap(text, cls) {
    var span = document.createElement("span");
    span.className = cls;
    span.textContent = text;
    return span;
  }

  function classify(word, state) {
    if (OPTION.test(word)) return "cmd-opt";
    if (!state.sawCmd) {
      // a passthrough wrapper is a command name, but doesn't consume the slot
      if (!Object.prototype.hasOwnProperty.call(PASSTHROUGH, word)) state.sawCmd = true;
      return "cmd-name";
    }
    return "cmd-arg";
  }

  // A newline ends the current command segment; we then wait for the next
  // prompt before colouring again.
  function newline(state) { state.inCmd = false; state.sawCmd = false; }

  function colourTextNode(node, state) {
    var parts = node.textContent.split(SPLIT);
    var frag = document.createDocumentFragment();
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (part === "") continue;
      if (isWhitespace(part)) {
        if (part.indexOf("\n") !== -1) newline(state);
        frag.appendChild(document.createTextNode(part));
        continue;
      }
      if (!state.inCmd) { frag.appendChild(document.createTextNode(part)); continue; }
      frag.appendChild(wrap(part, classify(part, state)));
    }
    node.parentNode.replaceChild(frag, node);
  }

  function process(code) {
    if (code.hasAttribute("data-cmdhl")) return;          // idempotent
    var state = { inCmd: false, sawCmd: false };
    var children = Array.prototype.slice.call(code.childNodes);
    for (var i = 0; i < children.length; i++) {
      var child = children[i];
      if (child.nodeType === 1) {                          // element node
        var cls = " " + (child.className || "") + " ";
        if (cls.indexOf(" gp ") !== -1) { state.inCmd = true; state.sawCmd = false; continue; } // prompt
        if (cls.indexOf(" go ") !== -1) { state.inCmd = false; state.sawCmd = false; continue; } // output
        if (cls.indexOf(" w ") !== -1) {                   // whitespace span
          if (child.textContent.indexOf("\n") !== -1) newline(state);
          continue;
        }
        // Other spans (.m number, .s string, .nb builtin) count as a word only
        // if they actually contain text. Skip empty nodes and <a> line anchors.
        if (state.inCmd && child.textContent && child.textContent.trim() &&
            !state.sawCmd && !OPTION.test(child.textContent)) {
          state.sawCmd = true;
        }
        continue;
      }
      if (child.nodeType === 3) colourTextNode(child, state); // text node
    }
    code.setAttribute("data-cmdhl", "");
  }

  function run(root) {
    var codes = (root || document).querySelectorAll(".highlight pre code");
    for (var i = 0; i < codes.length; i++) {
      if (codes[i].querySelector(".gp")) process(codes[i]);   // only prompt blocks
    }
  }

  // Material swaps page content via its `document$` observable when instant
  // navigation is on; subscribe so colouring re-applies after each navigation.
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(function () { run(document); });
  } else if (document.readyState !== "loading") {
    run(document);
  } else {
    document.addEventListener("DOMContentLoaded", function () { run(document); });
  }
})();
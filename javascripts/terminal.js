(function () {
  "use strict";

  var USER = "mousseroyale";
  var HOST = "repository";
  var NAME = "MousseRoyale";              // display name (whoami)
  var PROMPT = USER + "@" + HOST + ":~$";

  // section name -> relative URL (works at site root or under a subpath)
  var ROUTES = {
    writeups: "writeups/",
    ctfs: "ctfs/",
    labs: "labs/",
    cheatsheets: "cheatsheets/",
    explanations: "explanations/",
    tags: "tags/"
  };

  var BIO = "I poke at things and write down what happens.";

  function boot() {
    var screen = document.getElementById("cv-screen");
    if (!screen) return;

    var out = document.createElement("div");
    out.id = "cv-out";
    screen.appendChild(out);

    var line = document.createElement("div");
    line.className = "cv-line";
    var ps = document.createElement("span");
    ps.className = "cv-prompt";
    ps.textContent = PROMPT;
    var input = document.createElement("input");
    input.id = "cv-in";
    input.className = "cv-input";
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("spellcheck", "false");
    input.setAttribute("aria-label", "terminal command input");
    line.appendChild(ps);
    line.appendChild(input);
    screen.appendChild(line);

    var history = [];
    var hi = 0;

    function print(text, cls) {
      var row = document.createElement("div");
      row.className = "cv-row" + (cls ? " " + cls : "");
      row.textContent = text;
      out.appendChild(row);
    }

    function printHTML(html) {
      var row = document.createElement("div");
      row.className = "cv-row";
      row.innerHTML = html;
      out.appendChild(row);
    }

    function echo(cmd) {
      printHTML('<span class="cv-prompt">' + PROMPT + '</span> <span class="cv-cmd">' +
        cmd.replace(/&/g, "&amp;").replace(/</g, "&lt;") + "</span>");
    }

    function go(path) {
      print("opening " + path + " ...", "cv-out");
      window.location.assign(path);
    }

    function run(raw) {
      var cmd = raw.trim();
      if (!cmd) return;
      echo(cmd);
      var parts = cmd.split(/\s+/);
      var name = parts[0].toLowerCase();
      var arg = (parts[1] || "").toLowerCase().replace(/\/$/, "");

      if (name === "help") {
        print("available commands:", "cv-out");
        print("  ls                list sections", "cv-out");
        print("  cd <section>      open a section  (e.g. cd writeups)", "cv-out");
        print("  cat about.txt     print bio", "cv-out");
        print("  whoami            who am i", "cv-out");
        print("  tags              browse by tag", "cv-out");
        print("  clear             clear the screen", "cv-out");
        print("  help              show this message", "cv-out");
        print("tip: you can also just type a section name and press enter.", "cv-out");
      } else if (name === "ls" || name === "ll" || name === "dir") {
        printHTML(
          '<span class="cv-dir">writeups/</span>  <span class="cv-dir">ctfs/</span>  ' +
          '<span class="cv-dir">labs/</span>  <span class="cv-dir">cheatsheets/</span>  ' +
          '<span class="cv-dir">explanations/</span>  <span class="cv-dir">tags/</span>'
        );
      } else if (name === "cd" || name === "open" || name === "go") {
        if (!arg || arg === "~" || arg === "." || arg === "..") {
          print("you're home.", "cv-out");
        } else if (ROUTES[arg]) {
          go(ROUTES[arg]);
        } else {
          print("cd: no such section: " + arg, "cv-err");
        }
      } else if (name === "cat") {
        if (arg === "about.txt" || arg === "about") {
          print(BIO, "cv-out");
        } else if (!arg) {
          print("usage: cat about.txt", "cv-out");
        } else {
          print("cat: " + parts[1] + ": no such file", "cv-err");
        }
      } else if (name === "whoami") {
        print(NAME, "cv-out");
      } else if (name === "pwd") {
        print("/home/" + USER, "cv-out");
      } else if (name === "clear" || name === "cls") {
        out.innerHTML = "";
      } else if (ROUTES[name]) {
        go(ROUTES[name]);
      } else {
        print("zsh: command not found: " + name + "  (try: help)", "cv-err");
      }
    }

    function banner() {
      print("Type help to get started, or ls to see what's here.", "cv-out");
    }

    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        var v = input.value;
        if (v.trim()) { history.push(v); hi = history.length; }
        input.value = "";
        run(v);
        screen.scrollTop = screen.scrollHeight;
      } else if (e.key === "ArrowUp") {
        if (hi > 0) { hi--; input.value = history[hi] || ""; }
        e.preventDefault();
      } else if (e.key === "ArrowDown") {
        if (hi < history.length) { hi++; input.value = history[hi] || ""; }
        e.preventDefault();
      }
    });

    var term = document.getElementById("cv-term");
    if (term) {
      term.addEventListener("click", function () { input.focus({ preventScroll: true }); });
    }

    banner();
    input.focus({ preventScroll: true });
  }

  if (document.readyState !== "loading") boot();
  else document.addEventListener("DOMContentLoaded", boot);
})();

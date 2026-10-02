(function () {
  "use strict";

  function openExternalLinksInNewTab() {
    document.querySelectorAll("a[href]").forEach(function (a) {
      var href = a.getAttribute("href");
      if (href && (href.startsWith("http://") || href.startsWith("https://")) &&
          !href.startsWith(window.location.origin)) {
        a.setAttribute("target", "_blank");
        a.setAttribute("rel", "noopener noreferrer");
      }
    });
  }

  if (document.readyState !== "loading") openExternalLinksInNewTab();
  else document.addEventListener("DOMContentLoaded", openExternalLinksInNewTab);
})();

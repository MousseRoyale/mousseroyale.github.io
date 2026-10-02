(function () {
  "use strict";

  // Material puts the logo before the drawer toggle in the DOM.
  // On mobile both are visible, so we move the toggle first so the
  // hamburger appears left of the logo rather than right of it.
  function fixMobileHeader() {
    var inner  = document.querySelector(".md-header__inner");
    var drawer = inner && inner.querySelector("label[for='__drawer']");
    var logo   = inner && inner.querySelector(".md-header__button.md-logo");
    if (drawer && logo && inner.firstElementChild !== drawer) {
      inner.insertBefore(drawer, inner.firstElementChild);
    }
  }

  if (document.readyState !== "loading") fixMobileHeader();
  else document.addEventListener("DOMContentLoaded", fixMobileHeader);
})();

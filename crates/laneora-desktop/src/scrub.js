function remover() {
  if (!document.getElementById("laneora-soft-hide")) {
    var css = document.createElement("style");
    css.id = "laneora-soft-hide";
    css.textContent = [
      ".nav-links,dat-worklist-controls,dat-certificate-of-insurance-banner,.certificate-banner-container,",
      "connected-email-connect-cta,connected-email-connect-button,connected-email-connect-modal,",
      "dat-load-details .mat-icon:empty,dat-load-details mat-icon:empty,",
      ".expanded-detail-row .mat-icon:empty,.expanded-detail-row mat-icon:empty,",
      ".table-row-detail .mat-icon:empty,.details-container .mat-icon:empty,",
      'dat-load-details img[src=""],dat-load-details img:not([src]),',
      ".origin-destination mat-icon,.route-arrow,.trip-arrow",
      "{display:none!important;width:0!important;height:0!important;overflow:hidden!important;}"
    ].join("");
    (document.head || document.documentElement).appendChild(css);
  }
  if (location.hostname === "one.dat.com") {
    var path = location.pathname || "/";
    var other = /\/(dashboard|company|my-company|my-trucks|my-loads|private-network|tools|notifications|my-account|support)(\/|$)/i;
    if (path.indexOf("/search-loads") !== 0 && other.test(path)) {
      var now = Date.now();
      if (!window.__laneoraHop || now - window.__laneoraHop > 8000) {
        window.__laneoraHop = now;
        location.replace("https://one.dat.com/search-loads");
        return;
      }
    }
  }
  document.querySelectorAll(
    ".nav-links, dat-worklist-controls, dat-certificate-of-insurance-banner, .certificate-banner-container, connected-email-connect-cta, connected-email-connect-button, connected-email-connect-modal"
  ).forEach(function (el) { el.remove(); });
  document.querySelectorAll("a, button").forEach(function (el) {
    var t = (el.textContent || "").trim().toLowerCase();
    if (t === "book" || t === "book load" || t === "prefer" || t === "block" || t === "connect email" || t === "sign in with microsoft" || t === "sign in with google") {
      el.remove();
    }
  });
  var oops = /logged in on another device|login anyway/i;
  document.querySelectorAll(
    ".usurpModal, .ui-widget-overlay, .cdk-overlay-backdrop, .cdk-overlay-pane, .mat-dialog-container"
  ).forEach(function (el) {
    var t = el.innerText || "";
    if (oops.test(t) || el.classList.contains("cdk-overlay-backdrop") || el.classList.contains("usurpModal") || el.classList.contains("ui-widget-overlay")) {
      el.remove();
    }
  });
}
setInterval(remover, 150);

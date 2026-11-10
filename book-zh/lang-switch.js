// Language switcher: adds a nav-bar button that jumps to the same page in the
// other language. Derives the site root from this script's own URL, so it works
// both for a local build served at "/" and for a GitHub Pages project site at
// "/<repo>/".
(function () {
  var script = document.currentScript;
  var src = script && script.src ? script.src : "";
  var base = src.slice(0, src.lastIndexOf("/") + 1); // absolute URL of site root
  var here = location.href.split("#")[0].split("?")[0];
  var zhPrefix = base + "zh/";
  var target = null;
  var label = "";
  if (here.indexOf(zhPrefix) === 0) {
    target = base + here.slice(zhPrefix.length);
    label = "EN";
  } else if (here.indexOf(base) === 0) {
    target = zhPrefix + here.slice(base.length);
    label = "中文";
  }
  if (!target) {
    return;
  }
  var link = document.createElement("a");
  link.href = target;
  link.textContent = label;
  link.className = "lang-switch";
  link.title = label === "EN" ? "Read in English" : "切换到中文";
  link.setAttribute("aria-label", link.title);

  function mount() {
    var anchor = document.querySelector(".right-buttons") ||
      document.getElementById("menu-bar");
    if (anchor && !document.querySelector(".lang-switch")) {
      anchor.insertBefore(link, anchor.firstChild);
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();

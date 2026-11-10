// Language switcher: adds a nav-bar button that jumps to the same page in the
// other language.
//
// Both books are built from the same file set, so this script must work out which
// book it is running in. It does that from its OWN url: additional-js files land in
// the root of each book's output, so the script's directory IS this book's root —
// which is "<site>/" for English and "<site>/zh/" for Chinese. Deriving the site
// root from "strip /zh/" (rather than assuming the script sits at the site root)
// is what keeps /zh/ pages from linking to /zh/zh/.
(function () {
  var script = document.currentScript;
  var src = script && script.src ? script.src : "";
  var bookRoot = src.slice(0, src.lastIndexOf("/") + 1); // absolute, this book's root

  var here = location.href.split("#")[0].split("?")[0];
  if (bookRoot === "" || here.indexOf(bookRoot) !== 0) {
    return;
  }
  var relPath = here.slice(bookRoot.length);

  var isChinese = /\/zh\/$/.test(bookRoot);
  var target, label, title;
  if (isChinese) {
    // Strip the trailing "zh/" to get the site root, then reuse the same relative path.
    target = bookRoot.slice(0, -3) + relPath;
    label = "EN";
    title = "Read in English";
  } else {
    target = bookRoot + "zh/" + relPath;
    label = "中文";
    title = "切换到中文";
  }

  var link = document.createElement("a");
  link.href = target;
  link.textContent = label;
  link.className = "lang-switch";
  link.title = title;
  link.setAttribute("aria-label", title);

  function mount() {
    var anchor =
      document.querySelector(".right-buttons") ||
      document.getElementById("mdbook-menu-bar") ||
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

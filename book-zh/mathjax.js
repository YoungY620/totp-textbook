// MathJax 4 setup for mdBook. Loaded as an additional-js file from the book root.
// `displayOverflow: 'linebreak'` (MathJax 4) lets long display equations wrap.
(function () {
  window.MathJax = {
    tex: {
      inlineMath: [["$", "$"], ["\\(", "\\)"]],
      displayMath: [["$$", "$$"], ["\\[", "\\]"]],
      processEscapes: true,
      tags: "none",
      macros: {
        KT: "\\mathrm{K_T}",
        truncate: "\\mathrm{DT}"
      }
    },
    options: {
      skipHtmlTags: ["script", "noscript", "style", "textarea", "pre", "code"],
      ignoreHtmlClass: "tex2jax_ignore"
    },
    chtml: {
      scale: 1.03,
      displayOverflow: "linebreak",
      linebreaks: { inline: false, width: "100%" }
    },
    startup: {
      typeset: true,
      pageReady: function () {
        return MathJax.startup.defaultPageReady().then(function () {
          document.documentElement.setAttribute("data-mathjax-ready", "true");
        });
      }
    }
  };
  var s = document.createElement("script");
  s.src = "https://cdn.jsdelivr.net/npm/mathjax@4/tex-chtml.js";
  s.async = true;
  document.head.appendChild(s);
})();

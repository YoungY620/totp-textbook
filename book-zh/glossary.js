// Wikipedia-style glossary hover cards.
//
// Every entry is {en, zh, short_en, short_zh}: `en`/`zh` are the terms to wrap
// in body text, `short_*` is the one-line gloss shown in the card. Terms are
// wrapped only after MathJax has finished (so we never touch rendered formulas),
// never inside code, links, headings or existing cards, and at most a few times
// per page so the prose does not turn into a sea of dots.
(function () {
  var TERMS = [
    { en: ["one-time password", "OTP"], zh: ["一次性密码", "OTP"],
      short_en: "A password valid for a single login and then discarded.",
      short_zh: "只在一个会话中有效、用完即弃的密码。" },
    { en: ["hash chain"], zh: ["哈希链"],
      short_en: "w_n = H(w_{n+1}); revealing terms in reverse order, each verifiable by one hash.",
      short_zh: "w_n = H(w_{n+1})；逆序逐个公开，每个值都可用一次哈希验证。" },
    { en: ["HMAC"], zh: ["HMAC"],
      short_en: "Keyed message authentication code built from a hash function; the core of HOTP/TOTP.",
      short_zh: "基于哈希函数的带密钥消息认证码，HOTP/TOTP 的核心。" },
    { en: ["hotp", "counter-based one-time password"], zh: ["HOTP", "基于计数器的一次性密码"],
      short_en: "RFC 4226: an HMAC-SHA-1 value over a shared key and an incrementing counter.",
      short_zh: "RFC 4226：以共享密钥与递增计数器为输入的 HMAC-SHA-1 值。" },
    { en: ["totp", "time-based one-time password"], zh: ["TOTP", "基于时间的一次性密码"],
      short_en: "RFC 6238: HOTP with the counter derived from the current time step (usually 30 s).",
      short_zh: "RFC 6238：把 HOTP 的计数器换成时间步长（通常 30 秒）后的算法。" },
    { en: ["shared secret", "seed"], zh: ["共享密钥", "种子"],
      short_en: "The secret provisioned to both authenticator and server; its compromise yields future codes.",
      short_zh: "同时下发给验证器与服务端的秘密；一旦泄露即可生成未来的验证码。" },
    { en: ["two-factor authentication", "2FA"], zh: ["双因素认证", "2FA"],
      short_en: "Authentication requiring something you know plus something you have.",
      short_zh: "要求「你知道的东西」加「你拥有的东西」的认证。" },
    { en: ["phishing"], zh: ["钓鱼"],
      short_en: "Tricking the user into submitting credentials — including live OTPs — to an attacker.",
      short_zh: "诱骗用户把凭据（包括实时验证码）交给攻击者。" },
    { en: ["webauthn", "passkey", "fido2"], zh: ["WebAuthn", "通行密钥", "Passkey", "FIDO2"],
      short_en: "Public-key authentication bound to an origin; the server stores no shared secret and phishing fails.",
      short_zh: "与来源绑定的公钥认证；服务端不存共享秘密，钓鱼无法得手。" },
    { en: ["key derivation function", "KDF"], zh: ["密钥派生函数", "KDF"],
      short_en: "Turns a master password into encryption keys; deliberately slow and salted.",
      short_zh: "把主密码转成加密密钥的函数，刻意放慢并加盐。" },
    { en: ["pbkdf2"], zh: ["PBKDF2"],
      short_en: "Password-based KDF (RFC 2898) used by several password managers; iteration count matters.",
      short_zh: "若干密码管理器使用的口令派生函数（RFC 2898）；迭代次数决定强度。" },
    { en: ["argon2"], zh: ["Argon2"],
      short_en: "Memory-hard password-hashing winner of the Password Hashing Competition.",
      short_zh: "以内存困难为设计目标的密码哈希函数，口令哈希竞赛获胜者。" },
    { en: ["zero-knowledge encryption"], zh: ["零知识加密"],
      short_en: "A vendor claim that the server cannot read the vault, even when it behaves maliciously.",
      short_zh: "厂商宣称即使服务端作恶也读不到保险库内容的一种说法。" },
    { en: ["master password"], zh: ["主密码"],
      short_zh: "The single password from which all vault keys are derived; never stored on the server.",
      en_short: "",
      short_en: "The single password from which all vault keys are derived; never stored on the server." },
    { en: ["vault"], zh: ["保险库", "密码库"],
      short_en: "The encrypted container holding a user's credentials and other items.",
      short_zh: "存放用户凭据等条目的加密容器。" },
    { en: ["autofill"], zh: ["自动填充"],
      short_en: "A password manager inserting credentials into a web form; a frequent source of origin-check bugs.",
      short_zh: "密码管理器把凭据填进网页表单的过程，是来源校验漏洞的高发区。" },
    { en: ["injection attack"], zh: ["注入攻击"],
      short_en: "Attacker-supplied payloads placed in shared data and interpreted by a victim's client.",
      short_zh: "攻击者把载荷放进共享数据、由受害者客户端解析执行的攻击。" },
    { en: ["forward-replay attack"], zh: ["前向重放攻击"],
      short_en: "Setting a device clock forward to harvest future TOTP codes and replay them later.",
      short_zh: "把设备时钟调快以预取未来 TOTP 验证码，日后再重放。" },
    { en: ["threat model"], zh: ["威胁模型"],
      short_en: "The explicit statement of which adversary capabilities an analysis assumes.",
      short_zh: "分析所假设的攻击者能力边界。" },
    { en: ["hash function", "cryptographic hash"], zh: ["哈希函数", "密码学哈希"],
      short_en: "A one-way function mapping arbitrary input to a fixed-length digest.",
      short_zh: "把任意长度输入映射为定长摘要的单向函数。" }
  ];

  var isZh = /\/zh(\/|$)/.test(location.pathname) || document.documentElement.lang.slice(0, 2) === "zh";

  function glossOf(term) {
    return isZh ? term.short_zh : term.short_en;
  }
  function wordsOf(term) {
    return isZh ? term.zh : term.en;
  }
  function labelOf(term) {
    return isZh ? term.zh[0] : term.en[0];
  }

  function run() {
    var root = document.querySelector(".content main") || document.querySelector("main");
    if (!root) return;
    var perPage = {};
    var SKIP = /^(CODE|PRE|A|H1|H2|H3|H4|H5|H6|SCRIPT|STYLE|SUP|SUB|MJX-CONTAINER)$/;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (node) {
        var p = node.parentNode;
        while (p && p !== root) {
          if (SKIP.test(p.tagName) || p.classList.contains("gloss-term") ||
              p.classList.contains("gloss-card") || p.classList.contains("source-card")) {
            return NodeFilter.FILTER_REJECT;
          }
          p = p.parentNode;
        }
        return node.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });

    var nodes = [];
    var n;
    while ((n = walker.nextNode())) nodes.push(n);

    TERMS.forEach(function (term) {
      var words = wordsOf(term).slice().sort(function (a, b) { return b.length - a.length; });
      var re = new RegExp("(" + words.map(escapeRe).join("|") + ")", "gi");
      nodes.forEach(function (node) {
        var key = term.en[0];
        if ((perPage[key] || 0) >= 3) return;
        if (!re.test(node.nodeValue)) { re.lastIndex = 0; return; }
        re.lastIndex = 0;
        var frag = document.createDocumentFragment();
        var text = node.nodeValue;
        var m;
        var last = 0;
        while ((m = re.exec(text)) && (perPage[key] || 0) < 3) {
          if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
          var span = document.createElement("span");
          span.className = "gloss-term";
          span.textContent = m[0];
          span.dataset.gloss = glossOf(term);
          span.dataset.glossTitle = labelOf(term);
          frag.appendChild(span);
          perPage[key] = (perPage[key] || 0) + 1;
          last = m.index + m[0].length;
        }
        if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
        // A node may already have been replaced (and detached) by an earlier
        // term's pass; replaceChild on a detached node throws.
        if (frag.childNodes.length && node.parentNode) node.parentNode.replaceChild(frag, node);
      });
    });

    wireCards(root);
  }

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  function wireCards(root) {
    var card = document.createElement("div");
    card.className = "gloss-card";
    document.body.appendChild(card);
    var timer = null;
    function show(target) {
      card.innerHTML = '<div class="gloss-card-title"></div><div class="gloss-card-body"></div>' +
        '<div class="gloss-card-link"></div>';
      card.querySelector(".gloss-card-title").textContent = target.dataset.glossTitle;
      card.querySelector(".gloss-card-body").textContent = target.dataset.gloss;
      var a = document.createElement("a");
      a.href = relativeGlossaryPath();
      a.textContent = isZh ? "查看术语表 →" : "See glossary →";
      card.querySelector(".gloss-card-link").appendChild(a);
      card.classList.add("visible");
      var r = target.getBoundingClientRect();
      var top = window.scrollY + r.bottom + 8;
      var left = Math.min(window.scrollX + r.left, window.scrollX + document.documentElement.clientWidth - card.offsetWidth - 12);
      card.style.top = top + "px";
      card.style.left = Math.max(8, left) + "px";
    }
    function hide() { card.classList.remove("visible"); }
    root.addEventListener("mouseover", function (e) {
      if (e.target.classList && e.target.classList.contains("gloss-term")) {
        clearTimeout(timer);
        show(e.target);
      }
    });
    root.addEventListener("mouseout", function (e) {
      if (e.target.classList && e.target.classList.contains("gloss-term")) {
        timer = setTimeout(hide, 200);
      }
    });
    root.addEventListener("click", function (e) {
      if (e.target.classList && e.target.classList.contains("gloss-term")) {
        e.preventDefault();
        location.href = relativeGlossaryPath();
      }
    });
    card.addEventListener("mouseenter", function () { clearTimeout(timer); });
    card.addEventListener("mouseleave", hide);
    document.addEventListener("scroll", hide, true);
  }

  function relativeGlossaryPath() {
    // Works for both books because the glossary page sits at the book root.
    var depth = location.pathname.replace(/\/[^/]*$/, "").split("/").filter(Boolean).length;
    var up = depth >= 1 ? "../".repeat(0) : "";
    // Compute depth from the site root using the script URL like lang-switch.js.
    var src = "";
    var scripts = document.getElementsByTagName("script");
    for (var i = 0; i < scripts.length; i++) {
      if (/glossary\.js/.test(scripts[i].src)) { src = scripts[i].src; break; }
    }
    if (!src) return "appendix-glossary.html";
    var base = src.slice(0, src.lastIndexOf("/") + 1);
    var here = location.href.split("#")[0].split("?")[0];
    return base + "appendix-glossary.html";
  }

  function ready() {
    if (typeof MathJax !== "undefined" && MathJax.startup && MathJax.startup.document) {
      // Wait for typesetting to settle, then decorate.
      MathJax.startup.promise.then(function () { setTimeout(run, 0); });
    } else {
      window.addEventListener("load", function () { setTimeout(run, 300); });
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();

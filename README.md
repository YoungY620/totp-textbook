# One-Time Passwords, Authenticators, and Password Managers — 一次性的密码、验证器与密码管理器

一本双语在线教材，沿着一条主线讲清 **TOTP**（你手机里每 30 秒跳一次的六位验证码）从
密码学构想到今天生态的演进，以及它与**密码管理器**加密原理共享的更深层问题：

> **秘密该放在哪里。**

全书六幕、13 章，每章对应一篇一手论文或标准，每章末尾附「相关文献」。
英文在站点根目录，中文在 `/zh/`。

## 目录

| 幕 | 章节 | 一手材料 |
|---|---|---|
| 第一幕 · 起源 | 1–2 | Lamport 1981；RFC 1760 S/KEY |
| 第二幕 · 标准化 | 3–4 | RFC 4226 HOTP；RFC 6238 TOTP |
| 第三幕 · 反攻 | 5 | T/Key (CCS 2017) |
| 第四幕 · 现实打脸 | 6–7 | Gilsenan et al. (USENIX Sec 2023)；Bianchi & Valeriani (2023) |
| 第五幕 · 另一条战线 | 8–12 | Li 2014 → Scarlata/Torrisi et al. (USENIX Sec 2026) |
| 第六幕 · 出路 | 13 | WebAuthn / Passkeys |

另有[术语表](book-zh/src/appendix-glossary.md)与[参考文献总表](book-zh/src/appendix-bibliography.md)。

## 本地构建

```bash
bash tools/build-site.sh     # 产出 ./site ：英文在根，中文在 /zh/
```

依赖：`mdbook` 0.5.x、`python3`（用于公式保护预处理器）。

## 仓库结构

```
book-en/            # 英文 mdBook 根
book-zh/            # 中文 mdBook 根
tools/
  build-site.sh     # 两本一起构建成 site/
  mathprotect.py    # mdBook 预处理器：让 LaTeX 活着穿过 Markdown
  lint-math.py      # 公式隐患 lint
  checker/          # Playwright 真实渲染验证器
  narrative-framework.md   # 全书叙述框架（故事内核 / 幕 / 母题）
  material-manifest.md     # 材料覆盖矩阵
```

## 验证

内容改动后跑一遍真实渲染检查（不是只编译）：

```bash
cd tools/checker && npm i && npx playwright install chromium
node check-render.mjs ../../site
```

它逐页断言：MathJax 确实完成了排版、正文没有残留的裸 LaTeX、图片无 404、控制台无报错、
语言切换链接存在且可跳、390px 窄屏无横向溢出。

> 本书由 course-textbook-builder 流程生成（<https://github.com/YoungY620/my-awesome-skills>）。

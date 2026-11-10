# 材料清单与覆盖矩阵

记录「用户提供的材料 + 检索发现的关键材料」与章节的对应，确保**覆盖到全部关键材料**，
并显式标出未能获取的部分。

## 一、用户提供的材料（handoff）

| 材料 | 年份 | 对应章节 | 状态 |
|---|---|---|---|
| Lamport, *Password Authentication with Insecure Communication* (CACM) | 1981 | 1 | ⚠️ 原文付费墙；基于公开摘要 + RFC 1760 + 课程讲义撰写，正文已显式标注 |
| Haller, *S/KEY*, RFC 1760 | 1995 | 2 | ✅ 原文；六词编码/2048 词表/链长已核对 |
| M'Raihi et al., *HOTP*, RFC 4226 | 2005 | 3 | ✅ 原文；附录 D 全部 10 行测试向量独立复算通过 |
| M'Raihi et al., *TOTP*, RFC 6238 | 2011 | 4 | ✅ 原文；附录 B 的 18 个测试值（SHA-1/256/512 × 6 时刻）独立复算通过 |
| Kogan, Manohar, Boneh, *T/Key* (CCS) | 2017 | 5 | ✅ arXiv 作者版；构造、参数、安全界已核对 |
| Gilsenan et al., *Security and Privacy Failures in Popular 2FA Apps* (USENIX Sec) | 2023 | 6 | ✅ USENIX 开放版 + artifact 附录 |
| Bianchi & Valeriani, *Time Is on My Side: Forward-Replay Attacks to TOTP* | 2023 | 7 | ⚠️ 期刊付费墙；基于作者会议 slides + 公开摘要，正文已标注 |
| Li et al., *The Emperor's New Password Manager* (USENIX Sec) | 2014 | 8 | ✅ USENIX 开放版 |
| Oesch & Ruoti, *That Was Then, This Is Now* (USENIX Sec) | 2020 | 9 | ✅ USENIX 开放版；语料/检测器/KDF 轮数已核对 |
| Fábrega et al., *Exploiting Leakage in Password Managers via Injection Attacks* (USENIX Sec) | 2024 | 10 | ✅ USENIX 开放版（+ arXiv 版对照） |
| Duan, Wang & Fu, *Security Analysis of Master-Password-Protected Password Management Protocols* (IEEE S&P) | 2025 | 11 | ✅ 作者全文版 + 公开 artifact；IEEE 版付费 |
| Scarlata/Torrisi et al., *Zero Knowledge (About) Encryption* (USENIX Sec) | 2026 | 12 | ✅ USENIX 预出版版（三厂商）；ePrint 2026/058 为含 1Password 的四厂商全版 |

## 二、主代理补充检索发现的关键材料（保证"现状"同步）

| 材料 | 用途 | 落点 |
|---|---|---|
| RFC 2289 *A One-Time Password System* | S/KEY 标准化续作、race attack、SHA-1 支持 | 2 |
| RFC 2104 *HMAC* | HOTP/TOTP 的密码学基元 | 3, 4 |
| RFC 6287 *OCRA* | OTP 家族扩展（挑战-响应） | 3, 4 |
| Google *Key URI Format*（`otpauth://`，事实标准） | TOTP 生态互操作，非 RFC | 4 |
| Fábrega et al., *Injection Attacks Against E2EE Applications* (IEEE S&P 2024) | 注入攻击的一般框架 | 10 |
| Fábrega et al., *Mitigating Injection Attacks … View-Based Partitioning* (USENIX Sec 2025) | 注入攻击的缓解方向 | 10 |
| *"We've Disabled MFA for You"* (ACM CCS 2023) | MFA 恢复流程的安全/可用性 | 6, 13 |
| Daffalla et al., Passkeys 人际威胁模型下的滥用 (USENIX Sec 2025) | Passkeys 的新风险 | 13 |
| Amft et al. (CCS 2023)、Lassak (USENIX Sec 2024) 等 | 恢复流程与采用障碍的实证 | 13 |
| W3C *Web Authentication Level 3* / FIDO2 / CTAP | WebAuthn 规范 | 13 |

## 三、撰写过程中发现的 handoff 错误（已按原文更正）

| handoff 的说法 | 原文实际 | 处理 |
|---|---|---|
| 第 12 章署名 "Scarlata et al." | 正式版首页署名 Scarlata、Torrisi、Backendal、Paterson | 按正式版署名 |
| 第 12 章攻击数 "27" | 三厂商正式版 **25**（BW 12 + LP 7 + DL 6）；四厂商全版 31 | 按正式版写 25，正文注明版本差异 |
| 第 8 章研究对象含 "Firefox" | 实为 LastPass、RoboForm、My1login、PasswordBox、NeedMyPassword | 按 Table 1 更正 |
| 第 8 章攻击分类学（bookmarklet/生成/填充/共享/OTP/导出/UI） | 原文四类：bookmarklet、经典 Web、授权、UI | 按原文四类 |
| Duan/Wang 机构"北京大学" | Ding Wang 现任 **南开大学** | 按原文 |
| *"We've Disabled MFA for You"* 归 USENIX Sec 2023 | 实为 **ACM CCS 2023** | 按原文 |
| 第 5 章"验证只需一次哈希" | T/Key 服务器需算 $t-t_{\text{prev}}$ 次哈希（单次哈希是 S/KEY） | 按原文 |

## 四、未获取 / 需注意

- **Lamport 1981**、**Bianchi & Valeriani 2023**：未取得开放获取全文，已在对应章节显式标注，只写可核实内容。
- **第 12 章**：官方 PoC（zenodo）未取用；部分次要攻击的机制在正式版里只写"deferred to the full version"，
  教材只报告其名称/成因/影响，未臆测步骤。
- **第 11 章**：作者全文版尾部（§5.3 之后的证明、附录）未能完整获取，相关结论只写到能核实的深度，已标注。
- **第 10 章**：攻击一的产品数在 arXiv v1（5 款）与 USENIX 正式版（7 款）之间不一致，采用正式版。

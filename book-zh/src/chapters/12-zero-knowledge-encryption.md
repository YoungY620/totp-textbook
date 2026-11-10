# 恶意服务器下的「零知识」加密（2026）

<div class="source-card">
<p><strong>本章文献：</strong> Matteo Scarlata, Giovanni Torrisi, Matilda Backendal, Kenneth G. Paterson. <em>Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers</em>. USENIX Security 2026（预出版）。<a href="https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf">预出版 PDF</a>；含额外一个厂商的全版见 <a href="https://eprint.iacr.org/2026/058">IACR ePrint 2026/058</a>；项目页：<a href="https://webro.ke/passwordmanagers">webro.ke/passwordmanagers</a>。</p>
<p><strong>一句话：</strong> 三家主流云密码管理器宣称的「零知识加密」意味着即使服务器完全恶意也安全；作者重新审视其代码与架构，发现 <strong>25 个可落地的攻击</strong>（Bitwarden 12 个、LastPass 7 个、Dashlane 6 个）——多数是设计缺陷而非高深密码分析，且过半可恢复保险库口令。</p>
</div>

*署名说明。* 正式论文的作者及顺序为 **Matteo Scarlata**（苏黎世联邦理工 ETH Zurich）、**Giovanni Torrisi**（瑞士意语区大学 USI, Lugano）、**Matilda Backendal**（USI, Lugano）与 **Kenneth G. Paterson**（ETH Zurich）；脚注说明 Torrisi 与 Backendal 的部分工作是在 ETH Zurich 完成的。同名工作的 ePrint 页面只列出 Torrisi、Backendal、Paterson 三人，公开报道则单独提到 Scarlata；本正文按 USENIX 预出版 PDF 的实际署名写。另外，这份标题为「Three Cloud-based Password Managers」的 PDF 是即将出版的正式版；ePrint 的全版标题为「Four」，多出一个 1Password（另有 6 个攻击）。本章依据三厂商的正式版。

<div class="hook">「连我们自己的工程师都看不到你的口令」，宣传语这么写，「而且就算服务器被攻破，你依然安全。」把这句话当真——用户完全有权当真——它就变成一条精确的密码学断言：一台会向客户端撒谎、会重排你的数据、会削弱你的密钥派生、还会掉包你的共享密钥的服务器，依然碰不到你的保险库。三家主流云密码管理器这次就是被拉到这条标准下衡量的；结果并不是宣传品。</div>

## 1. 背景与动机

云密码管理器用从主口令派生的密钥把用户口令加密成一个**保险库（vault）**，把密文上传到服务器；服务器看不到明文——这与端到端加密（E2EE）云存储同形。厂商把这一性质宣传为**零知识加密（Zero Knowledge Encryption）**。作者指出，这个术语并无严格技术含义（并非零知识证明），却传递出一个很强的承诺：服务器对保险库一无所知。

论文研究的三家厂商——**Bitwarden、LastPass、Dashlane**，合计**逾 6000 万用户、23% 市场份额**——的表述按字面推断，意味着*即使服务器完全恶意*仍安全：Bitwarden 说团队成员「无法看到你的口令」；Dashlane 说「即使 Dashlane 的服务器被攻破，恶意者也无法窃取信息」；LastPass 说除你之外（连 LastPass 也不行）无人能访问主口令。它们都没交代攻击者模型，但用户有理由推断「服务器被攻破也能扛住」。这一推断即论文的**威胁模型**：**完全恶意的服务器**，可与客户端交互时任意偏离预期行为。三条理由支撑该模型：厂商自己的宣传暗示了它；保险库集中存放高价值秘密，使服务器成为高级攻击者的诱人目标（LastPass 于 2015、2022 年被攻破，2022 年那次已触及加密的企业保险库与备份密钥）；而在 E2EE 消息与云存储领域，「对恶意服务器安全」早已是「端到端加密」的公认含义。平凡的*恶意客户端*攻击（被投毒的客户端）被排除，因为签名发布使这类攻击可被审计且对厂商风险极高。

由此推出用户应有的**安全期望**：保险库全部数据的**机密性**（口令、银行卡、笔记）；保险库数据与元数据的**完整性**（既在单个条目层面，也在整体层面）；以及**安全的共享与账户恢复**——只有预期对象才能访问或恢复。达成这些还需次级性质，例如抵抗服务器通过降低 KDF 迭代次数来削弱客户端密码学。由于恶意服务器往往仍需诚实客户端作出反应，作者把**客户端交互**视为成本：表 1 为每个攻击标注所需交互是常规动作（`sync` 同步、`login` 登录、`open` 打开保险库）还是较罕见动作（`join` 加入组织、`share` 共享、或被误导点击 `dialog`）。多数攻击只需常规动作。

## 2. 三家密码管理器及其密钥层级

分析沿用「Cryptography in the Wild：攻击分支」的方法：读白皮书与客户端代码，为每个功能建伪代码模型，对模型找攻击，再实现恶意服务器 PoC 在真实客户端上验证。Bitwarden 先做（源码可得），Dashlane 与 LastPass 部分靠逆向。作者强调：没有形式化分析，其攻击集合只能视为**不完整**——有些地方凑够足够多的严重漏洞后就停手了。

**Bitwarden。** 主口令与邮箱分别作为 KDF（PBKDF2 或 Argon2id）的输入与盐，生成 32 字节主密钥 $k_{m}$；认证发送 $h_{m}$——对 $k_{m}$ 以口令为盐做*一次* PBKDF2 迭代的结果，与注册时存的值比较。再由 $k_{m}$ 经 HKDF-Expand 以标签 `enc`、`mac` 派生 64 字节扩展主密钥。随机生成的 64 字节**用户密钥** $k_{u} = k_{u}^{enc} \,\|\, k_{u}^{mac}$ 保护全部数据，自身用扩展主密钥加密后存服务器。另有一对 2048 位 RSA 密钥用于组织，私钥用 $k_{u}$ 加密。加密为 AES-CBC 加 HMAC（为向后兼容，当密钥只有 32 字节时省略 HMAC）。自客户端 2024.2.0 起，新条目使用单独采样的**逐条目密钥（per-item keys）**，旧条目仍直接用 $k_{u}$。组织通过 64 字节对称密钥 $k_{org}$ 共享，$k_{org}$ 用各成员公钥加密，另有组织 RSA 密钥对用于恢复。

**LastPass。** 口令经 PBKDF2（邮箱为盐）得到 32 字节用户密钥 $k_{u}$，默认迭代 **600,000** 次；认证发送 $h_{u}$——对 $k_{u}$ 再以口令为盐做一次 PBKDF2 的结果。条目用 AES-CBC 加密且**无完整性保护**。用户另有 RSA 密钥对，私钥用 AES-CBC 加密于 $k_{u}$ 之下；共享用共享文件夹，32 字节 $k_{shr}$ 以 RSA-OAEP 加密到接收者公钥。

**Dashlane。** 保险库是一个**事务型数据库**：每个事务带未加密的类型与时间戳元数据、以及加密内容。内容前缀的**载荷串（payload string）**声明 KDF（PBKDF2、Argon2d 或不做派生）、其参数、密码算法（AES-256）与模式（默认带 HMAC 的 CBC）。先由口令派生出 32 字节中间密钥 $k_{cbc}$；CBC+HMAC 模式下再经 SHA-512 得到 64 字节 $k_{cbc\text{-}hmac}$。2048 位 RSA 密钥对支持共享，新的 $k_{shr}$ 加密到接收者公钥。由于唯一完全开源的客户端是不支持加密与共享的 CLI，Dashlane 的描述部分来自逆向。

## 3. 攻击：四类，共 25 个

恶意服务器 PoC 得到 **25 个攻击**：**Bitwarden（BW）12 个**、**LastPass（LP）7 个**、**Dashlane（DL）6 个**。表 1 按成因分为四类：**密钥托管（Key Escrow）**、**条目级保险库加密**、**共享（Sharing）**、**向后兼容（Backwards Compatibility）**。表 1 用剑标（dagger）标出「可恢复加密口令」的攻击——**25 个中有 12 个**带此标记，论文更笼统地说「多数攻击可恢复口令」。影响从篡改元数据，到**攻陷某个组织下所有保险库**。

**密钥托管。** **BW01（恶意自动登记）**——用户加入*任何*组织时，客户端拉取的组织数据未做完整性保护；服务器可打开自动登记、并把组织公钥换成自己的，于是客户端把用户密钥加密给攻击者。影响：保险库完全沦陷（剑标），只需用户加入某个组织——邀请完全可能来自诚实的亲友或企业。由于组织私钥为全体成员所知，该攻击会**像蠕虫一样**在启用了恢复、成员重叠的组织间蔓延。**BW02（恶意密钥轮换）**在用户轮换密钥时重演同样手法——客户端会经同样未认证的同步重新取回 $pk_{org}$。**LP01（恶意口令重置）**——超级管理员公钥在每次登录时从服务器取回且未认证，而 LastPass 客户端即便用户未登记恢复也会上传恢复密文，因此一次登录即可泄露用户密钥。这三个都是保险库完全沦陷（剑标）。

**条目级加密。** 每个字段单独加密、且密文与其条目或字段名没有任何绑定，完整性只在字段级成立。**BW05 / LP02（条目字段互换）**让服务器在条目内、条目间搬移密文，或把不同字段拼成新条目；与 **BW06 / LP03（图标 URL 条目解密）**串联即可泄露机密：两个客户端都解密 URL 字段并向图标服务器发请求、请求中带该 URL 的域名，于是把用户名或口令的密文移到 URL 字段就能读回（Bitwarden 对明文有额外条件，LastPass 没有）。Bitwarden 于 2024 年 7 月上线 URL 校验和，但只保护此后新建、且存在逐条目密钥的条目——而攻击者可用 **BW10** 阻止逐条目密钥生效。**BW07 / LP04 / DL04（移除 KDF 迭代次数）**利用未认证、未加密的 KDF 设置。Bitwarden 的派生成本为 $N+1$ 次迭代，把 $N=600{,}000$ 改成 $N=1$，成本从 600,001 降到 2——对主口令的暴破获约 **300,000 倍加速**；LastPass 可被压到 3 次迭代（内层最小值 2、外层固定 1），**200,000 倍**；Dashlane 可伪造设置事务，把 PBKDF2 从 200,000 次降到 1 次，同样是 **200,000 倍**。本类还包括 **BW04 / LP06**（元数据未保护）、**LP05**（保险库可延展）、**DL01（事务重放）**——事务密钥并不唯一，服务器可重复、重排或删除事务而不被察觉。

**共享。** 三家都实现共享，也都未认证公钥。**BW08（组织注入）**把用户加入任意组织（无密钥认证），并向 **BW03/BW09** 串联；**BW09（组织覆盖）**在同步时换成攻击者控制的组织密钥且不可察觉——组织沦陷（剑标）。**LP07 / DL02（共享密钥覆盖）**在共享时替换接收者的 RSA 公钥，使共享者把共享文件夹密钥加密给攻击者——共享保险库沦陷（剑标）。

**向后兼容。** 恶意服务器触发旧代码路径。Bitwarden 中加密类型字节无完整性保护，「已知明文机器件」（**BWb1**）加比特翻转即可得到 **BW11（用户密钥覆盖）**，恢复 $k_{u}^{enc}$，此后所有条目机密性尽失（剑标）；以及 **BW12（降级到旧格式）**，剥掉 MAC 密钥使后续加密退回纯 CBC 模式——再结合填充预言机即完全沦陷（剑标）。二者都需两次登录尝试。Dashlane 的可延展载荷仍接受纯 CBC 模式，从而给出填充预言机（**DLb1/DLb2**）并串联出 **DL03（条目注入）**、**DL04**、**DL05（纯 CBC 降级）**（剑标）与 **DL06（Lucky 64）**；这些需要约 $10^{4}$–$10^{5}$ 次同步，正常速度下需 126 天以上，但对定向攻击「是合理的」。

反复出现的根因是一组**反模式（anti-pattern）**：缺少公钥认证、组织元数据未认证、缺少整体完整性、缺少密钥分离、以及可被远程重新启用的旧式 CBC 支持。

## 4. 缓解、适用范围与实践含义

论文把每个攻击对应到五种手段的组合：**认证加密（AE）**、**密钥分离（KS）**、**对不可避免的明文做认证（AD）**、**公钥认证（PKA）**与**密文认证（SC）**。具体做法：废弃旧式 CBC；把 Bitwarden 的逐条目密钥推广到逐字段并强制启用；对元数据与 KDF 参数等安全关键设置做认证；对公钥密文做认证或*签名*——作者主张用**签密（signcryption）**，因为公钥加密本身无法提供来源认证（任何人都能加密）。公钥最终仍需 **PKI**（其 CA 不能由服务器运营方控制）、首次使用信任（TOFU）或消息领域式的可验证密钥目录（VKD）；密钥托管可用 **HSM** 加固，如同 Signal/WhatsApp 与 Apple 的 Advanced Data Protection。作者强调修复需要**破坏性变更**，为避免用户保险库变砖，提议一个专用于强制迁移的客户端。

**恶意服务器模型何时成立？** 作者态度明确：它成立——承诺是被宣传的、数据集中且价值极高、相邻 E2EE 领域早已以此为准；服务器端的*隐蔽*篡改尤其难以察觉，定点攻击时更甚。至于「普通用户是否该弃用云密码管理器」，论文立场是**否**：发动这些攻击的前提苛刻，**多数用户不会被针对**，而高风险个人与组织则「可能面临重大风险」。论文也承认，这些攻击可能早已为高级威胁行为者所知。

**局限与迁移。** 攻击集合被明说为**不完整**（无形式化分析），PoC 测试限于 Bitwarden 网页端与 LastPass/Dashlane 浏览器扩展，但多数攻击属设计层面、与具体客户端无关。结论可迁移到三家之外：「PKI 无法回避」「公钥加密不提供认证」「条目级加密不等于保险库完整性」「向后兼容是负债」等教训，在 E2EE 云存储与消息领域反复出现；作者认为密码管理器的复杂度已可与现代 E2EE 云存储比肩。一个遗留难题是**防回滚**：Merkle 树可认证结构，但若无可信第三方或本地状态，无法排除整体回滚，而这又与「任意无状态设备上仅凭主口令即可访问」的期待冲突。总体而言，这篇论文是**改良派而非废除派**：保留云密码管理器，但修好密码学，并厘清「零知识」到底允许意味着什么。

<div class="aside">
<p><span class="aside-label">题外话 · 一个双关，两个数字</span></p>
<p>标题 <em>Zero Knowledge (About) Encryption</em> 一语双关：既是厂商叫卖的「零知识」性质，也暗指这个领域对「这个性质究竟该意味着什么」知之甚少——后一层是就标题所作的解读，并非论文原话。攻击总数还会随版本变动：已出版的三厂商 USENIX 版报告 25 个攻击（Bitwarden 12、LastPass 7、Dashlane 6），ePrint 全版多出 1Password 后达到 31 个。二手转述里常说的「25 或 27」，两个数其实都对不上。</p>
<p class="aside-source">出处：论文标题；USENIX 预出版 PDF（25 = 12 + 7 + 6）；IACR ePrint 2026/058（31 = 12 + 7 + 6 + 6）。标题的双关解读属理解而非引文。</p>
</div>

## 5. 相关文献与领域现状

- **Z. Li, W. He, D. Akhawe, D. Song, *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*, USENIX Security 2014**（[usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li)）——网络密码管理器学术批判的开山之作（第 8 章）；其威胁模型更弱，早期工作都没考虑恶意服务器。
- **S. Oesch, S. Ruoti, *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-based Password Managers*, USENIX Security 2020**（[usenix.org](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch)）——2020 年的再评估，结论是安全性有改善（第 9 章）；本文是回击：诚实服务器模型下的改善并未带来恶意服务器安全。
- **A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart, *Exploiting Leakage in Password Managers via Injection Attacks*, USENIX Security 2024**（[usenix.org](https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega)）——恶意*客户端*加被动服务器模型下的注入攻击（第 10 章）；二者互补，那项工作假设服务器大体诚实。
- **Y. Duan, D. Wang, Y. Fu, *Security Analysis of Master-Password-Protected Password Management Protocols*, IEEE S&P 2025**（[IEEE](https://www.computer.org/csdl/proceedings-article/sp/2025/471500a701/26JLYLtitl6)）——对主口令保护协议的形式化分析（第 11 章），本文将其列为邻近工作，并呼吁对恶意服务器场景做同样处理。
- **G. Avoine, X. Carpent, D. Leblanc-Albarel, *In the Vault, but Not Safe: Exploring the Threat of Covert Password Manager Providers*, ePrint 2025/1278**（[eprint.iacr.org](https://eprint.iacr.org/2025/1278)）——作者所称的「并行预印本」：假设服务器保持*隐蔽*而非完全恶意，把云密码管理器分成三类并勾勒跨类攻击，但没有 PoC，也未充分探讨影响。
- **最邻近的 E2EE 云存储工作。** Albrecht 等，*Share with Care: Breaking E2EE in Nextcloud*, IEEE EuroS&P 2024（[eprint 2024/546](https://eprint.iacr.org/2024/546)）；Backendal 等，*MEGA: Malleable Encryption Goes Awry*, IEEE S&P 2023（[eprint 2022/959](https://eprint.iacr.org/2022/959)）；Backendal 等，*A Formal Treatment of End-to-End Encrypted Cloud Storage*, CRYPTO 2024（[eprint 2024/989](https://eprint.iacr.org/2024/989)）。它们提供了「恶意服务器是常态」的基调、公钥认证失效的具体模式，以及作者希望密码管理器借用的形式化定义。

作者对领域现状的总判断是：这里**没有金字标准、也没有精确的安全定义**可依，不同于 TLS 或 Signal；而它的历史包袱——LastPass 可追溯到 2008 年——使向后兼容长期保留着 2000 年代初密码学的残迹。他们把本工作定位为首次确立「密码管理器需要恶意服务器下的形式化定义」的必要性，与 E2EE 云存储如今才刚起步的形式化工作相呼应。

## 6. 小结与回响

- 本章针对厂商的**「零知识加密」**宣传，把它读作**对完全恶意服务器安全**；在此模型下分析 **Bitwarden、LastPass、Dashlane** 三家，合计**逾 6000 万用户、23% 市场份额**。
- 论文报告 **25 个攻击**：**BW 12、LP 7、DL 6**，分四类——密钥托管、条目级加密、共享、向后兼容。表 1 有 **12 个**带剑标（可恢复加密口令）；论文称多数攻击可恢复口令。
- **密钥托管**类（BW01、BW02、LP01）凭借组织/管理员公钥未认证，仅需「加入组织」或「登录」这类常规动作即可拿到整个保险库；BW01 还会像蠕虫般蔓延。
- **条目级**设计使整体完整性失效（BW05/LP02 互换），进而通过图标 URL 请求泄露机密（BW06/LP03），并可把 KDF 迭代次数降级，得到约 **300,000 倍**（Bitwarden）与 **200,000 倍**（LastPass、Dashlane）的暴破加速。
- **共享**类败在公钥未认证（BW09、LP07、DL02）；**向后兼容**让服务器强制旧式 CBC，触发密钥覆盖与降级攻击（BW11、BW12、DL03–DL06）。
- 根因是一组反模式——缺公钥认证、无整体完整性、密钥分离不足、可被远程触发的旧代码；可用 AE、密钥分离、认证数据、公钥认证与签密来根治。
- 实践上作者**并不**建议普通用户弃用云密码管理器：攻击需要苛刻（多为恶意服务器）的前提，多数用户不太会被针对，而高风险个人与组织则可能面临重大风险；正确回应是厂商修补与形式化安全定义。
- 更广的教训——呼应全书主线——是「云 + 零知识宣称」重复了共享秘密的老问题：安全必须针对恶意服务器论证，不能从营销想当然；持久解药是经过认证、良好分离的密钥（而对钓鱼威胁，则是走向第 13 章的公钥认证器）。

**回响。** 第五幕到此收官。第 1 章让 Lamport 把秘密从服务器上拿走，好让一份失窃的口令文件毫无价值；第 3、4 章为了好用，又把共享密钥放回了服务器；第 8–12 章一路追着这个决定，走过了密码管理器的世界。本章点出的那道差距——「零知识」宣传册与可被密码学证明的保证之间——正是第 1 章那句承诺在云时代的验收：保险库也许只是一堆密文，但密钥材料、共享密钥，以及决定主口令有多难猜的设置，依然要送到一台能把它们改掉的服务器手上。结论不是「承诺为假」，而是：只要协议未在恶意服务器模型下被论证过，这个承诺就一直未被验证。第 13 章干脆不再请服务器保管任何共享秘密——交出去的只有一把公钥，秘密从不离开设备。

## 参考文献

1. M. Scarlata, G. Torrisi, M. Backendal, K. G. Paterson. *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers*. USENIX Security 2026（预出版）。https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf
2. 同作者. *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers*（全版）. IACR Cryptology ePrint Archive, Report 2026/058, 2026. https://eprint.iacr.org/2026/058
3. 项目页. https://webro.ke/passwordmanagers
4. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*. USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li
5. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-based Password Managers*. USENIX Security 2020, pp. 2165–2182. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
6. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega
7. Y. Duan, D. Wang, Y. Fu. *Security Analysis of Master-Password-Protected Password Management Protocols*. IEEE S&P 2025, pp. 701–719. https://www.computer.org/csdl/proceedings-article/sp/2025/471500a701/26JLYLtitl6
8. G. Avoine, X. Carpent, D. Leblanc-Albarel. *In the Vault, but Not Safe: Exploring the Threat of Covert Password Manager Providers*. IACR Cryptology ePrint Archive, Report 2025/1278, 2025. https://eprint.iacr.org/2025/1278
9. M. R. Albrecht, M. Backendal, D. Coppola, K. G. Paterson. *Share with Care: Breaking E2EE in Nextcloud*. IEEE EuroS&P 2024. https://eprint.iacr.org/2024/546
10. M. Backendal, M. Haller, K. G. Paterson. *MEGA: Malleable Encryption Goes Awry*. IEEE S&P 2023. https://eprint.iacr.org/2022/959
11. M. Backendal, H. Davis, F. Günther, M. Haller, K. G. Paterson. *A Formal Treatment of End-to-End Encrypted Cloud Storage*. CRYPTO 2024. https://eprint.iacr.org/2024/989
12. S. Vaudenay. *Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS…*. EUROCRYPT 2002.（DLb1/DLb2 填充预言机攻击的基础。）

## 事实核对清单

以下每个关键数字与结论均取自 USENIX 预出版 PDF（三厂商版），括号内为对应位置。

- **署名与顺序**（首页）：Matteo Scarlata（ETH Zurich）、Giovanni Torrisi（USI, Lugano，脚注）、Matilda Backendal（USI, Lugano，脚注）、Kenneth G. Paterson（ETH Zurich）；脚注：「Part of this work was done while Giovanni Torrisi and Matilda Backendal were at ETH Zurich」。
- **标题 / 厂商数 / 攻击总数**：标题「…of Three Cloud-based Password Managers」；摘要「12 distinct attacks against Bitwarden, 7 against LastPass and 6 against Dashlane」，合计 25。
- **用户数与份额**：摘要与第 1 节/Target Selection——「more than 60 million users and 23% market share」；厂商自报：Bitwarden 10M、Dashlane 19M 用户+24,000 企业客户、LastPass 33M 用户+100,000 企业客户；2024 年 1000 名美国消费者调查：Google+Apple 55%（2021 年为 15%）、Bitwarden 11%、LastPass 10%、Dashlane 2%（2021 年为 7%）。
- **威胁模型**：第 2 节——完全恶意服务器；三条正当化理由；排除恶意客户端攻击；三项安全期望（机密性/完整性/共享与恢复）及抵抗降级这一次级性质。
- **厂商引文**：第 2 节——Bitwarden、Dashlane、LastPass 的「zero knowledge」表述原文。
- **表 1 内容**（全部 25 个攻击的编号、名称、成因、影响、交互、缓解）：均读自表 1；**带剑标共 12 行**（BW01、BW02、BW03、LP01、BW06、LP03、BW09、LP07、DL02、BW11、BW12、DL05）。摘要「majority … allow recovery of passwords」按原文引用。
- **架构**：第 3.1 节 Bitwarden（PBKDF2/Argon2id、32 字节 $k_{m}$、单次迭代 $h_{m}$、HKDF-Expand 的 `enc`/`mac`、64 字节 $k_{u}$、2048 位 RSA、AES-CBC-HMAC、2024.2.0 起逐条目密钥、$k_{org}$）；第 3.2 节 LastPass（PBKDF2、32 字节 $k_{u}$、默认 600,000 次、AES-CBC 无完整性、RSA-OAEP 共享文件夹）；第 3.3 节 Dashlane（事务型库、载荷串、$k_{cbc}$、SHA-512→$k_{cbc\text{-}hmac}$、AES-256、2048 位 RSA、部分逆向）。
- **攻击细节**：BW01/BW02（蠕虫式蔓延、轮换）、LP01（登录即上传、与是否登记无关）、BW05/LP02、BW06/LP03（2024 年 7 月 URL 校验和；Bitwarden 的明文条件）、BW07（600,000→1，「from 600,001 to 2」，「300,000x」）、LP04（降到 3，「200,000x」）、DL04（200,000→1，「200,000x」）、BW08/BW09、LP07/DL02、BW11/BW12（2 次登录；已知明文器件 BWb1）、DL03–DL06 及「>126 days … reasonable for a targeted attack」、「$10^{4}$–$10^{5}$ syncs」（表 1 记为 `104`/`105 syncs`，即上标 $10^{4}$/$10^{5}$）。
- **缓解**（第 5 节）与**讨论/结论**（第 6–7 节）：AE/KS/AD/PKA/SC；签密；PKI/TOFU/VKD；基于 HSM 的密钥托管；强制迁移客户端；回滚局限；「not deep in a technical sense」却此前未被发现；披露时间（Bitwarden 2025-01-27、LastPass 2025-06-04、Dashlane 2025-08-29）与共同公开日期 2026-02-14。
- **相关文献归属**：参考文献 [44] Li 2014、[46] Oesch 2020、[30] Fábrega 2024、[28] Duan/Wang/Fu 2025、[9] Avoine 等 2025/1278、[10] Backendal 等 CRYPTO 2024、[3] Albrecht 等 EuroS&P 2024、[11] Backendal 等 S&P 2023、[54] Vaudenay EUROCRYPT 2002。

## 存疑 / 未获取清单

- **「25 还是 27」**：handoff 提到二手来源有 25/27 之说。USENIX 三厂商 PDF 明写 12+7+6=**25**；ePrint 四厂商全版为 12+7+6+6（1Password）=31。两者都得不出 27，故「27」应为讹传，本章采用 **25**。
- **作者顺序**：ePrint 元数据仅列 Torrisi、Backendal、Paterson，ETH 新闻则提到 Scarlata。按任务与 WRITING-SPEC「以正式论文为准」，采用 PDF 首页署名（Scarlata 居首），并在署名说明中标注此出入。
- **仅在正式版中简述的攻击**：BW03（Key Connector）、BW04、BW10、LP05、LP06 及 DL03/DL06 的机制细节，正式版只说「deferred to the full version [48]」。本章报告其表 1 的名称、成因与影响，但不臆断其逐步机制。
- **表 1 交互数**（`104`/`105 syncs`）在提取文本中无可见上标，据上下文释为 $10^{4}$/$10^{5}$，正文以数量级范围表述而非精确值。
- **23% 份额**与「多数可恢复口令」均为论文自身说法（23% 为作者推算，且据脚注 1 被 Dashlane 质疑）；本章照录，未自行重算。
- **Dashlane 架构**被作者承认为部分逆向、可能不完整（唯一完全开源的是 CLI，且其不支持加密与共享）。

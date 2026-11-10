# 主流 2FA 应用的安全与隐私缺陷

<div class="source-card">
<p><strong>本章文献：</strong> Conor Gilsenan、Fuzail Shakir、Noura Alomar、Serge Egelman. <em>Security and Privacy Failures in Popular 2FA Apps</em>. 第 32 届 USENIX Security 研讨会, 2023, pp. 2079–2096. <a href="https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf">原文 PDF</a> · <a href="https://www.usenix.org/system/files/usenixsecurity23-appendix-gilsenan.pdf">Artifact 附录</a> · <a href="https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan">论文页面</a></p>
<p><strong>一句话：</strong> 本文系统分析了 22 款主流 Android TOTP 应用的备份与恢复机制，发现其中大多数把 2FA 的信任基础又悄悄换回了 TOTP 本该取代的那几样东西——口令、短信和邮箱；而它们所谓的加密，往往弱到可以被离线破解。</p>
</div>

<div class="hook">
你启用 TOTP，是因为短信验证码会被截获；你告诉自己，光猜到口令已经进不来了。可接着验证器提示你要不要备份，而在好几款应用里，这份备份是把密钥原样明文带走的——你刚从账号上挪开的那些钥匙，转眼躺进了云盘，守着它的还是你正想摆脱的那种口令登录。你为安全加的那层保险，就这样以更弱的形式，被复制给了拿到备份的人。
</div>

## 1. 背景与问题

TOTP 当初被宣传为对短信 2FA 的升级：验证码由本地的共享密钥（shared secret）算出，生成过程中既不需要网络，也不需要手机号。但这个设计带来一笔可用性上的欠账——密钥只存在于用户设备上。一旦设备丢失、换新，或者卸载了应用，用户就再也算不出验证码，所有用 TOTP 保护的账号都会一并被锁在门外。

而「怕被锁死」恰恰是人们拒绝启用 2FA 的首要原因。于是绝大多数验证器应用都提供了某种**备份**：手动导出、二维码迁移、云同步，或者直接依赖 Android 平台自带的「Android 自动备份」。每一种选择都意味着把密钥挪到了别的地方。本文要问的就是：这笔账到底有多贵。

- **RQ1** —— 使用备份机制会向应用开发者或第三方泄露哪些个人信息？
- **RQ2** —— 攻击者获得一份备份的风险有多大？
- **RQ3** —— 拿到备份的攻击者，从中还原出 TOTP 密钥的风险有多大？

## 2. 研究对象

2021 年 11 月至 12 月，作者遍历 Google Play 商店中所有通用型 TOTP 应用。检索共得到 546 个候选，剔除 193 个安装量不足 10 万的应用、263 个描述中不含任何检索词的应用后，剩下 90 个逐个人工复核。只绑定单一服务的应用（如 Blizzard Authenticator），以及把 TOTP 作为附带功能的「多功能」应用（尤其是密码管理器，其密码学复杂度远高于验证器）都被排除。最终样本是 **22 款应用**，合计安装量超过 **1.8 亿**（表 1 的合计为 181.5M+）。

本文的威胁模型刻意收得很窄：恶意软件、root 权限、设备本地被攻破都**不在范围内**，设备被假定为未 root 且已打补丁。作者要分析的是备份中的数据——密钥、标签、签发方——**离开本地设备之后**的处境。全文对两个词做了严格区分：*明文*（plaintext）指离开应用前没有做端到端加密的数据；*加密*（encrypted）指应用在传输前做了端到端加密，与是否使用 TLS 无关。所有被测应用都用了 TLS，但仅靠 TLS 在这里不算「加密」。

理解结论还需要知道配置（provisioning）流程：启用 TOTP 时，网站会把三个值交给应用——**签发方**（issuer，服务名称）、**标签**（label，用户在该服务上的账号名）与**密钥**（secret）。RFC 6238 定义了客户端与服务端如何使用密钥，却明确把密钥的传递排除在范围之外；填补这个空缺的事实标准是 Google 的 Key URI Format，它把上述字段编码进二维码。因此标签和签发方不是可有可无的元数据——它们合起来就是用户所持全部账号的一张地图。

## 3. 分析：方法、机制与攻击

### 3.1 方法

每款应用的 APK 都用 ADB 从 Google Play 拉取，分三个阶段分析。**动态分析**把应用装在一台运行定制版 Android 9（由 AppCensus 维护）的 Pixel 3a 上，该系统会把明文网络流量落盘，同时用 `scrcpy` 镜像屏幕，使每一笔外发流量都能追溯到触发它的那一次点击。这种平台级抓包能把流量归因到具体应用，并能绕过 TLS 证书固定（certificate pinning）——这两点恰恰是 mitmproxy、Charles 一类普通代理的软肋。由于研究者掌控配置流程，他们可以埋入**已知值**：构造两个写入指定签发方、标签、密钥的二维码，再在抓到的流量里搜索这些字符串；一旦命中，就证明该字段是明文离开设备的。

**密码分析**则用 `jadx` 反编译 APK，通过静态字符串以及和 Bouncy Castle、libsodium 的函数签名比对来定位密码学代码，重建两件事：密钥是怎么来的（用了哪个 KDF、盐是什么、迭代多少次），以及密文由哪个密码与哪种模式产生、有没有完整性保护。为证明结论无误，作者把每款应用的解密过程用独立 Go 脚本重新实现，验证它确实能还原出二维码里的密钥。全部材料作为可复现的 artifact 公开。

### 3.2 备份机制的分类计数

表 1 按支持哪些备份机制对每款应用归类。

| 机制 | 应用数 | 安装量 |
|---|---|---|
| 二维码迁移（离线） | 7 | 101 M+ |
| 云同步，明文 | 3 | 6.1 M+ |
| 云同步，加密 | 9 | 73.7 M+ |
| 文件导出，明文 | 5 | 1.8 M+ |
| 文件导出，加密 | 6 | 1.5 M+ |
| 分享，明文 | 7 | 2 M+ |
| 分享，加密 | 4 | 1.7 M+ |
| Android 自动备份 | 9 | 2.2 M+ |

完全不经过网络的离线方案十分稀少。7 款应用提供二维码迁移，而安装量高出第二名一倍以上的 Google Authenticator **只**支持这一种。Google 说明该功能需要「对该手机的物理接触以及解锁能力」。但它在可用性上不成立：纯手工、必须有第二台设备，而且每新增一个账号就要重做一遍。

**明文备份。** 超过半数的应用——**12 款**、近 800 万安装量——能产生明文备份。其中 10 款通过 Android 分享菜单、剪贴板或文件导出实现；只有 **3 款**把明文同步到云端。Latch 会不经同意地把所有字段自动发给 Latch 服务器，而这已是它唯一的备份方式；SAASPASS 经 XMPP 备份明文，虽是可选项且默认关闭，却不断弹窗催促开启；2FAS 的 Google Drive 备份默认就是明文。**警告**才是这里真正的丑闻：§5.2 统计的 12 款里只有 **4 款**给出了真正的警示——2FAS、Authenticator Pro、andOTP 与 Aegis Authenticator。（论文摘要写的是「只有两款」，这与正文自相矛盾；正文更具体，并点出了这四款的名字。）Authenticator Pro 在文件导出时给了详细警告，但它同时提供的剪贴板复制却毫无提示。

**加密备份，以及它是怎么做的。** **15 款**应用、超过 7400 万安装量支持加密备份——而问题恰恰集中在这里。除一款外，其余全部由用户自设的口令派生密钥，因此拿到密文的攻击者可以像攻击口令哈希一样攻击它。可行性首先取决于口令强度，其次才取决于 KDF。

*口令策略。* 多款应用接受**单字符**口令；样本中的最小长度从 1（Auth0 Guardian、2FAS、Authenticator Pro）到 12（LastPass Authenticator）不等。Duo Mobile 会拒绝已知弱口令，Latch 会查询 Have I Been Pwned 并提示，但只有 Aegis 提供了强度计。Authenticator 与 App Authenticator 可以从 6,566 词的词表中建议四词口令，但两者随后都用了静态盐，这基本抵消了建议口令的意义。

*KDF。* PBKDF2 是最常见的选择（**n = 7**，其中 4 款配 SHA-1、3 款配 SHA-256），但代价形同虚设：样本中最高的迭代次数也只有约 **10 万次**（andOTP、LastPass Authenticator），而 OWASP 的现行建议是 PBKDF2-HMAC-SHA1 用 72 万次、PBKDF2-HMAC-SHA256 用 31 万次。Zoho OneAuth 与 TOTP Authenticator 更进一步，直接用**单轮 SHA-256**——那是快速哈希，根本不是 KDF；Authenticator 与 App Authenticator 用的是 PKCS#12 的 KDF。只有 **3 款**使用了内存硬（memory-hard）KDF：Yandex.Key 与 Aegis Authenticator 用 scrypt，Duo Mobile 用 Argon2i。

$$\text{Duo (Argon2i)}: m = 128\ \text{Mb},\ t = 6,\ p = 1; \qquad \text{Aegis (scrypt)}: N = 2^{15},\ r = 8,\ p = 1$$

随机盐是主流做法，但 Authenticator 与 App Authenticator 把盐硬编码成 `ROYALEWITHCHEESEROYALEWITHCHEESE`，从而使备份暴露在彩虹表攻击之下；作者据此怀疑 App Authenticator 是未经授权的二次打包克隆——盐值相同，且「塞满广告」。

*密钥管理。* 有几款应用的备份能被存储密文的那一方解密，因为密文与密钥（或派生密钥的口令）落到了同一个实体手里。**Microsoft Authenticator** 是唯一使用 Microsoft 密钥服务随机生成 AES-256 密钥的应用，但它同时把密文存在 Microsoft 自控的存储服务上（Microsoft 确认该设计是有意为之；而 iOS 版本把密文放在用户自己的 iCloud 里，Microsoft 便不具备这种能力）。**Yandex.Key**、**Zoho OneAuth**、**Salesforce Authenticator** 都在上传密文的同时，把备份口令发给了自家服务器——Zoho 的文档声称口令不会被存储，但传输本身可被观测，用户也无从验证。**TOTP Authenticator** 更彻底：它用静态硬编码口令派生 Google Drive 备份的密钥，任何反编译 APK 的人都能拿到这把钥匙。

*密码与完整性。* 15 款加密备份的应用中，**5 款**使用了现代 AEAD（2 款用 libsodium 的 `secret_box`，即 Xsalsa20-Poly1305；3 款用 AES-GCM），**5 款**用 AES-CBC，**3 款**用 AES-ECB——后者是确定性加密，不满足 IND-CPA（选择明文下的不可区分性）。Microsoft Authenticator 是唯一不用 AEAD 却对密文做认证的应用（HMAC-SHA256）；其余应用完全没有 MAC，只能靠启发式猜测解密是否成功——解密结果是不是合法 JSON、合法 URI、或合法 Base32？离线攻击者用的是同一套启发式，所以省掉 MAC 一点安全性都没换来。TOTP Authenticator 还叠加了全零 IV；2FAS 存在交互设计缺陷，会在用户设置备份口令之前就把已有 TOTP 数据以明文传上 Google Drive。andOTP 是唯一支持非对称加密的应用，而它的做法是把明文交给另一个 PGP 应用处理。

**Android 自动备份（AAB）。** AAB 默认把应用数据上传到用户的 Google Drive，在 Android 9 及以上用设备 PIN、图案或口令做端到端加密。12 款应用显式关闭了它，10 款支持，其中 3 款无法让 AAB 无错运行。在可观察到行为的 7 款中，有 6 款备份了**全部** TOTP 字段，于是 Google 账号成了单点故障；Google Authenticator 只备份了应用设置。Auth0 Guardian 额外加了一层受口令保护的加密 Realm 数据库。

### 3.3 隐私：泄露了什么

只有 **2 款**应用仅为了打开就得索取个人信息：Twilio Authy（邮箱，外加证明手机号归属）与 Latch（需注册账号，含邮箱）。但开启云同步几乎总要交出信息。11 款云同步应用中，**8 款**要求邮箱、**5 款**要求手机号；Microsoft Authenticator 要求最多——手机号、邮箱、姓名和出生日期；Zoho OneAuth 收集邮箱、国家与州。3 款直接上传 Google Drive 的应用通过 OAuth/OpenID 拿到了用户的主邮箱、姓名和头像，而这些对备份功能毫无必要。

第二类泄露用户完全看不见：多款应用只加密密钥，却把签发方和标签明文带出。Zoho OneAuth 与 Twilio Authy 会把服务名称与账号名以明文发到自家服务器，于是链路上任何一环都能知道用户持有哪些账号。Duo Mobile 则视服务是否在内部「热门网站」名单上，有条件地把签发方或标签之一明文包含进去；Duo 的理由是：让用户在未恢复状态下看到账号，有助于他们重新配置。

### 3.4 恢复：闭环合上

在 **19 款**会把备份自动上传到云端的应用中，**15 款**需要登录云服务，另外 **4 款**在恢复时**仅**依赖短信验证码。SAASPASS 把「明文云备份」和「仅短信恢复」凑到了一起：任何接管了手机号的人立刻拿到完整备份；它提供一个可选的对恢复短信延迟 20 小时的开关，能给用户争取时间，但很少有人会去安全菜单里翻到它。这些云账号本身就是普通的口令账号——Latch 只要求用户名加口令，且不支持任何 2FA。就连 Google 推动数亿用户启用 2FA 这件事，最终也把大部分人导向短信或推送，而推送恢复可能需要在一台已经丢失的设备上点确认。

全文最锋利的一句结论是：云备份「不可避免地把 TOTP 2FA 的安全性降格为它本该取代的那套认证机制的又一层——用户名/口令、短信和/或邮箱」。

<div class="aside">
<p><span class="aside-label">题外话 · 加密了，钥匙就在旁边</span></p>
<p>论文关于密钥管理的发现，像一只上了锁的箱子，钥匙就贴在箱盖上。有 4 款应用把备份口令、或由它派生的密钥，发给了存放密文的同一个主体——分别是 Microsoft Authenticator、Yandex.Key、Zoho OneAuth 和 Salesforce Authenticator——于是拿着密文的那一方也能把它解开。另有 2 款干脆把明文密钥直接发给开发者，还有 2 款把盐硬编码成同一个值，等于白送攻击者一张彩虹表。</p>
<p class="aside-source">出处：Gilsenan、Shakir、Alomar、Egelman, USENIX Security 2023——密钥管理（密文与密钥落到同一实体、明文密钥发给开发者、硬编码盐）。</p>
</div>

## 4. 影响与局限

**建议。** 应用不应支持明文备份；若支持，必须清晰警告。必须加密**全部**字段而非只加密密钥；使用远端密钥服务器的应用应把密钥与密文拆分到不同实体。由口令派生密钥的应用应执行强口令策略，绝不让备份口令离开应用（用完即从内存抹除，密钥存入 Android Key Store），并把 KDF 配置得比「口令存储」类建议**慢得多**——密钥派生只在设置和恢复时各发生一次，因此作者提议复用用户熟悉的 30 秒倒计时，把 KDF 调到耗时 30 秒。他们推荐 Argon2，因为它能独立调节内存与 CPU 参数。andOTP 已经把 PBKDF2 轮数调到 1 秒的预算内，但只用于 AAB 路径，用于 Google Drive 时没有这么做。

**负责任披露。** 6 款应用无可披露；andOTP 被开发者宣布弃用；TOTP Authenticator 找不到安全联系人。其余 14 位开发者都收到了通知并留有至少 90 天，其中 6 位始终未回复。回复本身就是发现：Twilio 让 2020 年就在 Authy 中报告的问题又存活了两年多（v24.3.1 到 v24.8.5），才承诺加长备份口令并显著提高 PBKDF2 迭代次数，并为明文发送签发方与标签辩护；Latch 称明文备份是「设计如此」，Microsoft 也给出一致说法；Salesforce 只是指向两篇从未回应「它能解密备份」这一事实的帮助文档。唯一的例外是 Authenticator 的开发者：1.2.4 版改用随机盐与 AES-CBC，把最短口令长度设为 20，并增加了明文导出警告。

**局限。** 研究仅覆盖 Android，且作者明确指出两平台并不一致——Microsoft Authenticator 就是反例。有 3 款支持 AAB 的应用无法让 AAB 无错运行。LastPass Authenticator 与 Auth0 Guardian 的密码学细节无法直接验证，表中相应单元格来自文档与观察，并已明确标注。

## 5. 相关文献

- **RFC 6238 —— TOTP: Time-Based One-Time Password Algorithm**（M'Raihi 等，2011）。<https://www.rfc-editor.org/rfc/rfc6238> 本章应用所实现的算法。它定义了客户端与服务端如何使用共享密钥，却把密钥传递排除在外——正是备份机制填得很糟糕的那个缺口。
- **Google Key URI Format**。<https://github.com/google/google-authenticator/wiki/Key-Uri-Format> 事实上的配置标准：`otpauth://` URI 以及经二维码下发的签发方/标签/密钥字段；Gilsenan 等正是靠它埋入已知值来检测泄露。
- **Sean Oesch, Scott Ruoti. "That Was Then, This Is Now"（USENIX Security 2020）。** <https://www.usenix.org/system/files/sec20-oesch_0.pdf> 对浏览器密码管理器在口令生成、存储与自动填充方面的安全评估——同一套方法论（反编译、重建密钥调度、检验离线攻击）用在另一类保险库上；见第 9 章。
- **Giuseppe Bianchi, Lorenzo Valeriani. "Time Is on My Side: Forward-Replay Attacks to TOTP Authentication"（SocialSec 2023）。** <https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7> 攻击的是 TOTP 协议本身而非其实现：在服务端仍然接受的窗口内重放验证码。与本章互补——Gilsenan 等展示的是密钥如何从存储中漏出，这两位展示的是一个被观测到的验证码值多少钱；见第 7 章。
- **Sabrina Amft 等. "'We've Disabled MFA for You'"（CCS 2023）。** <https://arxiv.org/abs/2306.09708> 考察了 1,303 个网站的 MFA 恢复流程，发现许多流程允许只要能访问账号绑定邮箱的攻击者彻底关闭 MFA——这正是本章客户端问题在服务端的镜像。
- **Sanchari Das, Bingxing Wang, Andrew Kim, L. Jean Camp. "MFA is a Necessary Chore!"（HICSS 2020）。** <https://aisel.aisnet.org/hicss-53/os/design/3/> 探讨用户对 MFA 的心智模型，确立了「怕被锁死」这一动机——本章分析的每一种备份机制都源于此。

## 6. 小结与回响

- 样本是 Google Play 上 **22 款**通用型 Android TOTP 应用（安装量 ≥10 万且带备份机制），合计安装量**超过 1.8 亿**，从 546 个候选筛选而来（2021 年底）。
- 方法为动态分析（在 Pixel 3a 上做平台级抓包，并埋入已知二维码值以检测明文泄露）加密码分析（用 `jadx` 反编译、重建 KDF 与密码，再用 Go 重写解密过程）。
- **12 款**应用能产生明文备份，其中只有 **4 款**警告了用户（§5.2；摘要写作两款）。
- **15 款**支持加密备份，但除一款外都由用户口令派生密钥；**5 款**用 AEAD、**5 款**用 AES-CBC、**3 款**用 AES-ECB，且 Microsoft Authenticator 是唯一对密文做认证的非 AEAD 应用。
- KDF 普遍偏弱：2 款用单轮 SHA-256，2 款用硬编码盐，最高的 PBKDF2 迭代次数也只有约 10 万。
- **4 款**把密钥或口令发给了存储密文的同一个服务，**2 款**干脆把明文密钥直接发给开发者。
- 恢复流程把 2FA 拽回口令、短信与邮箱：19 款云备份应用中有 **4 款**仅凭短信验证码恢复。
- 建议：不做明文备份、加密每一个字段、密钥与密文分离存放、口令不离开设备，并把 KDF 调到 30 秒的预算（优先 Argon2）。

**回响。** 这一章是第二幕埋下的伏笔第一次爆炸。第 3、4 章的 HOTP 与 TOTP，为了好用，把共享密钥重新放回了服务器两边；第 5 章的 T/Key 已经证明可以把它取走，但市场选择了方便。于是账单在这里送到：一个必须存放在某处的密钥，最后落进了云盘、明文导出文件或开发者的服务器；而备份存在的理由本就是对抗锁死，于是它又把恢复流程拽回口令、短信和邮箱——恰恰是 TOTP 当初宣称要取代的那几样。同样的剧本会在第 8 章之后重演：密码管理器一面宣称「零知识加密」，一面留着一份保险库的副本；而决定一份被盗保险库能撑多久才被破解的，正是和本章这些迭代次数一样不起眼的参数。第 7 章则去追本章没有触及的另一个假设——时钟。

## 参考文献

1. Conor Gilsenan, Fuzail Shakir, Noura Alomar, Serge Egelman. *Security and Privacy Failures in Popular 2FA Apps*. 第 32 届 USENIX Security 研讨会, 2023, pp. 2079–2096. <https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf>
2. Conor Gilsenan, Fuzail Shakir, Noura Alomar, Serge Egelman. 同上论文的 *Artifact Appendix*. USENIX Security 2023. <https://www.usenix.org/system/files/usenixsecurity23-appendix-gilsenan.pdf>（artifact：<https://github.com/blues-lab/totp-app-analysis-public>）
3. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, 2011. <https://www.rfc-editor.org/rfc/rfc6238>
4. Google. *Key URI Format*（TOTP 事实上的配置标准）. <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
5. Sean Oesch, Scott Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. 第 29 届 USENIX Security 研讨会, 2020, pp. 2165–2182. <https://www.usenix.org/system/files/sec20-oesch_0.pdf>
6. Giuseppe Bianchi, Lorenzo Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication*. SocialSec 2023 (Springer), pp. 109–126. <https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7>
7. Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments*. ACM CCS 2023, pp. 3138–3152. <https://arxiv.org/abs/2306.09708>
8. Sanchari Das, Bingxing Wang, Andrew Kim, L. Jean Camp. *MFA is a Necessary Chore! Exploring User Mental Models of Multi-Factor Authentication Technologies*. HICSS 2020. <https://aisel.aisnet.org/hicss-53/os/design/3/>

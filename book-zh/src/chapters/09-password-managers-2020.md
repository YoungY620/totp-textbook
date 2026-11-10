# 那是当时，这是现在（2020）

<div class="source-card">
<p><strong>本章文献：</strong> Sean Oesch, Scott Ruoti. <em>That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers</em>. 收录于 Proceedings of the 29th USENIX Security Symposium, USENIX Association, 2020 年 8 月, pp. 2165–2182。<a href="https://www.usenix.org/system/files/sec20-oesch_0.pdf">开放获取 PDF</a>（<a href="https://www.usenix.org/conference/usenixsecurity20/presentation/oesch">会议页面</a>）。</p>
<p><strong>一句话：</strong> 在经典评估过去五年之后，本文重新审视 13 款流行密码管理器，覆盖其生命周期的全部三个阶段——生成、存储、自动填充——结论是确有进步，但一批老问题依旧，并且第一次暴露了一个此前无人测量的新问题：生成器实际吐出来的口令长什么样。</p>
</div>

<div class="hook">
想象那个从未出现的自动填充提示：你打开一个页面，表单自己填好了，你甚至没察觉。2014 年，好几篇论文演示了这种便利如何变成一条凭据窃取通道，厂商随即动手修补。六年之后，一个团队重新打开 13 款密码管理器，用同一个问题去问整整一代新软件——当初的洞，到底修好了没有？答案不是一句「修好了」；而真正没有人想起要去检查的那一环，恰恰是那个负责「凭空造出口令」的按钮。
</div>

## 1. 背景与问题

密码管理器本应弥合「安全建议说的」与「用户能做的」之间的落差。它生成强口令、把口令存进加密的保管库（vault）、并在正确的站点替用户填写，于是用户既不必记住任何一个口令，又能为每个账号保留唯一口令。Herley 的论证 [18] 指出：当付出的努力很大、而风险很小时，用户理性地拒绝安全建议是合理的——密码管理器正是为了卸下这份负担而存在。

但这个工具本身也是软件，而只要把三件事中的任何一件做错，密码管理器就会变成它所保管的全部账号的单点故障。这正是本文继承的问题意识。Li 等 [19] 在 2014 年分析了 5 款**基于浏览器扩展**的管理器，发现逻辑与授权错误、对 Web 安全模型的误解、CSRF/XSS 暴露，以及沙箱做得不到位的 bookmarklet。同年 Silver 等 [29] 与 Stock 和 Johns [31] 证明自动填充（autofill）是一条凭据窃取通道：如果管理器不经询问就填写，那么任何被攻击者注入脚本的页面都能直接拿到口令；而如果允许在 iframe 内自动填充，点击劫持（clickjacking）就能伪造出用户从未真正给出的「用户交互」。Gasti 和 Rasmussen [17] 则分析过保管库格式，发现未加密的元数据（metadata）以及从密文泄露的旁道信息。

作者的动机在于：这些结论脚下的地基已经变了。2014 到 2020 年间，产品形态发生变化——管理器从浏览器扩展走向独立 App 与通过云端同步的保管库，浏览器也开始自带内置管理器。一条 2014 年关于 bookmarklet 部署方式的结论，可能对 2020 年一个云同步扩展毫无意义。因此论文的框架是明确的对照式命题——*that was then, this is now*（那是当时，这是现在）——它同时问两个问题：**五年前发现的具体漏洞修好了吗？这些工具现在是否已经可以放心大规模采用？** 它还有第二个更原创的动机：文献里根本没有人评估过**口令生成**。此前的工作看的是保管库如何存储、或凭据如何被填写，却没人问过：生成器产生的口令真的随机吗？

## 2. 评估对象与方法

**研究对象。** 13 款密码管理器，按与浏览器集成的紧密程度分类（原表 Table 1）：

| 类别 | 管理器 |
|---|---|
| App（桌面客户端，不与浏览器集成） | KeePassX、KeePassXC |
| 扩展（extension） | 1Password X、Bitwarden、Dashlane、LastPass、RoboForm |
| 浏览器内置 | Chrome、Edge、Firefox、Internet Explorer、Opera、Safari |

即 2 款桌面客户端、5 款浏览器扩展、6 款浏览器原生管理器。作者指出，到写作时已有若干变化：KeePassXC 把默认密钥派生函数（key derivation function，KDF）换成了 Argon2D；LastPass 与 RoboForm 改版了生成界面；Firefox 将转向 Firefox Lockbox；Edge 将改为基于 Chromium（第 3.4 节）。作为对照，生成研究还包含两个基线：一个读取 `/dev/random` 的 Python 脚本，以及在线 Secure Password Generator（SPG，在 Google 搜索 "password generator" 的第一条结果）。

**生成。** 这是论文的原创贡献。13 款管理器中有 9 款具备口令生成能力——7 款完整支持（KeePassX、KeePassXC、1Password X、Bitwarden、Dashlane、LastPass、RoboForm），2 款部分支持（Chrome、Safari）。作者对每个生成器交叉变化字符类别（仅字母 `l`；字母加数字 `ld`；字母加符号 `ls`；符号加数字 `sd`；四类全含 `all`）与长度（8、12、20），**每种组合采集 100 万个口令**。加上两个基线，语料库共 **1.47 亿个口令**——论文给出的算式是 $10 \times 5 \times 3 - 3$，其中减去的 3 对应唯一的例外（1Password X 无法生成「只有符号和数字」的口令）。Safari 没有可用于脚本化生成口令的接口，因此只手工生成并检查了 100 个口令，未发现明显问题。

由于没有任何测试能证明一个伪随机生成器不可与真随机区分，作者用四种彼此独立的检测手段去找**非随机性的证据**：字符频率上的香农熵（Shannon entropy）；随机性 $\chi^{2}$ 检验；zxcvbn 强度估计器；以及 Melicher 等 [22] 的 LSTM 循环神经网络口令猜测器（用每个语料的 80% 训练、20% 测试）。因为同一族数据上做了大量检验，所有 $p$ 值都按 147 做了 Bonferroni 校正（乘以 147，上限取 1.00）。

**存储。** 云端数据库对作者不可见，因此存储的评估方式是**逐个手动检查各管理器在本地的数据库**，考察哪些内容被加密、密文格式如何、以及更换主口令（master password）会怎样影响密文。作者特别说明，「加密是如何进行的」这一判断综合了维护者的声明、客户端暴露的选项与密文的格式——它并不是对云端服务的密码学审计。

**自动填充。** 作者搭建了测试网站，复现 Li 等 [19]、Silver 等 [29]、Stock 和 Johns [31] 所描述的攻击，并针对此后浏览器与管理器新增的防护做了更新。观察指标是可分级而非通过／失败的二值：是否需要用户交互（user interaction）、在同源与跨源 iframe 中的行为、当被填充的表单与保存口令时的表单不一致时是否反应、以及是否填充非标准的登录字段。

## 3. 评估结果

### 3.1 生成

**主要问题不是明显的非随机，而是弱口令。** 字符分布检验发现了若干统计上非随机的分布（Table 4），但几乎都能用一个无辜的特性解释：要求口令至少包含每个已选类别中的一个字符。记 $|characters_{all}|$ 为已启用字符集之并的大小、$|sets|$ 为启用类别数，则某字符出现的概率：

不启用该特性时为

$$
\frac{1}{length \cdot |characters_{all}|}
$$

启用该特性时为

$$
\left( (length - |sets|) \cdot \frac{1}{|characters_{all}|} \right) + \frac{1}{|characters_{set}|}
$$

也就是说，来自*更小*字符集（数字、符号）的字符会更高频地出现。两个看似例外的情况其实也吻合：Bitwarden 的 `sd` 集里符号与数字数量相等，因此二者被选中的频率相同；Dashlane 的 `l` 集里大写与小写字母数量不等。唯一无法用这条特性解释的是 RoboForm 的 `l`：除 `Z` 之外的大写字母比小写字母被更频繁地选中，而 `Z`、`z`、`9` 一贯是最少被选中的字符。作者假设这与用取模运算选取字符有关（`rand()%(max - min) + min`），但明确标注为假设。

真正严重的发现不是分布偏斜，而是**尾部**。按通行的阈值——抵抗在线攻击需要超过 $10^{6}$ 次猜测、抵抗离线猜测需要超过 $10^{14}$ 次 [16]——分析显示：生成器既然是真正随机的，就偶尔会吐出可被轻易猜中的口令，例如做了常见替换的字典词（`d@rKn3s5`），或重复字符模式（`'+'+'+_+`）。这类口令很罕见——**不到 1/200**——但确实会出现。后果随长度放大：长度为 8 时，最弱的生成口令对*在线与离线*攻击都不设防；长度为 12 时只对离线攻击不设防；长度为 20 时连最弱的口令也能扛住离线攻击。论文由此给出经验规则：**抵抗在线攻击取长度 10，抵抗离线攻击取长度 18**。

另外两个生成层面的问题属于界面而非统计。其一，各家的符号集差异极大——KeePassXC 支持除空格外的全部标准 ASCII 符号外加扩展 ASCII；KeePassX 与 Dashlane 支持除空格外的标准 ASCII；1Password X 支持 19 个符号；其余不超过 8 个——而每一种限制都直接削弱口令强度。其二，多数管理器会**把最近一次使用的设置保存为新的默认值**，于是用户一旦为迁就某站点的密码策略把设置调弱，此后更弱的设置就可能悄悄变成他的默认（Dashlane 避免了这一点；KeePassX 只在应用重启前保留新设置）。

### 3.2 存储

App 与扩展类管理器都用 **AES-256** 加密保管库，并且都用 KDF 从主口令派生密钥。KeePassX 与 KeePassXC 用 AES-KDF、10 万轮；1Password X、Bitwarden 与 LastPass 用 PBKDF2、约 10 万轮（原表分别为 100,000、100,001、100,100）；RoboForm 的 PBKDF2 只有 **4,096 轮**——是这一组里唯一低于 10 万的；Dashlane 则是唯一采用内存硬（memory-hard）KDF 的，用 **Argon2D、3 轮**。

浏览器内置的管理器里，只有 Firefox 自己加密保管库，而且是做得最差的：数据用 **3DES**，密钥派生只用**一轮 SHA-1**，并且对主口令毫无策略要求。作者称它「远为最弱」。其余各家把加密交给操作系统——Edge、Internet Explorer 与 Safari 用 Windows Vault 或 macOS 钥匙串；Chrome 与 Opera 在 Windows 上用 `CryptProtectData`、在 Linux 上先尝试写入 GNOME keyring 或 KWallet，若两者都不可用则**退回到明文存储口令**，在 macOS 上用钥匙串派生密钥但口令本身存在本地。由于这些管理器没有自己的主口令，它们的保管库无法独立于操作系统账号被锁上。

元数据方面，情况确实比 2014 年好。KeePassX 与 KeePassXC 加密全部元数据；扩展类管理器加密大部分，但每家都至少留了一项未加密——1Password X 把**扩展设置以明文存储**，其中包括是否启用自动锁定等安全相关设置；Dashlane 加密网站 URL 但不加密与之关联的**图标**，从而泄露用户开了哪些账号；所有扩展类管理器都泄露用于登录管理器的邮箱地址。其余浏览器管理器（Windows/macOS 上的 Chrome 与 Opera，以及全平台的 Firefox）把 **URL 明文存储**，且除 Firefox 外用户名也是明文，还暴露账号创建时间、最后使用时间与填充次数。

### 3.3 自动填充

自动填充是「那是当时」这条线索延续的地方。只有 KeePassX 完全没有浏览器自动填充，只有 Bitwarden 把自动填充标注为实验性；其余之中，**只有 1Password X 与 Safari 总是要求用户交互**。别的要么默认不经询问就填充（Dashlane、LastPass、Firefox——虽有「要求交互」选项，但默认值才是关键），要么总是自动填充（Chrome、Edge、Internet Explorer、Opera）。KeePassXC、Bitwarden 与 RoboForm 默认要求交互，但允许用户关掉这一要求，也就是说它们距同样的暴露只差一个设置。管理器对无效的 HTTPS 证书会反应——Edge 与 IE 升级为要求交互，Chrome 与 Opera 干脆禁用自动填充——但在明文 HTTP 下反应参差不齐。

iframe 的结果最为尖锐。在 iframe 内自动填充无论是否需要交互都危险，因为点击劫持可以隐形地代用户「交互」；而如果允许在**跨域** iframe 内自动填充且不要求交互，攻击者就能对他能通过注入或 XSS 触达的每一个站点批量收割凭据。KeePassXC、1Password X、Dashlane、LastPass 会在同源 iframe 内填充，因而暴露于点击劫持；Bitwarden 与 RoboForm 也会填充，但把交互提示放在页面之外（扩展的下拉浮层中），从而基本化解了点击劫持。KeePassXC 还允许跨域 iframe 填充，且其交互要求可以关闭，因此可被收割攻击。Firefox 的默认行为——跨域 iframe 不要求交互——使它在开箱状态下就**易受域收割攻击**，这正是作者点名建议避开它的原因。Chrome、Edge、IE、Opera 与 Safari 在跨域 iframe 中要求交互，但点击劫持这条路径依然敞开。

两个修复实验揭示了生态在哪里卡住了。Stock 等 [31] 提出一种**基于 nonce 的自动填充**：先填入一个 nonce，只有当请求真的要发往匹配域时，管理器才把它换成真口令，于是页面 JavaScript 永远看不到秘密。**13 款管理器无一支持**，而作者自己着手实现时也失败了，因为浏览器不允许扩展修改请求体。而 `autocomplete="off"` 属性——W3C 规范说它应当阻止用户代理（user agent）填充字段——**没有任何一款管理器遵守**，这与 Mozilla 自己的说明一致：为维持管理器可用，现代浏览器对登录字段有意忽略该属性。

### 3.4 Web 保管库

5 款扩展类管理器中，1Password X、Bitwarden、Dashlane、LastPass 使用了 CSRF token；**RoboForm 没有**，作者对其 Web 保管库发起 CSRF 攻击并改掉了会话超时参数。内容安全策略（CSP）方面，1Password X 与 Dashlane 没有问题；Bitwarden 有两处小缺口（`script-src 'self'`、`object-src 'self'` 与 `blob:`）；**LastPass 在 `script-src` 中允许 `unsafe-inline`**，这是一个显著的 XSS 开口；而 **RoboForm 完全没有 CSP**。针对 LastPass 与 RoboForm 的实际利用尝试都失败了，因为两个站点的输入清洗都很严格——作者仍指出这两家都应实施更严格（或任何）的 CSP。bookmarklet 方面，只有 LastPass 还在提供，且其代码正确地在受保护的 iframe 内执行并过滤危险消息，纠正了 2014 年的问题。

### 3.5 那是当时，这是现在

- **已修复或改善（不再成立的「当时」）：** App 与扩展类保管库的元数据保护；不安全 bookmarklet 部署方式的移除；对 iframe 内自动填充的限制，足以关闭凭据收割攻击；以及在线 Web 保管库的 CSRF/XSS 加固。
- **被复制、即仍然存在的问题（延续至今的「当时」）：** 不经用户交互的自动填充，在遭 XSS 或注入攻陷的页面上仍是实打实的凭据窃取通道；同源 iframe 上的点击劫持仍能绕过交互要求；管理器仍不会对「正在填充的表单 ≠ 保存口令的表单」发出警告；没有一款实现 Stock 等的 nonce 式安全自动填充；`autocomplete="off"` 仍被普遍忽略。
- **新增的（「现在」）：** 第一次对口令生成做测量，发现非随机的字符分布，以及更重要的——偶尔可被轻易猜中的生成口令；1Password X 的明文扩展设置；不安全的生成*默认值*；LastPass 的 `unsafe-inline` CSP 与 RoboForm 缺失的 CSP 和 CSRF token；以及一个结构性障碍——浏览器拒绝让扩展改写请求体——它封死了 XSS 安全自动填充唯一被提出的缓解方案。

<div class="aside">
<p><span class="aside-label">题外话 · 一个参数决定成败</span></p>
<p>保管库的 AES-256 之下，是从主口令派生出来的一把密钥；而决定「一份被偷走的保管库破解起来有多贵」的参数，就是派生的成本——对这一代（2019 年的）PBKDF2 与 AES-KDF 构造而言，即迭代次数。在 Oesch 与 Ruoti 审视的版本里，LastPass 的 PBKDF2 跑了 100,100 轮，而 RoboForm 只有 4,096 轮——这是该组中唯一低于 10 万的数字。它安静地躺在表格里，很容易被跳过；可它实质上就是「被盗保管库还能撑多久」的全部答案。</p>
<p class="aside-source">出处：Oesch &amp; Ruoti, USENIX Security 2020, Table 6（论文正文把同一批数字概述为「约 10 万轮」）。</p>
</div>

## 4. 适用场景与迁移边界

**结论覆盖哪些产品形态。** 本研究针对**桌面上的、以浏览器为中心**的密码管理器：桌面客户端、浏览器扩展，以及 6 款浏览器自带的管理器。未被覆盖的：独立的移动端管理器与原生移动自动填充框架（作者在第 7.2 节明确将其列为必要的后续工作）。因此凡涉及「密码管理器」的一般性结论，都应读作「2019 年的桌面、浏览器类密码管理器」——版本号在论文中已固定。存储结论还进一步限于**本地保管库**：云端后端无法直接评估，加密判断依赖可观察的密文格式与维护者声明，而非审计。

**结论所依赖的前提。** 生成结论假设各生成器处于默认配置、且语料按上文方式构造；神经网络分析缺少长度为 20 的结果，因为分析器内存溢出，所以关于长口令的论断依赖另外三种检测手段。自动填充结论假设攻击者能触达页面——通过网络注入（例如控制一个恶意 Wi-Fi 接入点）或某处 XSS 漏洞——而点击劫持还假设用户会被诱导访问恶意页面；作者认为这道门槛很低，因为身处同一接入点的攻击者可以向每个用户都会看到的强制门户（captive portal）页面注入内容。

**哪些已经过时、如何过时。** 有些结论在论文写作时就在变化：KeePassXC 已改为默认使用 Argon2D（使 10 万轮 AES-KDF 这个数字退役），LastPass 与 RoboForm 改版了生成界面，Firefox 将用 Firefox Lockbox 替换内置管理器，Edge 将重建于 Chromium。论文自己交代了披露过程：结果已交给每一款受研究管理器的维护者，而 RoboForm 已采纳了其中若干建议。今天读来，长期有效的部分是*方法*与*失效的形态*，而不是版本号——真正能迁移到新管理器或新平台的，是那张问题清单（什么被加密、默认值设成了什么、谁触发自动填充、iframe 里发生什么、保管库是否理会 `autocomplete`）。

**方法论的可迁移性。** 生成方法论——每种配置百万口令的语料，配上四种各自独立的非随机性检测与 Bonferroni 校正——是可用于任何从随机数产生器（RNG）输出秘密的产品的通用工具；论文对其限度也很坦诚：没有任何测试能*证明*随机，所以方法只能给出反例；而基线上（`/dev/random` 以及若干管理器）的阴性结果与阳性结果同样重要，因为它们说明这些检测在真有问题时确实会触发。同一套工具被后续工作沿用：Oesch、Gautam 与 Ruoti 在 2021 年把自动填充的威胁模型搬到 iOS 与 Android 的自动填充框架 [a]，Oesch、Ruoti、Simmons 与 Gautam 又在 2022 年做了一项关于管理器实际如何被使用的观察性用户研究 [b]——恰好补齐了本文自己标出的两个边界条件（移动端，以及真实用户而非被配置好的默认值）。

**对实践意味着什么。** 论文的建议很直接：在浏览器内置的管理器中，避开 Firefox 内置保管库（自动填充不安全、易受收割攻击）；优先选择 App 与扩展类管理器，它们功能更全、存储更安全、且拒绝在跨源 iframe 中填充——Safari 是唯一例外，它存储做得好、也避免了自动填充失误，只是生成器不佳。即便如此，用户仍必须把工具配置正确，而作者指出这恰恰是用户很少能尽责做好的事。对本书主线而言，更大的教训是：密码管理器仍然持有一种*共享秘密*，并且仍会代表用户把它交到网页里，所以这种脆弱性是结构性的而非偶然的——这正是本领域的方向转向「根本不交给页面的秘密」的原因。

## 5. 相关文献

- **Z. Li, W. He, D. Akhawe, D. Song, *The Emperor's New Password Manager: Security Analysis of Web-Based Password Managers*, USENIX Security 2014**（[usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li)）——本文的直接前身、也是标题中「当时」的所指，覆盖 5 款扩展类管理器；本书第 8 章。Oesch 与 Ruoti 对它做了复现与更新。
- **D. Silver, S. Jana, D. Boneh, E. Y. Chen, C. Jackson, *Password Managers: Attacks and Defenses*, USENIX Security 2014**（[usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver)）——确立了自动填充的威胁模型（网络注入、XSS、点击劫持），并提出基于 nonce 的防御；Oesch 与 Ruoti 检验后发现无人实现。
- **B. Stock, M. Johns, *Protecting Users Against XSS-based Password Manager Abuse*, ASIACCS 2014**（[ACM DL](https://dl.acm.org/doi/10.1145/2590296.2590332)）——2014 年自动填充「双璧」的另一半；「更安全的自动填充」这一建议的出处，本文用它逐一核对了全部 13 款管理器。
- **P. Gasti, K. B. Rasmussen, *On the Security of Password Manager Database Formats*, ESORICS 2012**（[Springer](https://link.springer.com/chapter/10.1007/978-3-642-33167-1_44)）——存储方向的前身，发现未加密元数据与旁道泄露；Oesch 与 Ruoti 在本地保管库上重做一遍，发现元数据状况已大幅改善。
- **W. Melicher, B. Ur, S. M. Segreti, S. Komanduri, L. Bauer, N. Christin, L. F. Cranor, *Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks*, USENIX Security 2016**（[usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher)）——被本文复用作四种生成检测手段之一的 LSTM 口令猜测器。
- **D. L. Wheeler, *zxcvbn: Low-Budget Password Strength Estimation*, USENIX Security 2016**（[usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler)）——模式／可猜性估计器，既用作检测手段，也在建议中充当让生成器拒掉自己弱输出的过滤器。

**作者如何定位自己。** 他们是系统化者与渐进改良者，而非颠覆者：论文自己的说法是这些管理器「已有改善」，正确的回应是谨慎挑选、正确配置、改进默认值，并在浏览器层面支持认证——尤其是把口令认证变成浏览器的一等公民，以及让管理器生成一个由浏览器在传输时代入的 nonce。这一领域其后的轨迹正好承接本文结尾那句「把责任推给用户很少有预期的结果」：后续工作先走向移动自动填充框架 [a]，再走向理解真实使用 [b]，最后——即本书第 10–12 章——开始攻击「零知识」这一保证本身，如 Fábrega 等的注入攻击 [c]，以及把本文无法评估的云端保管库当作受攻击者控制的恶意服务器来分析。

## 6. 小结与回响

- 本文在经典 2014 年研究五年之后重新评估密码管理器安全，命题是**「那是当时，这是现在」**：哪些老发现被修复了，这些工具是否已可大规模采用？
- 它研究 **13 款管理器**——2 款桌面客户端、5 款浏览器扩展、6 款浏览器内置——并覆盖生命周期的**全部三个阶段**：生成、存储、自动填充。这是对口令生成的首次评估，也是首次同时考察三个阶段。
- 生成在 **1.47 亿个口令**的语料上测量（$10 \times 5 \times 3 - 3$：10 个生成器、5 种字符类别、3 种长度，各 100 万），用香农熵、$\chi^{2}$、zxcvbn 与 LSTM 口令猜测器四种手段，并按 147 做 Bonferroni 校正。
- 多数非随机字符分布都能归因于一个特性——要求每个类别至少含一个字符——但**尾部**才是关键：不到 1/200 的生成口令可被轻易猜中，因此长度 8 可能沦陷于在线猜测、长度 12 沦陷于离线猜测。长度 **10** 抗在线攻击，**18** 抗离线攻击。
- 存储确有改善（KeePassX/KeePassXC 加密全部元数据），但 AES-256 保管库仍会泄露：**1Password X 的扩展设置是明文**、Dashlane 泄露网站图标、所有扩展都泄露登录邮箱，而 Firefox 自带的保管库是全场最弱（3DES、一轮 SHA-1）。
- 自动填充仍是最大的攻击面：**只有 1Password X 与 Safari 总是要求用户交互**；若干管理器不询问就向被攻陷页面填充；而 **Firefox 的默认设置易受跨域 iframe 的域收割攻击**。
- 两个被提出的修复都被生态堵死：**基于 nonce 的安全自动填充**没有任何一款管理器支持（浏览器禁止扩展修改请求体），而 `autocomplete="off"` **没有任何一款管理器遵守**。
- 持久的贡献是**方法论**：一套「语料 + 多检测手段」的秘密生成器审计工具，以及一张可迁移到新产品、新平台的存储／自动填充问题清单——作者 2021 年的移动自动填充 [a] 与 2022 年的使用研究 [b] 正是这样做的。

**回响。** 第 8 章问的是「那是当时」，本章就是「现在」——同一类产品被重新审视：既有实打实的修复，也有一批顽固的幸存者，结论是概念站得住、出问题的是实现。两条线向前延伸。第一条正是上文边栏里那个枯燥的参数：决定一份被盗保管库能扛住多久离线猜测的「迭代次数」，在接下来两章里不再是脚注。第 11 章（Duan、Wang、Fu，S&P 2025）发现 43 款管理器里有 35 款靠 PBKDF2 或 Argon2 拖慢猜测，同时表明拖慢并不够——凡是能扛住离线猜测的产品都额外引入了一个高熵秘密，因为单个主口令本身提供不了那么多熵。第 12 章（Scarlata 等，2026）则直接攻击这个参数：恶意服务器可以压制客户端存储的 KDF 设置，把 Bitwarden 的成本从 $N = 600{,}000$ 压到 $N = 1$，攻击者约加快 30 万倍。迭代次数从来不是客户端能指望服务器替它守住的秘密。第二条线是本章的结构性判断：管理器终究会把一个*共享秘密*交给网页——而第 10 章会把这一点彻底掀翻：在那里，攻击者既不需要被攻破的客户端，也不需要被破解的密码学，因为加密状态本身就会泄露。

## 参考文献

1. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. 收录于 Proceedings of the 29th USENIX Security Symposium, USENIX Association, 2020, pp. 2165–2182. https://www.usenix.org/system/files/sec20-oesch_0.pdf
2. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-Based Password Managers*. USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li
3. D. Silver, S. Jana, D. Boneh, E. Y. Chen, C. Jackson. *Password Managers: Attacks and Defenses*. USENIX Security 2014, pp. 449–464. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver
4. B. Stock, M. Johns. *Protecting Users Against XSS-based Password Manager Abuse*. 收录于 Proceedings of the 9th ACM Symposium on Information, Computer and Communications Security (ASIACCS), 2014, pp. 183–194. https://dl.acm.org/doi/10.1145/2590296.2590332
5. P. Gasti, K. B. Rasmussen. *On the Security of Password Manager Database Formats*. 收录于 European Symposium on Research in Computer Security (ESORICS), Springer, 2012, pp. 770–787. https://link.springer.com/chapter/10.1007/978-3-642-33167-1_44
6. W. Melicher, B. Ur, S. M. Segreti, S. Komanduri, L. Bauer, N. Christin, L. F. Cranor. *Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks*. USENIX Security 2016, pp. 175–191. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher
7. D. L. Wheeler. *zxcvbn: Low-Budget Password Strength Estimation*. USENIX Security 2016, pp. 157–173. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler
8. D. Florêncio, C. Herley, P. C. van Oorschot. *An Administrator's Guide to Internet Password Research*. LISA 2014, pp. 44–61.（本文所用的 $10^{6}$ 在线／$10^{14}$ 离线猜测阈值出处。）
9. C. Herley. *So Long, and No Thanks for the Externalities: The Rational Rejection of Security Advice by Users*. NSPW 2009, pp. 133–144. ACM. https://dl.acm.org/doi/10.1145/1719030.1719050
10. F. Stajano, M. Spencer, G. Jenkinson, Q. Stafford-Fraser. *Password-Manager Friendly (PMF): Semantic Annotations to Improve the Effectiveness of Password Managers*. 收录于 International Conference on Passwords, Springer, 2014, pp. 61–73.
11. Y.-Y. Choong. *A Cognitive-Behavioral Framework of User Password Management Lifecycle*. 收录于 Human Aspects of Information Security, Privacy, and Trust (HAS), Springer, 2014, pp. 127–137.（本文通篇所用三阶段生命周期模型的出处。）
12. S. Oesch, S. Ruoti. *Research artifacts for "That Was Then, This Is Now"*. https://userlab.utk.edu/papers/oesch2020that

**第 4–5 节引用的后续工作：**

- [a] S. Oesch, A. Gautam, S. Ruoti. *The Emperor's New Autofill Framework: A Security Analysis of Autofill on iOS and Android*. ACSAC 2021, pp. 996–1010. https://arxiv.org/abs/2104.10017 · https://doi.org/10.1145/3485832.3485884
- [b] S. Oesch, S. Ruoti, J. Simmons, A. Gautam. *"It Basically Started Using Me:" An Observational Study of Password Manager Usage*. CHI 2022. https://doi.org/10.1145/3491102.3517534
- [c] A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. USENIX Security 2024, pp. 4337–4354. https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega

## 事实核对清单

| 本章中的说法 | 原文出处 |
|---|---|
| 作者 Sean Oesch 与 Scott Ruoti，田纳西大学（Knoxville） | 标题页（p. 2165–2166） |
| USENIX Security 2020, pp. 2165–2182, 第 29 届, 2020 年 8 月 12–14 日 | 论文集封面页 |
| 13 款管理器；2 款桌面客户端、5 款扩展、6 款浏览器内置 | Abstract；§1 Introduction（"thirteen popular password managers"；"five browser extensions and six password managers integrated directly into the browser… two desktop clients"）；Table 1 |
| 各类别下的管理器清单 | Table 1 行：KeePassX, KeePassXC / 1Password X, Bitwarden, Dashlane, LastPass, RoboForm / Chrome, Edge, Firefox, IE, Opera, Safari |
| 第 2 节引用的版本号 | §3.1–3.3（v2.0.3、v2.3.4、v1.14.1、v1.38.0、v6.1908.3、v4.24.0、v8.5.6.6、v71.0、v42.17134、v64.0、v11.523、v58.0.3135、v12.0） |
| 1.47 亿个口令；$10 \times 5 \times 3 - 3$；每种配置 100 万 | §4.2，"This resulted in a corpus of 147 million passwords (10 × 5 × 3 − 3)" |
| 字符类别 `l`/`ld`/`ls`/`sd`/`all`；长度 8、12、20 | §4.2 |
| 三阶段生命周期（生成、存储、自动填充） | §1；§7 Discussion；参考文献 [8]（Choong） |
| 首次对口令生成做评估 | §1 贡献 2；§2.2 "our work is the first to study the strength of password generators" |
| 四种检测：香农熵、$\chi^{2}$、zxcvbn、LSTM RNN | §4.2；Appendix A Listing 1 |
| Bonferroni 校正 ×147，上限 1.00 | §4.2 脚注 5 |
| 较短口令易受在线（<10 字符）与离线（<18 字符）攻击 | §1 Introduction（"shorter than 10 characters and 18 characters, respectively"） |
| 阈值 $10^{6}$ 在线、$10^{14}$ 离线 | §4.2，引参考文献 [16] |
| 弱生成口令出现频率不到 1/200 | §4.3 "Random but Weak Passwords"（"less than 1 in 200"） |
| 长度 10 抗在线／长度 18 抗离线 | §4.3；§7.1（"10 characters for online resistance, 18 for offline resistance"） |
| 非随机分布归因于「每个类别至少一个字符」；方程 (1)(2) | §4.3 "Randomness"；Equations (1) 与 (2) |
| RoboForm（`l`）无法解释；取模运算偏差假设 | §4.3 "Randomness" |
| Bitwarden `sd`、Dashlane `l` 由集合大小相等／不等解释 | §4.3 "Randomness"；Table 3 |
| 符号集规模：KeePassXC 除空格外的全部标准 ASCII + 扩展 ASCII；KeePassX 与 Dashlane 除空格外的标准 ASCII；1Password X 19 个；其余 ≤ 8 | §4.1；Table 2 |
| 最近设置成为新默认（Dashlane 例外；KeePassX 至重启） | §4.1 |
| Safari 口令形如 "xxx-xxx-xxx-xxx"；手工生成 100 个未发现明显问题 | §3.3；§4.2 |
| 7 款完整支持、2 款部分支持的生成器 | §4 首句 |
| 手动检查本地数据库；云端不可用 | §5 首段 |
| App 与扩展类保管库用 AES-256 | §5.1 |
| KDF 轮数：KeePassX/KeePassXC AES-KDF 100,000；1Password X PBKDF2 100,000；Bitwarden 100,001；LastPass 100,100；RoboForm PBKDF2 4,096；Dashlane Argon2D 3 轮 | §5.1；Table 6 |
| Firefox：3DES、一轮 SHA-1、无主口令策略、"by far the weakest" | §5.1 |
| Chrome/Opera 在 Linux 无 keyring 时退回明文；Windows 用 CryptProtectData；macOS 由钥匙串派生密钥而口令存本地 | §5.1；Table 6 脚注 1 |
| KeePassX/KeePassXC 加密全部元数据 | §5.2 |
| 1Password X 明文存储扩展设置（含自动锁定、生成默认值、通知） | §5.2 |
| Dashlane 加密 URL 但不加密网站图标；所有扩展都泄露登录邮箱 | §5.2 |
| Chrome/Opera（Win/macOS）与 Firefox：URL 明文；仅 Firefox 加密用户名；暴露创建时间、最后使用、填充次数 | §5.2 |
| 仅 KeePassX 无浏览器自动填充；Bitwarden 自动填充为实验性 | §6 首段；脚注 6 |
| 仅 1Password X 与 Safari 总是要求交互 | §6.1 |
| HTTPS 有效证书：KeePassXC/Bitwarden/RoboForm 默认要求交互但可关闭；Dashlane/LastPass/Firefox 默认直接填充（有选项）；Chrome/Edge/IE/Opera 总是填充 | §6.1 |
| 无效证书：Edge 与 IE 总是要求交互；Chrome 与 Opera 禁用自动填充 | §6.1 |
| HTTP：KeePassXC/Bitwarden/RoboForm 仍要求交互；Dashlane/LastPass/Edge/IE 改为总是要求交互 | §6.1 |
| 同源 iframe：KeePassXC、1Password X、Dashlane、LastPass、Bitwarden、RoboForm 与所有浏览器都会填充 | §6.2 |
| 跨域：KeePassXC 允许且可关闭交互要求；1Password X/LastPass/RoboForm 不填充；Bitwarden/Dashlane 用最顶层窗口的域；Chrome/Edge/IE/Opera/Safari 要求交互（仍可点击劫持）；Firefox 默认不要求 → 可被收割 | §6.2 |
| `type="text"` 只有 Dashlane 会填充 | §6.4 |
| 极简非登录表单被 Bitwarden、Chrome、Edge、Firefox、IE、Opera 填充 | §6.4 |
| 表单不一致时的行为（URL、协议、action、method、字段改名） | §6.3 |
| nonce 式自动填充无人支持；浏览器禁止扩展修改请求体 | §6.5；§7.2 |
| 无人遵守 `autocomplete="off"`；W3C 规范存疑；Mozilla 说明 | §6.5；参考文献 [32]、[23] |
| 1Password X/Bitwarden/Dashlane/LastPass 使用 CSRF token；RoboForm 的 CSRF 改了会话超时 | §6.6 |
| CSP：1Password X/Dashlane 无问题；Bitwarden 两处；LastPass `unsafe-inline`；RoboForm 无 CSP；XSS 尝试未成功 | §6.6 |
| bookmarklet：仅 LastPass 保留，且沙箱正确 | §6.6 |
| 向维护者披露；RoboForm 已采纳若干建议 | §Disclosure |
| §3.4 更新：KeePassXC 改默认 Argon2D；LastPass/RoboForm 生成界面变更（去掉位数选项；RoboForm 默认长度 16）；Firefox → Lockbox；Edge → Chromium | §3.4 |
| 实践建议：避开 Firefox 内置管理器；优先 App/扩展类；Safari 例外 | §7 Discussion |
| 研究制品 URL | §Research Artifacts |

## 存疑／未获取清单

- **云端保管库加密未经验证。** 论文自己说明云端数据库 "are not available to us for direct evaluation"；§5 只涉及本地保管库。因此本章关于加密的描述只是复述论文自身的推断——综合维护者声明、客户端选项与密文格式——并非独立的密码学审计。这一局限同样适用于本章。
- **`100,000` 这一数字按印刷原样处理。** Table 6 把 Bitwarden 列为 `100,001` 轮、LastPass 列为 `100,100` 轮，而正文将其概括为「约 10 万轮」；本章精确数字从表、概述从正文。
- **语料算式为引用而非推导。** 论文给出 $10 \times 5 \times 3 - 3 = 147$ 百万，但未逐一列举被排除的 3 种配置。本章照录该数字而不再重构排除项，只注明论文明确说明的那一条（1Password X 无法生成只有符号和数字的口令）。
- **RoboForm 的偏差是假设。** 论文明确说 "it is not entirely clear what causes this issue"，把取模运算作为假设提出；本章按假设标注。
- **缺少长度 20 的神经网络结果。** 论文说明分析器在长度 20 上无论何种设置都会因内存溢出崩溃，故相关论断依赖另外三种检测手段。本章第 2、4 节已说明。
- **版本号属于研究期间（2019 年）。** 其中若干在写作时已变（§3.4），此后全部又已推进；本章据此标注，而不主张其当前行为。
- **页码。** 任务说明给出 pp. 2165–2182，与 PDF 印刷页码一致；官方页码范围以 USENIX 论文集索引为准。

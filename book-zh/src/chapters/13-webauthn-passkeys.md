# WebAuthn 与 Passkeys

<div class="source-card">
<p><strong>规范：</strong> W3C. <em>Web Authentication: An API for accessing Public Key Credentials, Level 3</em>（Web 认证：访问公钥凭据的 API，第 3 级）. Candidate Recommendation Snapshot, 2026-05-26. <a href="https://www.w3.org/TR/webauthn-3/">w3.org/TR/webauthn-3</a>. FIDO Alliance. <em>FIDO2 / CTAP 规范</em>. <a href="https://fidoalliance.org/specifications/">fidoalliance.org/specifications</a>.</p>
<p><strong>研究：</strong> Alaa Daffalla, Arkaprabha Bhattacharya, Jacob Wilder, Rahul Chatterjee, Nicola Dell, Rosanna Bellini, Thomas Ristenpart. <em>A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal Threat Models</em>（滥用性分析框架：人际威胁模型下的 Passkeys）. USENIX Security 2025. <a href="https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf">PDF</a>. · Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. <em>"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments</em>. ACM CCS 2023. <a href="https://arxiv.org/abs/2306.09708">arXiv:2306.09708</a>.</p>
<p><strong>一句话：</strong> TOTP 之所以不抗钓鱼，是因为验证码是一个可转交的共享秘密；WebAuthn 把它换成一对绑定来源、服务器永不持有的密钥——代价是同步与恢复带来的新信任假设。</p>
</div>

<div class="hook">
<p>屏幕上那串六位数字正在倒数，只剩 20 秒。你面前的页面和银行官网长得一模一样，连图标和"欢迎回来"都没差分毫。你把验证码填了进去——半秒之后，钓鱼网站已经把它实时转交给了真正的银行，而这个码此刻仍在有效期里，你刚刚替攻击者完成了登录。服务器这头看上去毫无异常：正确的码，在正确的时间，抵达了。</p>
</div>

## 1. 背景与动机

本书前面每一章，其实都在变着法地回答同一个问题：**秘密放在哪里。** Lamport（1981）把秘密彻底从服务器上拿走了；S/KEY、HOTP、TOTP 为了可用性又把共享秘密放回了双方；T/Key（第 5 章）再次把服务器的秘密拿掉；密码管理器则以"零知识"之名重演了同一场争论（第 8–12 章）。本章收束全书，看的是行业最终收敛出的答案：**不要再共享秘密，而是给每个账户一对密钥。**

TOTP（RFC 6238）**不抗钓鱼**，这一点是设计层面的性质，不是实现 bug。六位验证码是共享密钥 $K$ 与当前时间步的函数：$\mathrm{TOTP}(K,T)=\mathrm{HOTP}(K,T)$。它不携带"谁来出示"或"在哪里输入"的任何信息。RFC 6238 的安全考量自己承认：验证系统收到 OTP 时，"并不知道客户端生成 OTP 的确切时间戳"——它只把验证码与*此刻*愿意接受的时间步比对，而不是核对来源。于是，一个夹在用户与真实服务器之间的钓鱼站点，只要在约 30–60 秒的接受窗口内把验证码实时转交过去，就能以受害者身份登录。这就是经典实时中间人（MITM），也正是"TOTP 不抗钓鱼"的准确含义。

第 7 章还讲过第二种、与时钟相关的失效——前向重放——其根因相同：TOTP 验证码是一枚在时间窗内有效的**持有者令牌（bearer token）**，谁来出示都一样。钓鱼与前向重放的区别只在攻击者如何拿到验证码；两者都会被同一个改动同时消除：**让凭据无法在它被创建的环境之外使用。**

WebAuthn 规范做的正是这件事。W3C 的 Web 认证 API（第 3 级）与 FIDO2/CTAP 认证器协议把凭据**绑定到来源（origin）**——也就是站点的身份——于是为 `example.com` 创建的凭据，在攻击者的仿冒域名上根本不可用。它的动机不是把第六位数字做得更强，而是把共享秘密整个移出画面：被偷走或被转交的验证码，没有秘密可偷。

## 2. 核心机制

**参与者。** WebAuthn 定义了三个角色。**依赖方（Relying Party, RP）**是"其 Web 应用使用 Web 认证 API 来注册和认证用户的实体"，它包含服务端组件（规范 §4）。**客户端（client）**是浏览器或平台，负责中介。**认证器（authenticator）**是生成并保存凭据的硬件或软件组件——可以是平台认证器（如内置指纹传感器），也可以是漫游认证器（如 USB 安全密钥）。

**凭据（credential）。** 公钥凭据是一对公钥—私钥。它**对每个 RP、每个用户账户、每个认证器都唯一**。私钥永不离开认证器，RP 只拿到公钥。

**两次仪式。** 规范描述了"两次不同但相关的仪式"：**注册（Registration）**，"在认证器上创建一个公钥凭据，并把它限定给某个依赖方与当前用户的账户"；以及**认证（Authentication）**，"依赖方收到一份认证断言，证明注册该公钥凭据的用户的在场与同意"。两者都是**挑战—响应**：RP 给出一个新鲜的挑战（challenge），认证器用私钥对它签名，RP 用保存的公钥验签。由于每次仪式的挑战都是新的，被截获的断言无法重放。

**RP ID 与来源绑定。** 这是协议的安全核心。规范把依赖方标识符（RP ID）定义为"标识某次注册或认证仪式所代表的 WebAuthn 依赖方的合法域名字符串"，并直说："一个公钥凭据只能用于与它注册时相同的实体（由 RP ID 标识）进行认证。"客户端把 RP 的来源与 RP ID 交给认证器，而"认证器确保由某依赖方创建的凭据只能用于同一 RP ID 请求的操作"（§4）。规范刻意把来源与 RP ID 分开，好让一个 RP 可以横跨多个来源，同时在别的来源面前拒绝签名。

**用户验证（User Verification, UV）。** 规范把 UV 定义为"认证器在本地授权调用 authenticatorMakeCredential 与 authenticatorGetAssertion 操作的技术过程"，可通过"触控加 PIN、密码输入或生物识别"等手势完成，"其意图是区分不同个体"（§4）。UV 由 RP 在每次仪式中配置。

**服务器不留共享秘密。** 由于服务器只保存公钥，服务器被攻破也拿不到任何可用于认证的东西。这正是 T/Key 用哈希链追求的性质（第 5 章）；WebAuthn 用公钥密码学达到它，并直接回应了第 6、7 章反复出现的失效——那个一旦外泄就是*全体用户*第二因素的共享秘密。

**Passkeys 与同步。** 规范用一个**永久属性**区分两种凭据模式：**可备份资格（backup eligibility）**。可备份的凭据是**多设备凭据（multi-device credential）**，不可备份的是**单设备凭据（single-device credential）**（§4）。认证器数据中有两个标志：**BE** 标志"当且仅当凭据是多设备凭据时置位"，且注册后不得改变；**BS** 标志"当且仅当凭据是多设备凭据且当前已被备份时置位"（§6.1）。允许的组合是 `00`（单设备）、`10`（多设备、未备份）、`11`（多设备、已备份），`01` 不允许。多设备凭据就是业界所说的 **passkey（同步型 passkey，synced passkeys）**，规范面向消费者的用例把它宣传为"抗钓鱼登录（phishing-resistant sign in）"（§1.2.1）；而面向企业员工的用例则把漫游密钥与平台认证器组合为单设备凭据（§1.2.2）。

同步化，正是本书主线问题回归的地方。同步型 passkey 的私钥会备份到云端的 **passkey 管理服务（passkey management service, PMS）**——iCloud 钥匙串、Google 密码管理器等——于是秘密不再只存在于设备上。*仪式*的抗钓鱼性质依然成立，但云端从此多了一份秘密副本。

## 3. 安全分析、攻击与实证评估

**来源绑定买到了什么、没买到什么。** 面对*远程*钓鱼，RP ID 绑定是决定性的：凭据根本不会为攻击者的来源签名，随机挑战又让断言无法重放。但这一保证只覆盖**签名仪式**。一旦私钥可以被*复制*，持有副本的攻击者就能从任何地方合法登录，来源校验分辨不出差别。

**人际威胁模型下的滥用。** Daffalla 等（USENIX Security 2025）提出一套六阶段**滥用性分析（abusability analysis）**框架，并将其应用于 passkeys：考察 **19 个支持 passkey 的服务与 4 个 passkey 提供方**，提出 **7 个滥用向量**，并在 iOS、macOS、Windows、Android 上执行 stepthrough（论文整体报告 **87 次 stepthrough**，例如"对抗性生物识别"向量 30 次、克隆 21 次）。这些滥用不是远程钓鱼，而是本地接触——威胁模型是能周期性接触到解锁设备的亲密伴侣、家人或同事：

- **对抗性生物识别。** 由于 FIDO2"不支持把 passkey 操作绑定到特定用户生物特征"，攻击者用已知 PIN 解锁设备后可以添加*自己*的指纹；此后设备上任意一个已注册生物特征都能解锁任意 passkey。添加生物特征在 macOS、Android 或 Windows 10 上都不触发通知，而清除它往往要删掉*全部*生物特征。
- **Passkey 克隆。** 凭据的可移植性让一次性接触设备的攻击者可以复制 passkey——通过 AirDrop 导出、Apple 的共享密码群组，或登录受害者的 iCloud 并保留本地钥匙串副本。论文报告，在 CVS、Porkbun、TikTok 上由此获得的持续远程访问"无法被察觉"，且"找不出任何撤销途径"。
- **对抗性 passkey 与拒绝服务。** 远程添加自己的 passkey（在 10 个服务上成功）、撤销受害者的 passkey（11 个服务）、或本地删除 passkey，都能劫持或剥夺访问。撤销常常**不会**终止活动会话：在 Adobe、GitHub、LinkedIn、Samsung 上，撤销后由 passkey 认证的会话在 60 分钟后仍然有效。
- **煤气灯操纵（gaslighting）。** 服务的账户安全界面可被伪造——改 User-Agent 字符串、挂 VPN、修改 passkey 标签——于是施害者可以误导受害者对"谁有访问权"的判断。

论文自身的表述很克制：其中不少是"不成熟"部署中的实现 bug（PayPal、Porkbun 向未认证调用方泄露凭据 ID——规范本身的 §14.6.3（非规范性）就把这种模式列为隐私考量；过期凭据；不可撤销的 passkey），但有些是**passkey 特有**、并非继承自密码的——尤其是一个账户可以并存多个活动 passkey，以及界面把 passkey 与密码混为一谈。关键的是，作者直接点出了安全权衡：由于设备被攻破即意味着设备上*所有*凭据被攻破，"凭据安全因此被降格为设备安全"。

**恢复是最薄弱一环。** Amft 等（ACM CCS 2023）研究 MFA 恢复，正因为一个强第二因素，其强度取决于重置它的那条路径。他们评估了 **1,303 个支持 MFA 的网站的文档化恢复流程**，随后对其中 **71 个网站**实际建号并测试恢复：**37 个（52.11%）重获访问、30 个（42.25%）永久失去、4 个（5.63%）无回复**。安全结论很直白：在他们成功恢复的账户中，**26 个（70.27%）**只需"能访问账户绑定的邮箱地址"即可完成恢复。很多情况下，实际部署的流程与其帮助页面不符，照官方文档操作的用户常被误导。一个抗钓鱼的第一因素，若身后是可由邮箱重置的恢复路径，就并不抗钓鱼。

**采用率与部署成本。** 另有两项研究界定了迁移的边界。Lassak 等（USENIX Security 2024）访谈了 **28 位** CISO、认证负责人与 FIDO2 专家；报告的最大部署障碍是**回退与恢复选项**、剧变带来的复杂性与摩擦、技术问题（浏览器支持、撤销）、监管要求与安全文化——而专家与部署者对"哪些障碍最紧迫"的看法并不一致。Bhardwaj 与 Sastry 的大规模爬取（*State of Passkey Authentication in the Wild*，arXiv 预印本 2602.15135，2026）用**43 条启发式规则**的浏览器爬虫扫描 Tranco 前 **100,000** 个域名，发现采用率"与站点流行度强相关"：前 100 名站点中 **20%** 支持 passkey，而 50K–100K 名仅为 **6.9%**，相差近 3 倍；许多部署是委托给外部身份提供方而非原生 WebAuthn；人工维护的目录只覆盖了不到 4% 的实际部署。作为量级参照，Daffalla 等提到 Google 报告截至 2024 年 5 月已有超过 4 亿账户启用了 passkey。

**同步密钥的泄露检测。** Islam 等（USENIX Security 2025）把同步的风险讲透：同步型 passkey 会把 FIDO2 私钥备份到 PMS 的云存储，因此"攻击者可通过攻破 PMS 的云存储窃取用户 passkey，进而接管其 Web 账户"。他们的 CASPER 框架——首个 passkey 泄露检测框架——把真实 passkey 藏在彼此不可区分的**诱饵 passkey**之间，使被盗凭据一旦被使用就有较大概率在 RP 处触发检测，而又不重新引入恢复摩擦。学界给出的首选补救是*检测*而非*预防*，这本身就是要点：秘密一旦上了云，就不再只属于设备。

## 4. 适用场景与迁移边界

第 7 章结尾建议，对高价值账户应"远离共享秘密与可钓鱼的验证码，转向 WebAuthn/passkeys 这类抗钓鱼认证器"。本章把这条建议说精确——也说明它在哪些边界之外不再成立。

**WebAuthn 明显更优的场景。** 凡主要威胁是*远程*凭据窃取——钓鱼、撞库、泄露秘密的服务器被攻破——的账户，收益都是决定性的：没有可转交的共享秘密，RP ID 拒绝攻击者的来源，数据库泄露只吐出公钥。对照用漫游硬件密钥的员工场景，单设备（`BE=0`）模型还提供了不可导出的凭据。

**TOTP 仍然够用或不可替代的场景。** 当以下条件成立时，TOTP 仍然合适：拿不到（或不被允许使用）硬件令牌与带生物识别的平台认证器；第二因素必须**离线**工作，不依赖浏览器或在线 RP 挑战；需要**跨设备**登录而**不信任任何云同步**；或遗留/隔离网络系统根本无法实现 WebAuthn 的 RP。TOTP 的代价——共享秘密——是真实存在的，但它是一个已知、可审计的风险，且 RFC 6238 的核心安全分析至今未被推翻（第 3–4 章）。在这些场景下，WebAuthn 并非即插即用的替代品，RFC 6238 这条技术线仍是对的工具。

**"抗钓鱼"成立的前提。** 这个词只有在若干条件同时满足时才成立：

1. **仪式由可信客户端强制执行。** 来源绑定实现在浏览器/操作系统中；规范指出，模仿该 API 的平台"可以定义不同的规则"来把调用方绑定到 RP ID。信任客户端本身就是假设的一部分。
2. **凭据在实践中不可复制。** 对同步型（多设备，`BE=1`）passkey，抗钓鱼保护的是*签名仪式*而非密钥：被克隆或从云端泄露的密钥会正常认证（Daffalla；Islam）。`BE`/`BS` 标志让 RP 能看到这一状态，但前提是它愿意据此行动。
3. **用户验证验证的是对的人。** FIDO2 不把 passkey 绑定到特定生物特征，在共享或可被物理接触的设备上，UV 确认的是"某个"已注册用户具有访问权，未必是账户主人。
4. **恢复不比认证更弱。** 如果一封邮箱（Amft）或一个撤销后仍存活的会话（Daffalla）就能恢复访问，前门的抗钓鱼便失去意义。

**对比总结。** 下表沿用全书一直使用的维度（威胁模型、可用性、部署成本）对比两个族系；每一格都可追溯到上述来源。

| 维度 | TOTP（RFC 6238） | WebAuthn / Passkeys（W3C L3；FIDO2） |
|---|---|---|
| 凭据 | 手机与服务器共享的对称密钥 $K$ | 公钥—私钥对，对每个 RP、账户、认证器唯一（§4） |
| 钓鱼（远程） | 不抗：验证码是可转交的持有者令牌，验证器无法判断生成时间与地点（RFC 6238 §5.2） | 在仪式层面抗：凭据只为注册它的 RP ID 签名（§4） |
| 服务器被攻破 | 泄露全体用户的共享秘密 | 服务器只存公钥，被攻破不产生可用凭据 |
| 时钟 / 重放 | 依赖本地时钟；同一时间步在窗口内可复用；存在前向重放（第 7 章） | 每次仪式由 RP 的新挑战唯一化；不依赖共享时钟 |
| 恢复 | 备份码 / 支持渠道；实践中常可经邮箱绕过（Amft：70.27%） | 云同步 / 多把 passkey；出现克隆与不可撤销的凭据（Daffalla） |
| 可用性 | 手动输入 6 位码；可离线 | 生物识别/PIN 手势；无需输码；跨设备需同步 |
| 部署成本 | 低：双方各存一个共享密钥 | 高：需浏览器、操作系统与服务三方支持；回退/恢复缺口是首要障碍（Lassak） |

<div class="aside">
<p><span class="aside-label">题外话 · 规范其实并不管它叫"passkey"</span></p>
<p>"passkey"是每个消费级登录页上的说法，但在 WebAuthn 规范自己的术语表里，它只是一条同义词：技术名称是<em>客户端侧可发现凭据（client-side discoverable credential）</em>，"passkey"与它并列（§4）。同一条目把更早的"驻留凭据（resident credential）"与"驻留密钥（resident key）"标为 [DEPRECATED]。规范的一条注释解释了旧词为何阴魂不散：<code>ResidentKey</code> 与 <code>residentKey</code> 已经写进 API 的字典成员名和操作参数里，为了向后兼容不能改名。</p>
<p class="aside-source">出处：W3C《Web Authentication: An API for accessing Public Key Credentials, Level 3》§4 术语（"Client-side discoverable Public Key Credential Source" 条目；[DEPRECATED] 标记与关于 <code>residentKey</code> 向后兼容的注释均出自该条目）。</p>
</div>

## 5. 相关文献与领域现状

- **RFC 6238，TOTP**（[rfc-editor.org/rfc/rfc6238](https://www.rfc-editor.org/rfc/rfc6238)）与 **RFC 4226，HOTP**（[rfc-editor.org/rfc/rfc4226](https://www.rfc-editor.org/rfc/rfc4226)）——本章要离开的共享秘密方案；"验证器不知道验证码何时生成"的表述出自 RFC 6238 §5.2。
- **FIDO Alliance，FIDO2 / CTAP 规范**（[fidoalliance.org/specifications](https://fidoalliance.org/specifications/)）——WebAuthn 在认证器一侧的配套规范（详见规范中关于认证器操作的相关章节）。
- **W3C，Web 认证第 3 级**（[w3.org/TR/webauthn-3](https://www.w3.org/TR/webauthn-3/)）——RP ID、来源绑定、用户验证与 BE/BS 备份标志的规范性来源。
- **Kogan, Manohar, Boneh，T/Key，CCS 2017**（[arXiv:1708.08424](https://arxiv.org/abs/1708.08424)，第 5 章）——更早一次"既要基于时间、又要服务器不留秘密"的尝试；WebAuthn 用公钥密码学回应了同一设计压力。
- **Daffalla 等，USENIX Security 2025**（[PDF](https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf)）——首个面向人际威胁模型的 passkey 分析：7 个滥用向量、19 个服务。
- **Amft 等，CCS 2023**（[arXiv:2306.09708](https://arxiv.org/abs/2306.09708)）——MFA 故事里的恢复侧，说明强第一因素会如何被下游环节消解。
- **Lassak, Pan, Ur, Golla，USENIX Security 2024**——*Why Aren't We Using Passkeys? Obstacles Companies Face Deploying FIDO2 Passwordless Authentication*；28 次访谈揭示部署阻力。
- **Islam, Arora, Chatterjee, Wang，USENIX Security 2025**（[PDF](https://www.usenix.org/system/files/usenixsecurity25-islam.pdf)）——CASPER，检测从云存储泄露的同步 passkey 之滥用。

文献界并不把 WebAuthn 当作已完成的万灵药。研究者把*密码学方向*（公钥、来源绑定）视为已定且正确的，而把*部署问题*——同步、恢复、撤销，以及消费级产品忽视的人际威胁模型——视为开放、且正在被主动攻击的前沿。这与全书反复得出的教训一致：最薄弱的一环很少是算法，而是它周围的生态。

## 6. 小结与回响

- TOTP 不抗钓鱼，是因为它的验证码是可转交的持有者令牌：它不表达来源，也不表达出示者，实时转交在 RFC 6238 的接受窗口（§5.2）内即可奏效。
- WebAuthn 用"每个账户一对密钥"替换共享秘密，并以 **RP ID** 限定依赖方：凭据只能用于它注册时的那个实体，且"认证器确保"这一限定（§4）。
- 注册创建凭据，认证对新鲜**挑战**返回断言；**用户验证**是本地手势，"其意图是区分不同个体"（§4）。
- 服务器只保存公钥，于是服务器被攻破不再是全体用户的第二因素泄露——这正是 T/Key 以另一种途径追求的目标（第 5 章）。
- **Passkey** 按可备份资格划分：**多设备**（同步，`BE=1`）或**单设备**（`BE=0`），**BS** 标志报告当前备份状态（允许 `00`/`10`/`11`，不允许 `01`；§6.1）。
- 同步把秘密搬到了云端的 passkey 管理服务，重新提出了本书的核心问题：PMS 被攻破会泄露可用密钥（Islam 等），而克隆在现实中会击穿抗钓鱼（Daffalla 等）。
- 恢复常常是最薄弱一环：凭借账户邮箱，Amft 等在其成功恢复的账户里有 26 个（70.27%）由此进入，且实际流程常与帮助页矛盾。
- 迁移是一条谱带而非一个开关：面对远程钓鱼与数据泄露，WebAuthn 是决定性的；而对离线、无硬件、或拒绝同步的跨设备使用，TOTP 依旧适用。"抗钓鱼"只有在客户端可信、密钥不可复制、UV 验证到对的人、且恢复不比认证更弱时才成立。

**回响。** 全书在第 1 章开场，是 Lamport 1981 的那一手：把秘密从服务器上拿走，因为一个保存着"能让你登录的东西"的服务器，迟早会被逼着交出来。四十多年后，WebAuthn 用公钥密码学而非哈希链走到了同一个终点——依赖方只持有公钥，一次数据泄露交不出任何可用于登录的东西；这也正是第 5 章 T/Key 想要抵达的地方：一个带来源、却在服务器上不留可用秘密的因素。但秘密并没有消失，它只是被搬了家。同步型 passkey 的私钥被交给了设备，又经平台的云端交给了 passkey 管理服务；于是全书开篇那个问题——**秘密放在哪里**——被向前推移了，而没有消失。第 5 章还能问"当一个服务器什么都不留时，它是否仍可被信任"；收尾这一章则显示，当我们把秘密交给设备与平台时会发生什么。所以这是全书最后一个手势，而非最后一句话：共享秘密退场了，但它所追问的问题仍然敞开——只是这一次，它指向了恢复、撤销与云。

## 参考文献

1. W3C. *Web Authentication: An API for accessing Public Key Credentials, Level 3.* Candidate Recommendation Snapshot, 2026-05-26. https://www.w3.org/TR/webauthn-3/
2. FIDO Alliance. *FIDO2 / CTAP specifications.* https://fidoalliance.org/specifications/
3. Alaa Daffalla, Arkaprabha Bhattacharya, Jacob Wilder, Rahul Chatterjee, Nicola Dell, Rosanna Bellini, Thomas Ristenpart. *A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal Threat Models.* USENIX Security 2025. https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf
4. Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments.* ACM CCS 2023. https://arxiv.org/abs/2306.09708
5. Leona Lassak, Elleen Pan, Blase Ur, Maximilian Golla. *Why Aren't We Using Passkeys? Obstacles Companies Face Deploying FIDO2 Passwordless Authentication.* USENIX Security 2024, pp. 7231–7248. https://www.usenix.org/system/files/usenixsecurity24-lassak.pdf
6. Mazharul Islam, Sunpreet S. Arora, Rahul Chatterjee, Ke Coby Wang. *Detecting Compromise of Passkey Storage on the Cloud.* USENIX Security 2025. https://www.usenix.org/system/files/usenixsecurity25-islam.pdf
7. Prince Bhardwaj, Nishanth Sastry. *State of Passkey Authentication in the Wild: A Census of the Top 100K sites.* arXiv preprint 2602.15135, 2026. https://arxiv.org/abs/2602.15135
8. David M'Raihi, Salah Machani, Mingliang Pei, Johan Rydell. *TOTP: Time-Based One-Time Password Algorithm.* RFC 6238, IETF, 2011. https://www.rfc-editor.org/rfc/rfc6238
9. David M'Raihi, Mihir Bellare, Frank Hoornaert, David Naccache, Ohad Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm.* RFC 4226, IETF, 2005. https://www.rfc-editor.org/rfc/rfc4226
10. Neil Haller. *The S/KEY One-Time Password System.* RFC 1760, IETF, 1995. https://www.rfc-editor.org/rfc/rfc1760
11. Dmitry Kogan, Nathan Manohar, Dan Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains.* ACM CCS 2017, pp. 983–999. https://arxiv.org/abs/1708.08424
12. Sanam Ghorbani Lyastani, Michael Schilling, Michaela Neumayr, Michael Backes, Sven Bugiel. *Is FIDO2 the Kingslayer of User Authentication? A Comparative Usability Study of FIDO2 Passwordless Authentication.* IEEE S&P 2020. https://doi.org/10.1109/SP40000.2020.00048

## 事实核对清单

正文中每个关键数字与结论，及其在原文中的出处。

| 正文中的说法 | 出处 |
|---|---|
| TOTP 验证码为 $\mathrm{TOTP}(K,T)=\mathrm{HOTP}(K,T)$ | RFC 6238 §4 |
| "验证系统并不知道客户端生成 OTP 的确切时间戳"；最多接受一个时间步的网络延迟 | RFC 6238 §5.2（原文引用） |
| 依赖方定义（"其 Web 应用使用 Web 认证 API……的实体"） | WebAuthn L3 §4 |
| "两次不同但相关的仪式"（注册 / 认证） | WebAuthn L3 §4 |
| RP ID 为"标识 WebAuthn 依赖方的合法域名字符串"；凭据只能用于注册时的同一实体；认证器确保同一 RP ID 才可用 | WebAuthn L3 §4（原文引用） |
| 凭据对每个 RP、账户、认证器唯一 | Daffalla 等 §2（FIDO2 背景） |
| 用户验证定义与"其意图是区分不同个体" | WebAuthn L3 §4（原文引用） |
| 可备份资格 → 多设备 / 单设备凭据；多设备即"同步型 passkey" | WebAuthn L3 §4；§1.2.1（术语） |
| BE 标志当且仅当多设备时置位且注册后不得改变；BS 标志当且仅当多设备且当前已备份；组合 `00`/`10`/`11` 允许、`01` 不允许 | WebAuthn L3 §6.1（标志表与文字） |
| 消费者（多设备）用例表述为"抗钓鱼登录"；企业员工用例使用单设备凭据 | WebAuthn L3 §1.2.1、§1.2.2 |
| 模仿该 API 的平台"可以定义不同的规则"来绑定调用方与 RP ID | WebAuthn L3 §4 |
| 非空 `allowCredentials` 导致凭据 ID 泄露（非规范性） | WebAuthn L3 §14.6.3 |
| Daffalla 方法：六阶段滥用性框架；19 个服务、4 个提供方；7 个滥用向量；87 次 stepthrough；生物识别向量 30 次、克隆 21 次 | Daffalla 等 摘要与 §3–§5 |
| FIDO2"不支持把 passkey 操作绑定到特定用户生物特征"；用受害者 PIN 添加对抗性生物特征；macOS/Android/Windows 10 无通知 | Daffalla 等 §5.1 |
| 克隆路径：AirDrop、共享密码群组、iCloud 登录；在 CVS、Porkbun、TikTok 上不可察觉、不可撤销的持续访问 | Daffalla 等 §5.2（及摘要） |
| 对抗性 passkey 在 10 个服务上成功；撤销在 11 个服务上成功；撤销后会话在 Adobe、GitHub、LinkedIn、Samsung 上 60 分钟后仍有效 | Daffalla 等 §5.3、§5.5；Figure 7 |
| "凭据安全因此被降格为设备安全" | Daffalla 等 §2（原文引用） |
| PayPal 与 Porkbun 向未认证调用方泄露凭据 ID | Daffalla 等 §4(c) |
| Amft 方法：1,303 个网站文档调研；实测 71 个；恢复 37（52.11%）、失去 30（42.25%）、无回复 4（5.63%）；26（70.27%）凭邮箱即可恢复 | Amft 等 摘要、§3.2.2、§3.2.3 |
| Lassak：28 次半结构化访谈；最大障碍为回退/恢复、摩擦、技术、监管、安全文化 | Lassak 等 摘要与 §1 |
| Bhardwaj & Sastry：43 条启发式规则、1,500 个站点调优；Tranco 前 100K；前 100 名 20% vs 50K–100K 6.9%；采用率与流行度相关；人工目录覆盖 <4% | Bhardwaj & Sastry 摘要与 §5.3 |
| Islam：同步型 passkey 将私钥备份至 PMS 云；攻破可致账户接管；CASPER 为首个泄露检测框架 | Islam 等 摘要与 §1 |
| Google 报告截至 2024 年 5 月有 4 亿账户启用了 passkey | Daffalla 等 §1（引 Google） |

## 存疑/未获取清单

- **未直接阅读 FIDO2/CTAP 规范正文。** 仅查阅了 FIDO Alliance 规范页；因此正文只笼统提到 CTAP，并引用该页面而不引用任何条款号。
- **WebAuthn 版本。** 所读规范为 2026-05-26 的第 3 级 Candidate Recommendation Snapshot；所引章节号来自该快照，后续草案可能变化。
- **Daffalla 的 stepthrough 计数。** 论文在 Stage-5 小结中称"共执行 87 次 stepthrough"，而其各向量的分项数字（30 + 21 + 21 + 12 + 12）并不显然等于 87。正文按原文分别报告，未在此解决该差异。
- **Bhardwaj & Sastry 为预印本**（arXiv 2602.15135，2026），数字未经同行评审，正文已作标注。
- **发表出处不一致。** handoff 与项目材料清单把 Amft 等 *"We've Disabled MFA for You"* 列为 USENIX Security 2023；而该论文自身的 ACM reference format 将其置于 **ACM CCS '23**（2023 年 11 月，哥本哈根）。正文依原文写作（CCS 2023），材料清单应据此更正。
- **CASPER 的 29 天检测阈值等内部细节**未细读；正文只使用该论文的框架与动机。

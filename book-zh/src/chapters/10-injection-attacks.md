# 注入攻击与跨条目信息泄露（2024）

<div class="source-card">
<p><strong>本章文献：</strong> Andrés Fábrega, Armin Namavari, Rachit Agarwal, Ben Nassi, Thomas Ristenpart. <em>Exploiting Leakage in Password Managers via Injection Attacks</em>. 第 33 届 USENIX Security Symposium, Philadelphia, PA, USA, 2024, pp. 4337–4354. <a href="https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf">原文 PDF（开放获取）</a>。预印本：<a href="https://arxiv.org/pdf/2408.07054">arXiv:2408.07054</a>。</p>
<p><strong>一句话：</strong> 攻击者只要控制自己的、未修改的密码管理器客户端，就能通过「共享」把选定的载荷注入受害者保险库，再从客户端导出的密文长度与明文元数据里还原出受害者的口令、URL、用户名与附件——这个威胁模型既不需要攻破客户端，也不需要破解密码学，某些情形下甚至只需一个被动的网络窃听者。</p>
</div>

<div class="hook">
想象密码管理器里最无害的一个动作：另一个用户把一条登录信息共享给你，你点了「接受」。没有任何不该解密的东西被解密，没有任何密钥被攻破，你机器上的软件分毫未动、完全按设计运行。然而就从这一条共享条目出发——连同客户端在它之上运行的那些再普通不过的功能——攻击者竟能反过来读出你的口令、URL、用户名，甚至附件。这就是注入攻击的全部：没有破解任何密文，没有植入任何流氓程序，只有一项合法功能，以及对它生成的密文长度的一次仔细观察。
</div>

## 1. 背景与动机

端到端加密（end-to-end encryption, E2EE）密码管理器承诺：只要主口令不泄露，保险库就是保密的——离开设备的一切都经过加密，因此无论服务端被入侵还是网络被窃听，都不应泄露任何信息。此前的学术攻击大致落在两个威胁模型里：一类攻击者控制某个**客户端侧资源**（恶意网页、流氓应用、恶意 Wi-Fi、XSS 载荷），即 Li 等（第 8 章）与 Oesch、Ruoti（第 9 章）所分析的那类；另一类攻击者拿到了加密保险库的副本，试图离线爆破主口令。主流产品正是针对这两类威胁设计的。

Fábrega 等提出的问题，这两个模型都没有覆盖，而在密码管理器从「单用户、非交互工具」变成「多人共享」之后变得紧迫：**如果保险库里可以存放别人共享的条目，一个恶意的共享者能做什么？** 他们把这个威胁模型称为**注入攻击（injection attacks）**，其假设是攻击者

1. **只控制自己的客户端**——软件未经修改、遵守标准协议——借助产品自带的凭据/文件夹共享功能，把选定的载荷放进受害者的保险库；
2. **被动观察离开受害者设备的某类数据**——例如加密的保险库备份、应用服务器收到的网络请求，或者 HTTPS 流量本身。

关键在于：攻击者既不篡改受害者或自己的客户端，也不植入后门代码，更不攻破任何密码学原语。原文明确写道：「注入攻击假设使用强密码学原语，因此底层、密码分析的漏洞不在其范围内；相反，密文长度和明文元数据才是我们攻击的基础。」载荷是作为合法数据、经由 E2EE 协议本身进入受害者保险库的；泄露发生在客户端自身逻辑把这份数据与受害者数据合并处理之处。

论文的立意是：这不是一张漏洞清单，而是**功能日益丰富的客户端的设计问题**。当密码管理器不断加入共享、健康报告、图标抓取、存储优化等功能时，每个新功能都可能制造一处**跨用户交互**——客户端对某个用户数据的处理方式依赖于另一个用户的数据。在 E2EE 系统里，任何这种交互只要体现在导出的密文中，就是一条信道。作者认为这件事重要的理由，是所需攻击者很弱、所需观测能力也很现实：服务端被入侵本就常见，而他们援引的 IBM 2022 报告显示，发现一次入侵平均需要 212 天。

## 2. 核心内容：模型、信道与三类攻击

### 2.1 威胁模型

保险库记为 $V = \{e_1, \dots, e_m\}$，每个条目 $e$ 含用户名 $e_{user}$、URL $e_{url}$、口令 $e_{pw}$ 和附件列表 $e_{attach}$ 等字段。**注入**经由共享发生：攻击者向受害者共享一个条目（或文件夹）；管理器要求受害者只接受**第一次**共享，但——这是最关键的细节——此后对已共享条目或文件夹的所有更新都**无需再批准**、自动传播。因此受害者只需接受一次，之后攻击者即可随意改写载荷。

**观测**有两种强度：

- **窃听者（eavesdropper）**：能持续访问 E2EE 数据本身及其明文元数据（被攻破的服务端或云厂商、内部人员、被攻破的 TLS 层）；
- 更弱的**网络窃听者（network adversary）**：只能看到承载这些数据的 HTTPS 数据包。

注入与观测交替、自适应进行。攻击按噪声容忍度区分：**安静设备（quiet device）**设定假设攻击期间受害者不向保险库新增内容；**噪声设备（noisy device）**设定允许用户无关活动。由于共享条目更新会自动传播，许多攻击只需数分钟即可完成。

### 2.2 研究语料

作者从一份流行度报告与若干在线投票出发，先泛查 16 款候选产品，再按两条入选标准筛选：必须支持跨用户凭据共享；且必须为共享凭据提供**密码学**访问控制。所有浏览器集成型管理器因不提供共享而被排除。**Bitwarden** 被第二条标准排除：它支持共享，但组织内所有「collection」共用同一密钥，任何成员本就能解密全部组织凭据——Bitwarden 确认这是「在授权层、而非加密层」的隔离。最终十款及测试版本为：LastPass（v4.123）、Dashlane（v6.2346）、Zoho Vault（v3.8）、1Password（v2.25.0）、Enpass（v6.11.0）、Roboform（v9.6.2）、Keeper（v116.18.0）、NordPass（v5.16）、Proton Pass（v1.17.4）、KeePassXC（v2.7.6），合计占密码管理器用户 30% 以上。其中只有 KeePassXC 与 Enpass 不自建同步服务器，而是设计上把加密数据库文件放在第三方云盘里。

这项研究以闭源商业服务为主。明确开源的是 KeePassXC，而本文的**文件格式类攻击**针对的是开源 KeePass 系所引入的 **KDBX 4 格式**，因此会波及其所有读取该格式的应用。论文本身并未逐一标注十款产品的许可证；它只在「信任客户端软件」这一点上援引公开可审计性与二进制透明服务。

### 2.3 攻击一：把保险库健康指标当作预言机

许多管理器会统计保险库「健康度」，其中最典型的是重复口令数量 $dup(V) = \tfrac{1}{2}\sum_{e^{\prime},e^{\prime\prime}\in V}(e^{\prime}_{pw} = e^{\prime\prime}_{pw})$，并把它记录到设备之外。漏洞在于：这个计数是在**个人条目与共享条目上一起**计算的。于是攻击者注入一条口令等于候选值 $p$ 的条目，观察 $dup(V)$ 是否增大，就能判断 $p$ 是否已在受害者保险库中。使一款产品易受攻击有三个前提：提供重复口令统计；该统计跨所有条目计算；该统计被记到设备之外。满足条件的有七款：LastPass、Dashlane、Zoho Vault、Enpass、Roboform、Keeper、NordPass。

通用攻击是一次字典攻击，有两种注入策略。若产品支持**共享文件夹**，攻击者做二分查找：把候选集切成两半，注入其中一半，观察 $dup(V)$，递归进入发生变化的那一半。代价为 $\lceil \log_2 n \rceil$ 次注入及同样次数的观测。若只能共享**单个条目**，则用顺序策略，每次注入 $t$ 条，代价为 $n/t + \lceil \log_2 t \rceil$。由于 $dup(V)$ 是确定性的，两种策略都不会产生假阳性：存在即找出，不存在即确认不存在。Zoho Vault 泄露得更多：其日志是逐条目的 JSON 数组，带一个布尔字段 `reused`，因此一次批量注入即可判断哪些候选命中；又因为字符串 `false` 比 `true` 多一个字符，HTTPS 载荷长度会随之差 1 字节，于是连**网络窃听者**都能实施攻击。

### 2.4 攻击二：只抓取一次的 URL 图标

客户端通常会在每条凭据旁显示网站图标，用 URL 向服务器请求得到。图标**每个 URL 只抓取一次**：同网站的后继条目复用客户端已缓存的图片。因此攻击者注入一条 URL 为 $w$ 的条目，观察客户端是否发起抓取，就能判断 $w$ 是否已在保险库中。受影响的有六款——Dashlane、1Password、Enpass、Roboform、NordPass、Proton Pass——且因为只看请求**是否存在**、不看其内容，只需**网络窃听者**。二分与顺序两种策略同样适用。

### 2.5 攻击三：KDBX 4 的省存储机制

持有整库加密副本的攻击者，可以利用压缩与去重：这两种机制会消除明文中的冗余，从而使密文大小依赖于明文内容。KDBX 4 把保险库序列化为：先是不加密的外层头 $H_{out}$，随后是内层头与 XML 载荷，二者先经 gzip 压缩、再加密。每个附件只存一份，即便它同时出现在共享与个人条目中（**去重**）；压缩则匹配重复子串（**压缩**）。十款产品中只有 KeePassXC 使用这两种机制。

- **去重 → 附件。** 加入一个已在附件库 $A$ 中的附件不会使文件变大。朴素探测无假阳性但代价线性；二分变体需修正噪声，因为 gzip 会引入噪声，于是攻击者按本地测得的可压缩性对各半集「惩罚」，当 $B_2/(B_1 + z^{\prime}) < B_3/(B_1 + z^{\prime\prime})$ 时递归进入 $W^{\prime}$。
- **压缩 → URL 与用户名。** 口令被排除，因为它位于第二层加密之下，匹配无法被压缩。为控制哈夫曼编码的影响，攻击者对每个候选注入两遍——原串，以及由相同字符打乱得到的置换串——并选出使 $\lvert n^{\prime\prime}_i - n^{\prime}_i \rvert / \lvert w_i \rvert$ 最大的候选。确认步骤则把找到的串加上 32 KB 填充（即 zlib 搜索窗口长度）重新注入，检查文件大小不再增长。

## 3. 安全分析与实验评估

评估把针对真实客户端的小规模概念验证与大规模仿真结合——这是评价已部署系统的常见做法：真实客户端用于确认正确性，本地重实现用于在大量独立试验中估计成功率，同时不过载厂商服务器。

**攻击一**：作者对 LastPass、Dashlane、Zoho Vault 部署概念验证，用两个账号/两台设备，并在受害者机上用代理捕获全部出站请求（模拟恶意服务器）。每次都成功还原目标；由于正确性不依赖字典规模，故意只用小规模负载。LastPass 在每次导入共享凭据后即上报 $dup(V)$，且支持共享文件夹（用二分）；Dashlane 与 Zoho 每天上报一次，且 Dashlane 无共享文件夹（用顺序）。值得注意的是，除「已登录」外无需受害者任何交互：后台脚本会同步并触发请求，因此攻击可在受害者做别的事时静默进行——属于**噪声设备**攻击。

**攻击二**：概念验证针对 Dashlane，URL 取自 Majestic 热门网站榜单，每次都成功。

**攻击三**：专用攻击只命中 KeePassXC，采用同样的双环境设置。去重：朴素攻击每次都能还原目标；二分搜索的成功率（原文图 4）随候选数、数据集与文件大小而下降——在 Enron 语料上，$|W| = 32, 128, 512$ 时分别为 92%、81%、52%；对等长随机文件，各尺寸均为 100%。压缩：用户名与 URL 能以较高概率还原（原文图 5）；对真实数据，随字典从 4 增至 100 条，网站还原率为 99%/97%/92%/89%/84%。两类攻击都「可通过重复放大」，并带有剔除假阳性的确认步骤。

<div class="aside">
<p><span class="aside-label">题外话 · 一个布尔值抵得上一整本字典</span></p>
<p>Zoho Vault 的保险库健康日志不是一个总数，而是一个 JSON 对象数组——每个条目一个对象，各带一个 <code>reused</code> 字段，取值就是 <code>true</code> 或 <code>false</code>。这样的粒度让攻击者可以完全跳过二分查找：一次性注入全部候选口令，再读一遍日志，哪个注入条目与真实口令撞上，标志位已经替他说了。泄露还不止于此——因为字符串 <code>false</code> 比 <code>true</code> 多一个字符，标志位从前者翻到后者会让加密的 HTTPS 载荷缩短至少一个字节，于是连一个什么都不解密的被动网络窃听者，也能盯住这 1 个字节。</p>
<p class="aside-source">出处：Fábrega 等, USENIX Security 2024——逐条目 <code>reused</code> 字段见 §5.1「Vulnerable Password Managers」及其「Extension to a network adversary」段；Zoho Vault 具体的字节级论证见 Zoho Vault 案例研究（附录 B）。</p>
</div>

## 4. 适用场景与迁移边界

这三类攻击不是十二个孤立的 bug，而是三种**设计模式**，论文正以此为核心论点：「我们的攻击向量是密码管理器的特性，而非仅存在于我们案例产品中的 bug。」抽象地看：

1. **导出同时依赖个人数据与外部数据的应用状态**（指标、健康报告、聚合统计）。指导原则：**按系统的信任假设切分数据**。
2. **以状态相关的方式抓取外部内容**（缓存图标，或任何资源，使「是否发起抓取」暴露先前状态）。指导原则：**客户端—服务器通信应尽量只针对具体资源、且不依赖此前操作的结果**。
3. **对来自不同信任上下文的数据施加相似性敏感函数——压缩、去重。** 指导原则：此处安全与存储效率存在张力，必须有意权衡。

这种迁移并非假设。在姊妹论文《Injection Attacks Against End-to-End Encrypted Applications》（IEEE S&P 2024）中，同一团队把模型用到了 E2EE 消息：WhatsApp 的附件去重、序列化数据库的 zlib 压缩、以及 FTS4 搜索索引，都会向「注入消息并观察加密**备份**」的攻击者泄露消息或附件信息（前提是攻击者控制了目标用户的 Google/Apple 账号）；Signal 的备份序列化则泄露联系人与会话数量。缓解论文（第 5 节）进一步把该模式推广到任何「滤波函数」为**相似性敏感**的功能，并指出同一形态也出现在多租户搜索服务中。

**边界条件是明确的。** 受害者必须先接受一个共享项，因此该模型假定存在某种初始信任，或攻击者能成功诱导受害者接受共享请求——接受一次共享本不该泄露保险库，但它是前提。偏离 E2EE 协议的客户端不在范围内（作者认为它不会带来额外攻击）。攻击一与攻击三需要特定的设备外产物（指标日志、整库加密文件），攻击三还需安静设备；只有攻击一（对 Zoho Vault）与攻击二能降级为纯被动的网络窃听者。关于结论最强的一句表述是：厂商部署的缓解都是**针对具体漏洞的补丁**；论文呼吁发展通用的检测与缓解技术，以及对这一威胁模型更深入的理论认识。

**与第 8、9 章的本质区别。** Li 等（2014）与 Oesch、Ruoti（2020）所分析的浏览器管理器攻击，假设攻击者攻破的是受害者**自身客户端环境**的某个部分——恶意登录页、XSS 或书签小工具、流氓扩展、恶意应用、剪贴板，或把口令交给错误源站的自动填充策略——泄露的直接是口令本身或一个代码执行原语。Fábrega 等则让受害者的客户端保持**诚实且未经修改**：攻击者是另一个用户，注入内容是普通的共享数据，泄露的不是口令本身，而是**关于口令的信息**（它是否存在，或其字节内容），从密文长度与明文元数据中推断而来。由此有两点后果。其一，攻击面由合法功能创造，因此修复了经典的浏览器类 bug 之后它依然存在。其二，防御不是修补某个解析器，而是客户端在加密前如何切分与处理数据的性质——正是 2025 年分区工作所形式化的那个性质。

## 5. 相关文献与领域现状

- **Z. Li, W. He, D. Akhawe, D. Song，《The Emperor's New Password Manager》，USENIX Security 2014**（[usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei)）——第 8 章；首个系统性的网页版密码管理器分析，采用客户端侧资源威胁模型。Fábrega 等回答的正是「当管理器变成多用户后」，那项分析所引出的新问题。
- **S. Oesch, S. Ruoti，《That Was Then, This Is Now》，USENIX Security 2020**（[usenix.org](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch)）——第 9 章；对浏览器管理器的生成、存储与自动填充的再评估，仍属单受害者、客户端侧模型。
- **A. Fábrega, C. Ortega Pérez, A. Namavari, B. Nassi, R. Agarwal, T. Ristenpart，《Injection Attacks Against End-to-End Encrypted Applications》，IEEE S&P 2024**（[arXiv:2411.09228](https://arxiv.org/abs/2411.09228)，[NSF PAR](https://par.nsf.gov/servlets/purl/10522889)）——向 E2EE 消息（WhatsApp、Signal）的推广；说明该模式并非密码管理器独有。
- **A. Fábrega, S. Breckenridge, A. Namavari, T. Ristenpart，《Mitigating Injection Attacks against E2EE Applications via View-Based Partitioning》，USENIX Security 2025**（[PDF](https://www.usenix.org/system/files/usenixsecurity25-fabrega-partitioning.pdf)）——给出注入攻击的首个形式化安全模型，以及一个把应用状态按**对抗性视图**切分的框架（例如每个会话、每个共享文件夹各自一条压缩流），使相似性敏感函数永不跨越信任上下文。它证明了「视图非干扰」蕴含「长度无关性」（鲁棒性归约到加密方案的安全性），并测出代价：含 200 个口令的 KeePassXC 备份由 29.7 KB 增至 36.5 KB，而「关闭压缩」的方案需要 530 KB——约好 14 倍。
- **C. Garman, M. Green, G. Kaptchuk, I. Miers, M. Rushanan，《Dancing on the Lip of the Volcano: Chosen Ciphertext Attacks on Apple iMessage》，USENIX Security 2016**（[usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/garman)）——被两篇 Fábrega 论文引为「在已部署 E2EE 协议中利用加密前压缩」的典型；注入这条脉络把该洞见从选择密文推广到经由普通功能注入的选择明文。
- **M. Backendal, M. Haller, K. G. Paterson，《MEGA: Malleable Encryption Goes Awry》，IEEE S&P 2023**（[eprint 2022/959](https://eprint.iacr.org/2022/959)）——「服务器作恶、客户端密码学处理有缺陷」这一类的标杆；与 Fábrega 等形成对照，后者根本不需要服务端密码学被攻破。

作者的定位是**系统化、改良派而非革命派**：他们不主张 E2EE 原语被攻破，并明确承认借鉴了可搜索加密中的二分技术（以及既有的压缩攻击）的先前工作。他们的主张是：**应用层**——搭建在 E2EE 之上的功能——是一片研究不足的攻击面，最好通过可复用的模板来研究，而领域需要的是通用检测与缓解工具，而非逐个 bug 的补丁。2025 年的分区论文可视作作者自己的回应：同一团队从「发现模式」走向「形式化并封堵模式」。

## 6. 小结与回响

- **威胁模型。** 只控制自己未修改客户端的攻击者，经凭据/文件夹共享注入载荷，再被动观察加密状态。受害者接受一次共享；此后更新自动传播、无需批准。既无客户端篡改，也无密码分析。
- **两类观测者。** 窃听者能看到 E2EE 数据与明文元数据；更弱的网络窃听者只能看到 HTTPS 数据包。多数攻击需要其一；少数只需网络视角。
- **研究语料。** 十款支持共享的管理器，占用户 30% 以上。Bitwarden 因各 collection 共用一密钥（「授权层而非加密层」）被排除；浏览器集成型因不支持共享被排除。
- **攻击一（健康指标）。** 七款产品在个人与共享条目上一起统计重复口令数。二分查找代价 $\lceil \log_2 n \rceil$ 次注入；顺序变体为 $n/t + \lceil \log_2 t \rceil$。Zoho Vault 逐条目泄露布尔值，1 字节的载荷长度差甚至使网络窃听者可行。
- **攻击二（URL 图标）。** 六款产品每个网站图标只抓一次，因此「未发起抓取」即暴露该 URL 已在保险库中；网络窃听者即可。
- **攻击三（KDBX 4）。** 去重泄露附件内容；压缩泄露 URL 与用户名（口令受第二层加密保护）。十款中仅 KeePassXC 符合条件，但弱点在共享的文件格式本身。成功率较高且可通过重复放大，并有确认步骤剔除假阳性。
- **缓解与披露。** 从在指标中分离个人/共享数据（LastPass 4.129.0），到 KDBX 中按共享文件夹分别去重、并加入随机 64–512 字节填充（KeePassXC 2.7），再到让图标信道可关闭、并把其端点做噪（Dashlane 6.2415）。详见原文第 8 节。
- **结论与推广。** 这些是三种可复用的设计模式，而非十二个 bug；同样的模式在 E2EE 消息（S&P 2024）与多租户搜索中复现，而作者 2025 年的框架展示了如何以可控且经度量的代价，按对抗性视图切分状态来封堵它们。
- **与第 8、9 章的对照。** Li（2014）与 Oesch（2020）攻击的是受害者自身的客户端环境；Fábrega（2024）让客户端保持诚实，由另一个**用户**通过普通功能来攻击它，泄露的不是口令本身，而是关于它的信息——来自密文长度与元数据。

**回响。** 第 9 章以一个结构性判断收尾：密码管理器仍然持有一种*共享秘密*，并且仍会把它交进网页，所以它的脆弱性是结构性的、而非偶然的。本章把这个母题又推了一转，并且发现失效甚至不需要「交出去」这一步：只要多出另一个*用户*就够了。第 8、9 章攻击的是受害者**自身客户端环境**的某个部分，泄露的是口令本身；Fábrega 等则让客户端保持诚实、注入普通的共享数据，从密文长度与元数据里读出**关于口令的信息**——于是攻击面由合法功能打开、而非由 bug 打开，修好了 2014 年那批浏览器漏洞也关不上它。这一推广论文中有明确陈述，也在其姊妹论文里得到演示：同一套模板适用于任何「用户之间彼此共享数据」的多租户 E2EE 应用，包括 E2EE 消息——WhatsApp 的附件去重、zlib 压缩与 FTS4 搜索索引，以及 Signal 的备份序列化，都会经由加密备份泄露。向前埋下的钩子不是补丁，而是修复的**形态**：把状态切分，使相似性敏感函数永不跨越信任边界——这正是作者 2025 年的框架所形式化的东西。第 11、12 章接着追问相邻的问题：当**服务器**成为攻击者时，支撑这一切的密码学协议是否还成立。

## 参考文献

1. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. 第 33 届 USENIX Security Symposium, 2024, pp. 4337–4354. https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf
2. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*（预印本）. arXiv:2408.07054, 2024. https://arxiv.org/pdf/2408.07054
3. A. Fábrega, C. Ortega Pérez, A. Namavari, B. Nassi, R. Agarwal, T. Ristenpart. *Injection Attacks Against End-to-End Encrypted Applications*. IEEE S&P (Oakland), 2024, pp. 2648–2665. https://arxiv.org/abs/2411.09228
4. A. Fábrega, S. Breckenridge, A. Namavari, T. Ristenpart. *Mitigating Injection Attacks against E2EE Applications via View-Based Partitioning*. 第 34 届 USENIX Security Symposium, 2025. https://www.usenix.org/system/files/usenixsecurity25-fabrega-partitioning.pdf
5. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*. USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei
6. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. USENIX Security 2020, pp. 2165–2182. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
7. C. Garman, M. Green, G. Kaptchuk, I. Miers, M. Rushanan. *Dancing on the Lip of the Volcano: Chosen Ciphertext Attacks on Apple iMessage*. USENIX Security 2016, pp. 271–288. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/garman
8. M. Backendal, M. Haller, K. G. Paterson. *MEGA: Malleable Encryption Goes Awry*. IEEE S&P, 2023. https://eprint.iacr.org/2022/959
9. D. Cash, P. Grubbs, J. Perry, T. Ristenpart. *Leakage-Abuse Attacks Against Searchable Encryption*. ACM CCS, 2015. https://eprint.iacr.org/2016/718
10. KeePassXC. *KDBX 4 数据库文件格式 / KeePassXC 项目*. https://github.com/keepassxreboot/keepassxc

## 事实核对清单

以下页码均指 USENIX Security 2024 正式版（pp. 4337–4354）。

| 正文事实 | 出处（原文位置） |
|---|---|
| 威胁模型：攻击者只控制自己未修改的客户端；经共享注入；观察受保护状态；客户端篡改与后门客户端不在范围内 | §4.1「Threat Model」「Injections」「Out-of-scope attacks」 |
| 「假设强密码学原语……密文长度与明文元数据是攻击基础」 | §4.1「Injections」/「Observations」段 |
| 受害者须接受一个共享项，此后更新无需批准；文件夹同理 | §3「Credential sharing」；§4.1 |
| 两类观测者：窃听者（E2EE 数据+明文元数据）与网络窃听者（HTTPS 包）；迭代交替 | §4.1「Observations」；图 2 |
| 安静/噪声设备设定 | §4.1 噪声段；§7（攻击三为安静）；§5、§7.1 |
| 服务端入侵常见；识别平均需 212 天（IBM 2022） | §4.1 |
| 语料：筛 16 款；两条入选标准；排除浏览器管理器与 Bitwarden；Bitwarden 引语「authorization level, not at the encryption level」 | §4.2 + 脚注 3 |
| 十款及版本（v4.123 … v2.7.6）；占用户 30% 以上 | §4.2 |
| KeePassXC/Enpass 不自建同步服务器；KDBX 由开源 KeePass 引入 | §3「Database file formats」；§4.2；§7 |
| 三类攻击概览（#1 指标、#2 图标、#3 省存储） | §4.3「Overview of Attacks」 |
| $dup(V)$ 公式及其预言机用法 | §5「Attack description」 |
| 攻击一受影响七款：LastPass, Dashlane, Zoho Vault, Enpass, Roboform, Keeper, NordPass | §5.1；图 1（L, D, Z, E, R, K, N） |
| 二分代价 $\lceil \log_2 n \rceil$；顺序代价 $n/t + \lceil \log_2 t \rceil$；均无假阳性 | §5 |
| 概念验证产品 LastPass/Dashlane/Zoho；LastPass 每次导入即上报且支持文件夹；Dashlane/Zoho 每日一次；Dashlane 无文件夹 | §5.1 |
| 攻击一无需受害者交互（登录态后台脚本），属噪声设备 | §5.1 |
| Zoho Vault 逐条目 `reused` 布尔；`false` 比 `true` 多一字符，给出 1 字节网络窃听信号 | §5.1「Extension to a network adversary」 |
| 攻击二：图标每 URL 只抓一次；六款（Dashlane, 1Password, Enpass, Roboform, NordPass, Proton Pass）；仅需网络窃听者；概念验证 Dashlane；Majestic 榜单 | §6、§6.1 |
| 攻击三：KDBX 4 = $H_{out}$ + Enc(gzip($H_{in}\,\Vert\,I$))；附件去重；口令在第二层加密下；十款中仅 KeePassXC；属格式层，故波及他应用 | §7「Background on KDBX 4」 |
| 去重二分噪声修正 $B_2/(B_1+z^{\prime}) < B_3/(B_1+z^{\prime\prime})$；朴素攻击无假阳性；等长随机文件 100% | §7.1 |
| 图 4 数字（Enron 92/81/52；10 KB 74/53/29） | §7.1, 图 4 |
| 压缩「双重注入」（原串+打乱）策略；判据 $\max \lvert n^{\prime\prime}_i - n^{\prime}_i \rvert / \lvert w_i \rvert$；以 32 KB 填充（zlib 窗口）确认 | §7.2 |
| 图 5 网站还原率：$\lvert W \rvert = 4, 10, 25, 50, 100$ 时为 99/97/92/89/84；以 $t=10$ 取平均 | §7.2, 图 5 |
| 缓解：分离指标、加密指标、图标用 PIR、每次重取图标、禁用省存储（体积增 5–6 倍）、按信任子集隔离、第二层加密、填充/噪声 | §8 |
| 披露：LastPass 4.129.0（先处理文件夹）、Zoho 计划 4.0、Dashlane 限流+图标开关 6.2415、KeePassXC 2.7（按共享文件夹去重+随机 64–512 字节填充） | §8「Responsible disclosure」 |
| 三条指导原则（信任切分；资源特定通信；安全/性能张力） | §9「Conclusion」 |
| S&P 2024 推广：WhatsApp（去重、zlib、FTS4）、Signal（序列化）；备份需控制 Google/Apple 账号 | S&P 2024 摘要；§1；图 1 |
| 分区 2025：view-based partitioning、形式化模型、视图非干扰⇒长度无关性、29.7 KB → 36.5 KB 对比禁用压缩 530 KB（约 14×） | USENIX'25 摘要；§4；§6.3（定理 2、推论 1）；§7.2（图 8） |

## 存疑 / 未获取清单

- **版本间的计数差异。** arXiv v1 预印本（2408.07054）对攻击一写「十款中有五款易受攻击」，其图 1 只列 `L, D, Z, K, N`；但其 §5.1 正文列的却是与正式版相同的七款。USENIX 2024 正式版内部自洽，为**七款**（`L, D, Z, E, R, K, N`），本章以正式版为准。之所以标注：handoff 与只读 arXiv 版的读者否则会看到「五款」。
- **开源/闭源明细。** 论文未逐一给出十款产品的许可证。本章只写明 KeePassXC 是明确的开源案例、且 KDBX 类攻击针对共享格式，未对其余九款断言许可证。
- **附录 A/B/C**（测试方法与逐产品案例研究）在所用 USENIX PDF 中只读到 Case Study #3 片段，其余扩展附录未逐页读完；正文无任何结论依赖其超出上表所引的内容。
- **「27 个攻击」式标题数字**出现在周边文献（如 2026 年零知识工作）的通俗报道中，本章**未采用**；只报告论文自身的「三类攻击 / 四种通用攻击」表述（§4.3「three main classes」；§9「four general attacks」）。
- **S&P 2024 姊妹论文的正式页码**（pp. 2648–2665，DOI 10.1109/SP58266.2024.00174）取自第三方索引；实际阅读的是 arXiv 预印本。

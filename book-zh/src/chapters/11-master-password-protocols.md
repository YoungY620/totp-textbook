# 主密码保护协议的形式化分析（IEEE S&P 2025）

<div class="source-card">
<p><strong>本章文献：</strong> Yihe Duan, Ding Wang, Yanduo Fu. <em>Security Analysis of Master-Password-Protected Password Management Protocols</em>. 2025 IEEE Symposium on Security and Privacy (S&P), pp. 701–719. <a href="https://doi.org/10.1109/SP61157.2025.00050">DOI</a> · <a href="https://github.com/DanielNKU/pm-analysis">论文公开数据仓库</a></p>
<p><strong>一句话：</strong> 首次在主密码「客户端—服务器」这条协议链路上做通用可组合（UC）形式化分析：43 款密码管理器中有 38 款至少扛不住一类离线猜测攻击，而只有额外引入第二个高熵秘密的设计才能抵挡全部四类攻击。</p>
</div>

<div class="hook">想象厂商的推销词：保险库用 AES-256 封存，连厂商自己也看不到你的主密码，服务器上只有一堆密文。现在把同一台服务器请进「对话」——登录握手、盐值、客户端被告知用多少轮迭代——再问一遍：这只保险库还封得住吗？密码算法可以毫无破绽，而把主密码送进去的那套协议，却可能悄悄把攻陷服务器所需的一切一并奉上。</div>

## 1. 背景与动机

密码管理器（password manager, PM）被 NIST、NCSC 等标准机构与安全专家推荐，理由很实在：它能替用户生成又长又不重复的口令，从根上避免复用和弱口令。论文一上来就给出量级：今天用户平均要维护 80–168 个账号，于是人们用「`123456`、`password` 这类高概率口令」「复用」「把个人信息塞进口令」来应付——而这些正是让猜测攻击真正致命的成因。

把所有凭据集中到一个保险库里，保险库本身就成了靶子。论文引 LastPass 为例：三年内被入侵三次；虽然 LastPass 声称 2022 年那次事件中没有口令泄露，但该事件后来被与约 440 万美元加密货币失窃联系起来。用户的不信任有两层：既怕被拖库，也不完全愿意把所有凭据托付给第三方。厂商对这两点的回应是同一个词——「零知识加密（zero-knowledge encryption）」。

论文研究的对象，是作者命名为**主密码保护的口令管理协议**（Master-Password-Protected Password Management, M3PM）的东西：客户端用主密码完成认证、并从 PM 服务器取回凭据，同时保险库对服务器保持不可见的那套密码学协议。作者的核心提醒是：**保险库被安全加密，并不等于 M3PM 协议安全。**认证机制与加密机制的不当组合会引入漏洞（原文 §5.4），而且 M3PM 协议的安全目标本就不止「保险库保密」这一条（§4.1）。

此前的工作恰恰都绕过了「协议」。Gasti 与 Rasmussen（ESORICS 2012）首次严格分析了 PM 保险库的**存储格式**，给出不可区分性与不可延展性两个安全定义；Oesch 与 Ruoti（USENIX Security 2020）在三年后复现了这项研究。两者评估的是格式而非协议，因此都漏掉了客户端认证，也漏掉了对主密码的离线猜测。Zhao 等与 Zhao、Yue 指出，主密码与认证符之间关系的不安全存储会让保险库可被离线破解；Bojinov 等（Kamouflage）与 Chatterjee 等（NoCrack）提出「蜜罐保险库（honey vault）」来抵抗保险库泄露后的猜测。气质最接近的是 Davies 等（CRYPTO 2023）：他们在 UC 框架下把 WhatsApp 备份协议形式化为「口令保护密钥检索」（PPKR）功能——但那是一个口令取回**一个**密钥，而一把主密码要同时保护**许多**口令。

全文由三个研究问题组织：RQ1，现有 PM 实际采用了哪些 M3PM 协议；RQ2，什么样的 M3PM 协议才算安全；RQ3，按这些定义衡量，现有 PM 是否安全。

## 2. 核心内容

**两类 PM。**「检索型（retrieval）」PM（如 1Password、LastPass）把凭据存在加密保险库里，用时取回；「生成型（generative）」PM（如 LessPass、SPHINX）则用主密码加上站点元数据，通过 OPRF 或哈希这类确定性函数按需**推导**出每个口令。论文只覆盖「记口令、取口令」这一基本功能，不涉及共享与单点登录。

**样本选取。** 作者在九至十月间从应用商店、年度编辑推荐榜，以及 GitHub（星标超一千的开源项目）收集工业 PM 候选，从 DBLP 与 Google Scholar 收集学术方案，随后剔除装机量不足一万的、学术上不以安全为焦点的、以及无法搭建运行的。最终样本为 **43 款：36 款工业产品 + 7 个代表性学术方案**。

**采集方法**靠三条渠道互相印证：**文档**（白皮书、README、专家博客）给出初步画像；**数据日志**补充用 Burp Suite 抓取的 **TLS 之前**的网络流量，以及 Windows/Linux/macOS 桌面版本地存储文件；**应用代码**先静态定位算法（`AES256`、`PBKDF2`、`Argon2`、`master` 等关键词），再动态下断点，读出真实参数值（例如 KDF 迭代次数）。结果：36 款工业产品中有 24 款必须靠逆向工程；32 款提供了有价值的数据日志；只有 6 款主要靠文档分析；27 款信息足以深入分析。全部原始数据公开。**不依赖 TLS 是刻意的**：在这套威胁模型里服务器本身就可能作恶，客户端与恶意服务器之间的 TLS 毫无意义。

**协议的解剖结构。** 每个 M3PM 协议都分两个阶段。

*认证阶段*（显式认证，客户端→服务器）有五种形态：

1. 发送主密码的哈希，$h_{\mathsf{pw}} = H(\mathsf{mpw}, \mathsf{salt})$；
2. 发送受保护令牌，$\mathsf{eauth} = \mathrm{Enc}_{H(\mathsf{mpw})}(\mathsf{auth})$，同时给出明文 $\mathsf{auth}$；
3. 使用 SRP 一类的 PAKE，验证子为 $v = g^{H(\mathsf{mpw}, \mathsf{ID}_{C}, \mathsf{salt})}$；
4. 用主密码回应服务器挑战（mpw challenge）；
5. 用公钥回应挑战（pk challenge），服务器持有 $\mathsf{pk}_{C}$ 与加密私钥 $\mathsf{esk}$。

*口令处理阶段*则有以下四类：

- **主密码加密**（mpw encrypt）：$e\mathsf{Vault} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{Vault})$；
- **设备密钥加密**（device-key encrypt）：服务器收到 $e\mathsf{vk} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{vk})$ 与 $e\mathsf{Vault} = \mathrm{Enc}_{\mathsf{vk}}(\mathsf{Vault})$；
- **编码后加密**（encode-then-encrypt，蜜罐保险库思路）：$e\mathsf{Vault} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{encode}(X,\mathsf{Vault}))$；
- **生成型**：服务器只存参数。

**形式化模型。**安全目标在通用可组合（UC）框架下形式化，从而保证协议与其他协议并行执行时安全性依旧成立。威胁模型给攻击者的能力是：攻陷服务器并读取其全部存储数据；恶意服务器可以发送偏离协议的任意消息；信道假设有 TLS，但该假设被明确视为无关；客户端与服务器都不处于可信环境。

论文要求七条安全目标：**口令不可区分性**；**口令不可延展性**；**主密码不可知（oblivious of master password）**，即初始化与取回阶段都不向服务器泄露主密码信息；**生成口令伪随机**；**抗口令猜测**，在松弛版功能中以 `TESTMPW` 查询刻画；**抗部分口令泄露**，通过「一次只建模一条凭据」来实现，即一条口令泄露不应危及保险库里的其他口令；以及**认证**，即取回时所用的主密码必须与初始化时相同。

作者先给出基础理想功能 $F_{\mathsf{M3PM}}$，再逐步细化：$F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ 覆盖**显式**认证（认证失败时服务器回 `FAIL`），$F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$ 覆盖**隐式**认证（失败时服务器返回一个随机的、独立错误的口令，且服从 Zipf 分布，正如「蜜罐加密」的做法）。由于基础功能要求「抗猜测」，而仅以人为口令为唯一秘密的设计几乎无法达到，作者加入松弛版 $F^{r}_{\mathsf{M3PM}}$，内含 `TESTMPW` 查询且**不限制猜测次数**——这与 PPKR 只允许 10 次猜测形成对照。最后，$F^{\mathsf{ad}}_{\mathsf{M3PM}}$ 把所有 $\mathsf{mpw}$ 换成元组 $(\mathsf{mpw}, \mathsf{secretkey})$，用以刻画引入第二个秘密的设计。

模型只考虑两方：单方（纯本地）PM 通过给它指派一个同步服务器来分析，三方（带辅助设备）协议留作未来工作。

**实例：1Password。** 在论文的 Protocol OP 中，客户端输入主密码 $\mathsf{mpw} \in \mathrm{Zipf}(n)$、秘密密钥 $\mathsf{SecretK} \in \{0,1\}^{n}$、登录元数据与口令。注册阶段用**两个独立秘密**算出主认证符与主密钥：

$$x = H_{1}(\mathsf{mpw},\mathsf{ID}_{C}) \oplus H_{1}(\mathsf{SecretK},\mathsf{ID}_{C}), \qquad \mathsf{mk} = H_{2}(\mathsf{mpw},\mathsf{ID}_{C}) \oplus H_{2}(\mathsf{SecretK},\mathsf{ID}_{C}),$$

随后 $\mathsf{esk} = \mathrm{AE}.\mathrm{Enc}_{\mathsf{mk}}(\mathsf{sk})$、$e\mathsf{vk} = \mathrm{PKE}.\mathrm{Enc}_{\mathsf{sk}}(\mathsf{vk})$、$e\mathsf{Vault} = \mathrm{AE}.\mathrm{Enc}_{\mathsf{vk}}(\mathsf{Vault})$。服务器手上只有 $(e\mathsf{vk}, \mathsf{esk}, e\mathsf{Vault})$，以及通过口令认证功能提交的认证符 $x$。这种「两个独立导出值的异或」结构，正是它能扛住下文全部等级攻击者的原因。

## 3. 安全分析

离线猜测之所以成立，靠两个事实。其一是**低熵**：人为口令通常只有约 $2^{20}$–$2^{22}$ 比特熵，而 AES 密钥是 128/192/256 比特，于是猜中口令的概率不可忽略。其二是**可离线验证**：一旦拿到服务器数据库，攻击者就有了可以反复比对的参照值。

**GuessVerify。** 作者把这一判定形式化为 $\mathrm{GuessVerify}(m, X, \sigma)$：给定候选串 $m$、正确值的分布 $X$ 与攻击者的置信阈值 $\sigma$，当 $m$ 在 $X$ 下的概率超过 $\sigma$ 时返回 $\delta = 1$。例如取 $X$ 为 Zipf 分布、$\sigma = 0.1$，`123456abc` 会被判为「像口令」，而 `Q!='GhEuk76!WH+92Rf` 不会——尽管后者才是生成器产出的形态。

**被攻陷的服务器如何验证猜测。** 每种认证形态各有一个突破口：哈希主密码时服务器比对 $h_{\mathsf{pw}} \stackrel{?}{=} H(\mathsf{mpw}',\mathsf{salt})$；受保护令牌时用 $H(\mathsf{mpw}')$ 解密 $\mathsf{eauth}$ 再与明文令牌比对；SRP 时重算 $v' = g^{H(\mathsf{mpw}',\mathsf{ID}_{C},\mathsf{salt})}$；mpw challenge 时服务器本就握有主密码明文；pk challenge 时解密 $\mathsf{sk}'_{C} = \mathrm{Dec}_{H(\mathsf{mpw}')}(\mathsf{esk})$ 并用 $\mathsf{pk}_{C}$ 校验。进入处理阶段后，**主密码加密**与**设备密钥加密**都允许服务器导出 $\mathsf{mk}' = H(\mathsf{mpw}',\mathsf{salt})$ 解密，再依靠「认证加密解密失败（如 AES-GCM）」或对乱码明文跑 GuessVerify 来判定。

**蜜罐保险库并不能补上缺口。**编码后加密的前提是「用错密钥解出的结果仍服从 $X$ 分布」；那么攻击者只要把同一个 $X$ 喂给 GuessVerify，诱饵口令也会被「认作正确」。自适应分布即可击穿：`abc12345` 在 Zipf 下很合理，但对一个强制要求特殊字符的网站概率为零；更糟的是，攻击者哪怕知道保险库里**一条**真口令，就能高置信度地验证猜测。生成型方案在没有任何生成口令泄露时能抗离线猜测（无从验证），可一旦泄露一条，攻击者就能反推主密码并重新生成。

**四类攻击者。** Type-I 只能跟协议交互——所有 PM 都能抵抗，因为无物可验。Type-II 能攻陷服务器：1Password 与 Multipassword 靠第二个秘密抵抗，LessPass/Gokey/SPHINX/Amnesia 因为根本不存保险库内容而免疫，NoCrack 与 Kamouflage 靠编码后加密，BluePass 与 Tapas 靠另一台设备。Type-III 额外知道部分已泄露的口令，LessPass 与 Gokey 在此失守。Type-IV 集前两者之大成，此时只有第二个秘密（1Password、Multipassword）或第二台设备（BluePass、Tapas）能抵抗。

**关键数字。** 43 款 PM 中有 **38 款**至少扛不住一类离线猜测攻击；服务器一旦被攻陷，**34 款**无法满足 $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ 或 $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$；**35 款**使用 PBKDF2 或 Argon2 来拖慢猜测；只有 **1Password 与 Multipassword** 达到 $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$。作者对 **8 种不同的协议**给出了可证明分析；另有 6 款无法在模型中证明（Norton、Chrome、Passwarden 信息不足；Amnesia、BluePass、Tapas 是三方的）。整个分析耗时近四个月，每一次证明失败都被当作线索追下去。

**两个具体失效。** Delinea Web 客户端完全不做密码学运算，通信全程明文。Passbolt 存在一个预言机（oracle）攻击，被攻陷的服务器可以学到加密密钥（§5.4）。

**元数据隐私。** 43 款中有 **30 款**的元数据未加密，违反元数据的不可区分性与不可延展性要求。元数据被篡改比口令被篡改更危险：攻击者可以把 URL 改成钓鱼地址，而自动填充或「点击跳转」功能会乖乖把凭据送到那里。作者验证了 Zoho Vault 离线版确实允许攻击者篡改 URL。

**负责任披露。** 研究结果已通报两家受影响的厂商。Delinea 确认了漏洞存在，但表示「恶意服务器」不在其威胁模型内；作者与 Passbolt 做了深入沟通并给出了缓解建议。

**结论性洞察。** 每一个能抵抗离线猜测的 PM，都引入了另一个高熵秘密——要么是一条额外的秘密字符串（1Password、Multipassword），要么是第二台设备（BluePass、Amnesia、Tapas）。没有它，单靠一把主密码无法提供足够熵，协议就只能全押在 PBKDF2、Argon2 这类慢哈希/内存困难函数上。

## 4. 适用场景与迁移边界

最可迁移的结论是模型层面的、定性的：**由单个人为选择的主密码保护的保险库存在硬上限**，而这个上限由口令的熵决定，与密码算法强度无关。下游的一切——哪些产品安全、在哪个攻击者面前安全——都由「是否存在第二个秘密」这一条决定。

结论是在一套特定威胁模型下给出的，前提必须说清。攻击者**攻陷服务器**并读取其存储状态；服务器可以任意偏离协议；TLS 被假设但视为无关；客户端诚实；协议限定为两方。在这套模型内，结论已接近此处能达到的最强形式：对 8 个协议是 UC 证明，其余是逐案的系统性论证，而不是带置信区间的测量。出了这个边界，指导性就变弱了。三方（带辅助设备）设计被明确排除在模型之外，所以它们表面上的「免疫」是范围设定的产物，而非证明。元数据也被刻意排除在功能之外（Remark 1）——作者把它打包移出，正是为了不让 1Password 未加密的元数据掩盖其双密钥机制的强度——这意味着该模型对 §5.2 记载的「经自动填充被钓鱼」风险不置一词。

形式化模型与落地实现之间还存在真实落差。作者只能从文档分析 3 款 PM，另有 3 款完全无法分析；还有 6 款（Enpass、Sticky、Password Boss、SafeInCloud、iCloud Keychain、TeamPass）是依据文档描述而非观测到的协议流量来判定的，因此其结论强度不如那 27 款信息充分的。真实的 KDF 参数也往往只有逆向工程才能读出。形式化结果描述的因此是**被重建出来的**协议，而不是任何厂商承诺的协议。

对实践而言，迁移含义很具体。检索型 PM 无法靠调优 PBKDF2 或 Argon2 逃出这个上限——35 款已经在这么做，而 38/43 仍然至少被一类攻击者打穿。真正有效的动作是：引入第二个高熵秘密或第二台设备；把当前明文的元数据加密（43 款中有 30 款没有）；替换 Delinea Web 式的明文认证与 Passbolt 式的预言机设计；并且把「零知识加密」当成一句**需要在恶意服务器模型下被检验的宣称**，而不是一种性质。Delinea 的回复本身就是一条迁移边界：厂商可以把恶意服务器定义在范围之外，此时分析依然成立，但产品对外宣称的保证并不成立。

<div class="aside">
<p><span class="aside-label">题外话 · 一句结论背后的成本</span></p>
<p>「43 款中 38 款失守」这句结论，来自一次作者形容为耗时近四个月的排查——每一次证明失败都不是放弃某个协议的理由，而是一条继续追下去的线索。筛选过程本身也值得一看：工业候选起初有 145 款，按装机量、是否以安全为焦点、能否跑起来逐层剔除，最后剩下 36 款工业产品，再加上 7 个学术方案。读出真实参数就是一半的工作量：36 款工业产品里有 24 款必须靠逆向工程，因为客户端实际使用的 KDF 迭代次数，和白皮书宣传的并不一定是一回事。</p>
<p class="aside-source">出处：论文完整版 §3.1（样本筛选）、§3.3（采集与逆向工程）、§5（分析耗时近四个月）。</p>
</div>

## 5. 相关文献与领域现状

- **Gasti 与 Rasmussen，2012。** *On the Security of Password Manager Database Formats*，ESORICS 2012。首个严格的保险库存储格式分析，给出不可区分性与不可延展性博弈；作者称之为里程碑，但批评它分析的是格式而非协议。([链接](https://doi.org/10.1007/978-3-642-33167-1_44))
- **Li, He, Akhawe, Song，2014。** *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*，USENIX Security 2014, pp. 465–479。开启这条研究脉络的、对已部署浏览器密码管理器的系统评估。([链接](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei))
- **Oesch 与 Ruoti，2020。** *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*，USENIX Security 2020, pp. 2165–2182。三年后的复现研究，其元数据发现被本章论文用自己的数据集再次核验。([链接](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch))
- **Scarlata, Torrisi, Backendal, Paterson，2026。** *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers*，IEEE S&P 2026 / IACR ePrint 2026/058。从另一侧攻击恶意服务器模型：对 Bitwarden、LastPass、Dashlane、1Password 给出具体协议攻击。([链接](https://eprint.iacr.org/2026/058))
- **Davies 等，2023。** *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol*，CRYPTO 2023。本章 M3PM 功能所借鉴的 UC 框架下 PPKR 功能的出处——一个口令、一个密钥、十次猜测。([链接](https://eprint.iacr.org/2023/843))
- **Bellare 与 Rogaway，1993。** *Entity Authentication and Key Distribution*，CRYPTO 1993。支撑「认证」这一目标的实体认证与会话密钥分发模型。([链接](https://doi.org/10.1007/3-540-48329-2_21))
- **Bellovin 与 Merritt，1992；Jarecki, Krawczyk, Xu，2018。** 加密密钥交换（EKE）与 *OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks*，EUROCRYPT 2018。SRP 式 M3PM 认证所属的 PAKE 脉络，也是该领域抗钓鱼后继方案的基石。([EKE](https://doi.org/10.1109/RISP.1992.213269) · [OPAQUE](https://eprint.iacr.org/2018/163))
- **RFC 5869、RFC 8018、RFC 9106。** HKDF、PBKDF2 与 Argon2——先提取后扩展的 KDF、被 35 款被分析产品采用的加盐迭代 KDF，以及取代它的内存困难函数。([HKDF](https://www.rfc-editor.org/rfc/rfc5869) · [PBKDF2](https://www.rfc-editor.org/rfc/rfc8018) · [Argon2](https://www.rfc-editor.org/rfc/rfc9106))

这篇论文把自己放在什么位置？**系统化的形式化者**。它认可 Gasti/Rasmussen 与 Oesch/Ruoti 已经确立了**保险库格式**必须满足什么，也认可 Bojinov/Chatterjee 让蜜罐保险库成为应对泄露的标准答案——然后指出这些都没有覆盖认证、跨设备取回，以及认证与加密的组合。它把领域现状读作：厂商在做一个不可证伪的「零知识」宣称，正确的做法是先把协议层的理想功能定义出来，再拿产品去比。它与随后那批以攻击为导向的工作（Scarlata 等 2026）互为对位：两者在「必须把恶意服务器纳入范围」上一致，分歧只在方法。

## 6. 小结与回响

- **主密码保护的口令管理协议（M3PM）** 指的是客户端—服务器之间**认证 + 取回**的完整交互，而不只是保险库的加密；仅凭加密安全推不出协议安全。
- 研究从文档、TLS 之前的流量、本地存储文件与静态/动态逆向工程中，重建了 **43 款 PM（36 工业 + 7 学术）** 的 M3PM 协议；36 款工业产品中 24 款必须逆向，全部原始数据公开。
- 认证有五种形态（哈希主密码、受保护令牌、SRP、mpw challenge、pk challenge），口令处理有四类（主密码加密、设备密钥加密、编码后加密、生成型）；论文比较的正是它们的组合。
- 安全目标在 **UC 框架**下形式化为 $F_{\mathsf{M3PM}}$，并细化为显式/隐式认证两版、含 `TESTMPW` 查询的松弛版 $F^{r}_{\mathsf{M3PM}}$、以及面向「第二秘密」设计的 $F^{\mathsf{ad}}_{\mathsf{M3PM}}$。
- 离线猜测只需两样东西——人为口令那 $2^{20}$–$2^{22}$ 比特的熵，以及任何可供比对的存储值——由 `GuessVerify` 算法刻画。
- 面对**四类攻击者**（无额外信息；服务器被攻陷；部分口令泄露；两者兼有），**43 款中 38 款**至少失守一类，**34 款**无法满足基础功能，只有 **1Password 与 Multipassword** 达到 $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$。
- 蜜罐保险库补不上缺口（自适应分布可击穿编码后加密）；Delinea Web 全程明文；Passbolt 经预言机泄露加密密钥；43 款中 30 款元数据未加密，从而给 URL 篡改与钓鱼留下空间。
- 最耐久的一条教训：**每一个能抗住离线猜测的 PM 都加了第二个高熵秘密**；没有它，安全性只能全押在 PBKDF2、Argon2 这类慢哈希/内存困难 KDF 上——而 35 款产品已经在这么做，却依然不奏效。

**回响。** 第 8–10 章测的是已部署密码管理器「实际做了什么」——Li 等发现自动填充与口令生成器的破绽，Oesch 与 Ruoti 发现三年后略有改善，Fábrega 等展示了注入攻击如何泄露保险库机密；三者评估的都是实现。本章从另一侧切入同一个靶子：把这些产品所跑的**协议**放进恶意服务器模型做形式化，追问哪些设计甚至「有证明可言」。它揭出的缺口，正是本书从第 1 章起一直背着的那一个——保险库是加密的，但主密码仍是一段必须送往服务器的共享秘密，而任何看到由它派生出的值的服务器，都能离线拿它验证猜测。第 8–10 章展示了破坏本身，本章则说明为什么在结构上，单凭一把人为选择的口令堵不住它：除非再加一个高熵秘密或第二台设备。第 13 章走的是相反的路——干脆不再共享可猜的秘密，改为让服务器只持有一把公钥。

## 参考文献

1. Yihe Duan, Ding Wang, Yanduo Fu. *Security Analysis of Master-Password-Protected Password Management Protocols.* 2025 IEEE Symposium on Security and Privacy (S&P), pp. 701–719. https://doi.org/10.1109/SP61157.2025.00050
2. Duan, Wang, Fu. 论文完整版（作者自存 PDF，篇幅长于会议版），https://bit.ly/3zBPVUO —— 该短链指向作者个人站点；撰写本章期间该站点时好时坏。
3. 论文公开数据仓库（逐产品的原始数据）：https://github.com/DanielNKU/pm-analysis
4. Paolo Gasti, Kasper Bonne Rasmussen. *On the Security of Password Manager Database Formats.* ESORICS 2012, LNCS 7459, pp. 770–787. https://doi.org/10.1007/978-3-642-33167-1_44
5. Zhiwei Li, Warren He, Devdatta Akhawe, Dawn Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers.* USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei
6. Sean Oesch, Scott Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers.* USENIX Security 2020, pp. 2165–2182. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
7. Matteo Scarlata, Giovanni Torrisi, Matilda Backendal, Kenneth G. Paterson. *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers.* IACR ePrint 2026/058（USENIX Security 2026）. https://eprint.iacr.org/2026/058
8. Gareth T. Davies, Sebastian Faller, Kai Gellert, Tobias Handirk, Julia Hesse, Máté Horváth, Tibor Jäger. *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol.* CRYPTO 2023. https://eprint.iacr.org/2023/843
9. Mihir Bellare, Phillip Rogaway. *Entity Authentication and Key Distribution.* CRYPTO 1993, pp. 232–249. https://doi.org/10.1007/3-540-48329-2_21
10. Steven M. Bellovin, Michael Merritt. *Encrypted Key Exchange: Password-Based Protocols Secure Against Dictionary Attacks.* IEEE S&P 1992, pp. 72–84. https://doi.org/10.1109/RISP.1992.213269
11. Stanislaw Jarecki, Hugo Krawczyk, Jiayu Xu. *OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks.* EUROCRYPT 2018, pp. 456–486. https://eprint.iacr.org/2018/163
12. Hugo Krawczyk, Pasi Eronen. *HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* RFC 5869, IETF, 2010. https://www.rfc-editor.org/rfc/rfc5869
13. Kathleen Moriarty (ed.). *PKCS #5: Password-Based Cryptography Specification Version 2.1.* RFC 8018, IETF, 2017. https://www.rfc-editor.org/rfc/rfc8018
14. Alex Biryukov, Daniel Dinu, Dmitry Khovratovich, Simon Josefsson. *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.* RFC 9106, IETF, 2021. https://www.rfc-editor.org/rfc/rfc9106
15. Hristo Bojinov, Elie Bursztein, Xavier Boyen, Dan Boneh. *Kamouflage: Loss-Resistant Password Management.* ESORICS 2010, LNCS 6345, pp. 286–302. https://doi.org/10.1007/978-3-642-15497-3_18
16. Rahul Chatterjee, Joseph Bonneau, Ari Juels, Thomas Ristenpart. *Cracking-Resistant Password Vaults using Natural Language Encoders.* IEEE S&P 2015, pp. 481–498. https://doi.org/10.1109/SP.2015.35

## 事实核对清单

以下每一条都取自论文正文（作者完整版；节号对应该版本），凡注明「数据仓库」者取自论文公开的原始数据。表格中「Table 1/2/3」为原文表号。

| 本章中的说法 | 原文出处 |
|---|---|
| 作者 Yihe Duan, Ding Wang, Yanduo Fu；IEEE S&P 2025, pp. 701–719；DOI 10.1109/SP61157.2025.00050 | 完整版首页；IEEE CSDL；DBLP `conf/sp/DuanWF25` |
| 作者单位南开大学（通信作者 wangding@nankai.edu.cn） | 完整版首页 |
| 用户需维护 80–168 个账号 | §1 |
| LastPass 三年内三次泄露；2022 年事件与约 440 万美元加密货币失窃相关 | §1 |
| 「零知识」是厂商宣称 | §1 |
| M3PM 定义；保险库加密安全 ≠ 协议安全；认证与加密的不当组合 | §1（交叉引用 §5.4） |
| Gasti–Rasmussen 2012 首个存储格式严格分析；Oesch–Ruoti 2020 复现 | §2.2 |
| Kamouflage 与 NoCrack 蜜罐保险库；Davies 等 CRYPTO'23 PPKR | §2.2 |
| PPKR：一个口令对一个密钥，允许 10 次离线猜测 | §2.2 |
| 检索型/生成型分类；LessPass、SPHINX 为例 | §2.1 |
| 43 款 = 36 工业 + 7 学术；工业候选 145 款 | §3.1、贡献列表 |
| 筛选条件（装机量 <1 万、学术非安全焦点、无法运行） | §3.1 |
| 24/36 靠逆向工程；32 款有可用数据日志；6 款主要靠文档；27 款信息充分 | §3.3 |
| 五种认证形态及其注册值（$h_{\mathsf{pw}}$、$\mathsf{eauth}$、$v$、mpw/pk challenge、$\mathsf{esk}$） | §3.3 与图 2 说明 |
| 四类口令处理及其公式（$e\mathsf{Vault}$、$e\mathsf{vk}$、编码后加密、生成型） | §3.3 与图 3 说明 |
| 威胁模型：可攻陷服务器、读取全部存储；服务器可偏离协议；TLS 假设但无关 | §4.1 |
| 七条安全目标 | §4.1 |
| $F_{\mathsf{M3PM}}$、$F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$、$F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$、含 `TESTMPW` 的 $F^{r}_{\mathsf{M3PM}}$、$F^{\mathsf{ad}}_{\mathsf{M3PM}}$ | §4.2 |
| 隐式认证失败时返回服从 Zipf 分布的诱饵口令 | §4.2 |
| 只建模两方（Remark 2）；单方指派服务器；三方留作未来工作 | §4.2、Remark 2 |
| 1Password Protocol OP：$x$、$\mathsf{mk}$、$\mathsf{esk}$、$e\mathsf{vk}$、$e\mathsf{Vault}$ 各表达式 | §4.2 / Protocol OP |
| 口令熵 $2^{20}$–$2^{22}$ 比特，对比 AES 128/192/256 | §5.1 |
| `GuessVerify`($m$, $X$, $\sigma$) 与 `123456abc` 例子 | §5.1 |
| 各类方案下被攻陷服务器的验证方式 | §5.1、Table 1 脚注 |
| 编码后加密被自适应分布击穿；`abc12345` 例子 | §5.1 |
| 生成型方案在一条生成口令泄露前可抗离线猜测 | §5.1 |
| 四类攻击者（Type-I … Type-IV）及各自失守的产品 | §5.1、Table 1 脚注 |
| 43 款中 38 款至少不敌一类 | 摘要；§3.3 贡献列表；§5.1 |
| 34/43 无法满足 $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ 或 $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$ | §4.2 |
| 35 款使用 PBKDF2 或 Argon2 | §4.2 |
| 30/43 元数据未加密；Zoho Vault 离线版 URL 可被篡改 | §5.2、Remark 1 |
| 仅 1Password 与 Multipassword 达到 $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ | §5、§4.2、Table 1 注 |
| 对 8 种不同协议给出可证明分析 | §5 |
| 6 款无法证明：Norton、Chrome、Passwarden（信息不足）；Amnesia、BluePass、Tapas（三方） | §5 |
| 另 6 款依文档判定（Enpass、Sticky、Password Boss、SafeInCloud、iCloud Keychain、TeamPass） | Table 1 注 |
| 分析耗时近四个月 | §5 |
| Delinea Web 客户端无密码学运算、全明文通信 | 摘要；§3.3；§5 |
| Passbolt：预言机攻击，被攻陷服务器可学到加密密钥 | 摘要；§5（细节在 §5.4） |
| 已向 Delinea 与 Passbolt 负责任披露；Delinea 不把恶意服务器纳入威胁模型 | 引言「Responsible disclosure」 |
| 洞察：所有能抗猜测的 PM 都引入了第二个高熵秘密 | §5.1「Insights」 |
| 各产品的 PBKDF2/Argon2/AES 选择（Bitwarden 用 PBKDF2 与 Argon2id；LastPass 用 PBKDF2；Dashlane 用 PBKDF2 与 Argon2；KeePass 用 AES-256/SHA-256/KDF） | 论文公开数据仓库各产品 `Documentations sources/summary.md`；论文附录 D |

## 存疑 / 未获取清单

- **完整版的后半部分未能取回。** 作者完整版 PDF 是通过缓存取到的，在第 5.2 节与 1Password 协议规格之后被截断。因此本章**没有**写：§5.3 对 1Password 协议的安全证明（以及该证明如何扩展到「显式认证 + 主密码加密/设备密钥加密」的同类协议）、§5.4 Passbolt 预言机攻击的具体机理、§5.5 对 SPHINX 的证明、§6.1 的具体缓解建议，以及附录 A–E。文中对 Passbolt 预言机与 SPHINX 证明的描述只到摘要与 §5 所陈述的层面；需要机理的读者应直接查阅原文 §5.4。
- **标准的开放获取渠道没有该文。** IACR ePrint、arXiv 与 Unpaywall 均显示为闭源（S2 标注为 `CLOSED`）；唯一找到的免费副本是作者自存的完整版（参考文献第 2 条），其托管站点在本环境与若干公共代理处均返回 404。本章内容是在该副本尚可访问时取到的，另加公开摘要。**未使用任何盗版镜像站。**
- **数据仓库里有 36 个产品目录，少于论文的 43 款**（论文的 43 = 36 工业 + 7 学术；仓库目录基本对应工业那一批，另含 LessPass、Gopass、Gokey 等学术方案）。因此本章**没有**声称该仓库完整枚举了 43 款。
- **Table 1 与 Table 2 的单元格内容无法从抽取文本中读出**（表格只以图片引用形式保留），所以逐产品判定只在正文点名处引用；超出「30/43」这一汇总值的逐产品元数据结论同样无法获得。
- 会议版比完整版短 8 页，措辞可能不同；页码与摘要文字是依据公开的出版元数据核对的，而非会议版 PDF 本身。
- **与任务 handoff 不一致之处：** handoff 把 Ding Wang 记为「北京大学」，而论文署名的单位是**南开大学**（北京大学是其博士所在）。本章以论文为准。handoff 把本章定位为「形式化/协议层」分析，这一点与原文一致。

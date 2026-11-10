# 最早的 Web 版密码管理器系统分析（2014）

<div class="source-card">
<p><strong>本章文献：</strong> Zhiwei Li, Warren He, Devdatta Akhawe, Dawn Song（加州大学伯克利分校）. <em>The Emperor's New Password Manager: Security Analysis of Web-based Password Managers</em>. 收录于第 23 届 USENIX Security Symposium 会议论文集, 美国圣迭戈, 2014 年 8 月, 第 465–479 页. <a href="https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-li-zhiwei.pdf">开放获取 PDF</a>（USENIX 官方）。</p>
<p><strong>一句话：</strong> 这是最早对五款流行的 <em>Web 版</em>密码管理器做系统安全分析的工作：五款全部发现严重漏洞，其中四款可被攻击者窃取用户任意网站的凭据——说明问题出在实现与对 Web 平台模型的假设，而不在"密码管理器"这个想法本身。</p>
</div>

<div class="hook">
<p>回想一下你上一次输入口令的那一刻。你记得的只有那个登录框——可登录框只是这个字符串停留过的众多地方之一。在你敲下它之前，已经有某个程序替你把它生成出来、保存起来、同步到服务器，再在你需要时填了回去；而一路上，同一串字符要经过 JavaScript、经过 iframe，还要经过一个你从未特意选择去信任的网站。2014 年的一篇论文问得很直接：当同一个程序替你保管着所有账号的口令时，一个仅仅在浏览器里站住了脚的攻击者，究竟能拿到多少东西？</p>
</div>

## 1. 背景与动机

Web 上基于口令的认证之所以不安全，很大程度上源于认知负担：用户往往（而且是理性地）在多个站点复用又短又好猜的口令。密码管理器正是为此提出的解法：为每个站点保存一个独立、强随机的口令，按需取用；而且由于它是**按页面 URL**（而非页面内容）来决定填入哪条凭据，还顺带提供了一定的抗钓鱼能力。再加上跨设备云同步，其卖点就是"以极低的部署成本换来巨大的安全与易用收益"。论文引用的一份 US-CERT 资料称密码管理器是"记录每个独立口令、又不必写在纸上"的最好办法之一；主流媒体乃至技术书籍也都在推荐。用户随之涌入：LastPass 宣称截至 2013 年 8 月已有超过一百万用户，PasswordBox 则声称在 2013 年 5 月上线后三个月内用户破百万。

但**理想化的**密码管理器并不等于真实的产品。Li、He、Akhawe 与 Song 要评估的正是真实产品：当把一次安全分析对准那数百万用户已经把全部口令托付给它的、运行在浏览器里的应用时，会发生什么？他们的动机说得很直白——密码管理器是认证生态里**一个新的、未经检验的单点故障**，一旦有实现缺陷，攻击者可以一次拿走用户所有口令。此前针对其他口令替代方案（如单点登录 SSO）的研究已经揭示过同样的落差。

本文的威胁模型是 **Web 攻击者（web attacker）**：控制若干 Web 服务器与 DNS 域名、并能诱导受害者访问这些域名的攻击者。作者针对本场景作了小幅扩展——受害者甚至可以在攻击者的应用上注册账号并用管理器保存其凭据；攻击者也可以自己在密码管理器服务上注册账号并直接向它发请求。模型假设：密码管理器自身的代码**不是恶意的**、不会私自把 Alice 的凭据分享给他人、用户会为管理器设置独立的主口令。

安全目标只有一条不变式——**保存的口令只能被授权用户以及它对应的网站访问**——并拆成四条目标：**主账号安全**（攻击者不能以用户身份登录管理器）、**凭据库安全**（凭据的机密性、完整性与可用性）、**协作者完整性**（共享功能必须真正执行其访问控制列表）、**不可关联性（unlinkability）**（使用管理器不应让互相串通的站点追踪同一个用户；采用 Bonneau 等人的定义）。

为什么此前的工作不够？针对密码管理器 **bookmarklet**（书签小工具）的攻击自 Adida 等人（2009）起就已知，Bhargavan 等人也研究过云端加密存储，但没有谁系统性地梳理过 Web 版密码管理器的攻击面。这些产品全是专有、经过代码混淆的，没有公开的安全架构，而且自动填充、客户端加密、一次性口令等功能各家实现方式迥异——这恰恰是最需要一次全面、横向对比分析的条件。

## 2. 研究对象与攻击面

研究覆盖五款流行的 Web 版密码管理器，刻意选取功能组合各异的产品（Table 1）：

- **LastPass**——功能最全：bookmarklet、浏览器扩展、网站三种入口；支持一次性口令（OTP）与双因素认证；支持共享。它用 `KDF(mp, mu, 5000, 32)` 派生密钥（主口令、主用户名、5000 次迭代、32 字节密钥），加密用户名与口令。
- **RoboForm (Everywhere)**——每条凭据单独存成一个文件，默认以网站域名命名；**除非用户主动设置主口令，这些文件会以明文发送到 RoboForm 服务器**。支持 bookmarklet、扩展与网站；不支持共享。
- **My1login**——只提供 bookmarklet，没有扩展（主打"No install needed"）；支持共享。密钥派生很特殊：把口令偶数位与奇数位字符的 MD5 拼接起来 `MD5(pheven) + MD5(phodd)`，凑成 256 位密钥。
- **PasswordBox**——只提供扩展；支持共享。用 `KDF(mp, mu, 10000, 32)` 派生密钥，且**只加密口令字段**。
- **NeedMyPassword**——最基础的一款：仅网站存储，无自动登录、无口令生成、无共享，且凭据在发送到服务器前**完全不加密**。

作者把攻击面划分为四类，后续分析都按这四类展开：

1. **bookmarklet 漏洞**：bookmarklet 是一段在当前页面（可能是恶意页面）上下文中运行的 JavaScript。运行在 `evil.com` 上的代码不能相信任何 DOM API，因为攻击者可能已把它们换掉。
2. **"经典" Web 漏洞**——CSRF（浏览器跨源共享 cookie）与 XSS（未净化的输入被插入文档；在 Web 安全模型下 XSS 等于完全沦陷）。
3. **授权漏洞**：共享功能给每条凭据都加了访问控制列表；把"认证"误当成"授权"（如服务端缺少归属校验）会让任何用户读到任何凭据。
4. **界面（UI）漏洞**：抗钓鱼本是核心卖点，一个反而把用户训练出可钓鱼习惯的管理器，比普通网站更糟——一次成功的钓鱼就能暴露全部凭据。

## 3. 安全分析与发现

核心结论：作者在**全部五款**管理器中发现严重漏洞，其中**五款里有四款**，攻击者可以窃取用户任意网站的凭据。漏洞跨越了截然不同的功能——一次性口令、bookmarklet、共享口令——根因同样多样：逻辑与授权错误、对 Web 安全模型的误解，以及常见的 CSRF 与 XSS。Table 2 汇总了各产品命中的漏洞类型。

**bookmarklet。** 三款提供 bookmarklet 的管理器——LastPass、RoboForm 与 My1login——**全部**存在漏洞；在三种情况下，只要用户在攻击者的站点上点击了 bookmarklet，攻击者就能窃取任意网站的凭据。以 LastPass 为例：用户安装 bookmarklet 时，页面生成随机值 `_LASTPASS_RAND` 并用它加密主密钥；服务器保存密文（`key_rand_encrypted`）和标识符 `h`，bookmarklet 中携带 `_LASTPASS_RAND` 与 `h`。使用时，bookmarklet 会从 `lastpass.com` 注入一段脚本（带上 `h` 与当前域名 `u`），该脚本再建立 iframe，去取 `lastpass.com/bml.php?u=dropbox.com`——这个 **URI 是可预测的**，返回的正是加密后的主密钥**以及**加密后的 Dropbox 凭据。由于同源策略允许任意来源包含并执行任意来源的脚本，攻击者可以直接请求这个 URI，用 JavaScript 劫持手法（如 `Function.toSource`）从被加载的脚本里把值抠出来，再用先前窃取的 `_LASTPASS_RAND` 解密——对每条凭据重复即可。此外，`h` 与 `_LASTPASS_RAND` 在不同浏览器间保持不变、但每个用户不同，因此任何用户点击过 bookmarklet 的站点都能拿到一个稳定的伪标识符，从而实现跨站追踪、把同一用户的多个账号关联起来（违反不可关联性）。

**Web 漏洞：LastPass 的一次性口令。** LastPass 的 OTP 设计成服务器永远看不到 OTP 与主密钥：客户端计算 `h = hash(hash(alice|otp)|otp)`，并用 `hash(alice|otp)` 加密主密钥得到 `rand_encrypted_key`，再把 `h` 与 `rand_encrypted_key` 发给服务器；服务器保存三元组，之后靠匹配 `(用户名, h)` 来认证。问题在于，创建 OTP 的请求（`otp.php`）**只靠 cookie 认证、且没有 CSRF token**，服务器也无法验证 `rand_encrypted_key` 是否真是主密钥的密文。于是，仅知道 Alice 用户名的攻击者就能伪造一个 `otp'`、算出 `h'` 和一个假的 `rand_fake_key`，发出 CSRF 请求——之后便能用 `otp'`"以 Alice 身份"登录。虽解不开真正的主密钥，却带来三点后果：（1）LastPass **明文存储**了入口点列表，攻击者由此得知 Alice 在哪些网站有账号（隐私泄露）；（2）拿到加密数据库后，可对用户死记硬背的主口令做**离线猜测**；（3）拒绝服务——以 Alice 身份登录后，即使解不开也能**删除**她的凭据。论文还报告了 RoboForm 的 CSRF（可更新、删除、添加任意凭据）与 NeedMyPassword 的 XSS（完全账号接管），二者的细节放在扩展技术报告里。

**授权。三款支持共享的管理器中有两款把认证当成了授权。** 在 **My1login** 中，客户端用接收者的公钥加密被共享的凭据，但服务器在 Alice 分享一张 web card 时只校验 Alice 已登录，**从不校验她是否拥有** `wcid` 指向的那张卡片。更糟的是，web card 的 ID 是**全局唯一、自增的整数**。由此产生"分享并更新（share-and-update）"攻击：Mallory 用虚假凭据把任意一个（甚至尚不存在的）卡片 ID 分享给协作者 Eve，Eve 就因此被登记为该卡片的协作者；日后真正的属主一更新这张卡片，客户端就会把真实凭据重新加密发给**所有**协作者——包括 Eve。同一缺陷也能让 Eve 注入凭据（一种登录 CSRF），或注入错误凭据以诱使 Alice"更正"。在 **PasswordBox** 中，同类缺陷出现在 `asset_id` 上——同样是全局唯一自增数字（论文据此推断 PasswordBox 管理着超过 400 万条资产）。PasswordBox **确实**做了 CSRF 防护（校验 `Referer` 并带上 `X-CSRF-Token` 头），所以这是纯逻辑漏洞：共享时不校验归属，Mallory 只要遍历所有 `asset_id` 就能把全部资产分享给 Eve。又因为 PasswordBox **只加密口令字段**——姓名、用户名、URL、创建时间全是明文——泄露全体用户的元数据本身就是严重的隐私事故。

**界面。** 用户未登录时，安全的设计应当请用户**新开一个标签页**去登录；只有 My1login 这么做。RoboForm 的 bookmarklet 却把登录表单放进一个 iframe、嵌在被访问的（攻击者可控的）页面里，于是地址栏永远不是 `roboform.com`——这恰恰把用户训练成违背唯一真正安全习惯的人。攻击者可以拦截 iframe、伪造登录框；再借助一个侧信道（用户已登录时 iframe 高度大于 200 px）让伪造更可信。LastPass 也有类似问题。

**漏洞披露。** 所有攻击都经过实验验证，并于 2013 年 8 月最后一周报告给相关厂商。五家中有四家在一周内回复，NeedMyPassword 始终未回复。除不可关联性问题与 NeedMyPassword 的漏洞外，论文描述的其余漏洞都在披露后几天内被修复。五款产品都没有漏洞赏金计划。

## 4. 适用场景与迁移边界

本文研究的是一种特定的架构——**Web 版（云端）密码管理器**：凭据同步到某个服务，并通过浏览器扩展、网站或 bookmarklet 取用。几乎每一项发现都是这种架构的性质，而非"密码管理器"这件事本身的性质。由此有两点推论。

**哪些结论不可直接迁移。** 占比最大的一类——bookmarklet 漏洞——只在管理器把代码跑进第三方页面 JavaScript 上下文时才存在。纯本地产品（论文明确排除了 RoboForm Desktop）与今天的浏览器内置管理器（Chrome、Edge、Safari、Firefox）根本没有这个攻击面，因此它们的具体漏洞不会照搬过来。同理，"把密钥放进 JS 文件"和"可预测的资源 URI"是那种部署方式的问题；一个拥有隔离 API 的原生扩展不会以同样方式暴露它们——而这样的隔离 API（或把代码放进管理器自身源下的 iframe）正是作者推荐的修法。

**哪些结论可以迁移。** 有若干发现是结构性的，不随版本失效：（a）运行在 Web 源里的客户端加密，必须保证任何其他源可包含的脚本里都不含密钥，否则加密会被**分发方式**本身破掉；（b）共享功能必须做真正的归属校验，而**可预测的标识符**会把一处缺失的校验从"攻击一个用户"放大成"攻击所有用户"；（c）把主口令输入框放进可被嵌入的框架里，等于把用户训练向那个唯一会攻破抗钓鱼的习惯。正因如此，作者的建议刻意写得很宽：CSRF token（或改用 `X-CSRF-Token` 头，因为扩展很难为每个表单都取一次新 token）外加 `Referer`/`Origin` 校验；启用 CSP（只有 LastPass 发了 CSP 头，而且策略很弱，允许 `eval` 与内联脚本）；所有用户加载的脚本必须一致、密钥只放在 HTML 或 JSON 里；用密码学随机的标识符取代连号整数；以及采用更简单、单一属主的共享模型，让缺失的授权校验更容易被发现。

**前提条件。** 这些攻击都假设 Web 攻击者模型：控制受害者会访问的站点，或在管理器服务上拥有账号。它们不需要本地恶意软件、不需要网络位置、也不需要管理器代码作恶。值得注意的是，授权类攻击（My1login、PasswordBox）与 LastPass 的 OTP 攻击**完全不需要受害者的浏览器参与**——只需知道一个用户名或一个 ID——这本身就说明"服务器只看得到密文"并不是一条独立成立的安全论据。

**局限（按作者的表述）。** 这次分析是手工进行的，作者因此预期仍有未被发现的漏洞；样本是 2013 年的五款专有、混淆过的产品；部分攻击细节只存在于扩展技术报告中；而且这里讨论的加密只保护**凭据字段**，元数据（URL、用户名、姓名）常以明文出现——这一主题在后续章节还会反复出现。对今天的直接启示是：浏览器内置管理器与独立 App 依然面临自动填充/注入与元数据泄露的问题，只是换了攻击面（原生自动填充框架、移动操作系统集成），而这正是后续工作接手的地方。

<div class="aside">
<p><span class="aside-label">题外话 · 标题本身就是双关</span></p>
<p>这篇论文叫 <em>The Emperor's New Password Manager</em>（皇帝的新密码管理器），显然化用了安徒生的《皇帝的新装》：满街的人都在称赞一件并不存在的衣服，因为谁一旦承认自己看不见，就等于承认自己不配待在这个位置上。照这个读法，标题本身就是作者对「零知识」密码管理器的判词——宣传中的安全，恰恰把实现里的窟窿遮住了，而用户选择去相信那个被告知能保护自己的东西。需要说明的是，这是本书对标题的理解，不是论文里的论断：原文从未对标题作过任何解释。</p>
<p class="aside-source">出处：本书的解读。标题出自 Li、He、Akhawe 与 Song，USENIX Security 2014（开放获取 PDF）；续作 <em>The Emperor's New Autofill Framework</em>（ACSAC 2021）沿用了同一化用方式。此条属背景解读，非论文内容。</p>
</div>

## 5. 相关文献与领域现状

作者把自己定位为对"理想化密码管理器"叙事的**系统化者与批评者**：他们接受"管理器本应有用"的评估框架（Bonneau 等），但用实证表明真实实现"严重削弱"了这一框架。

- **J. Bonneau, C. Herley, P. C. van Oorschot, F. Stajano, *The Quest to Replace Passwords: A Framework for Comparative Evaluation of Web Authentication Schemes*, IEEE S&P 2012**（[IEEE](https://doi.org/10.1109/SP.2012.44)）——提供了评估框架与不可关联性的定义；它展示了理想化管理器的优势，而本文随后给出了现实中的漏洞。
- **B. Adida 等, *Attacks on password manager bookmarklets*, 2009**——更早的 bookmarklet 攻击；本文表明这些问题依然存在，且一旦管理器在客户端加密凭据，就需要新的、基于 iframe 的防御。
- **K. Bhargavan 等, *Defensive JavaScript / 云端加密存储研究***——研究了五款密码管理器以及其他云端加密服务，启发了 LastPass bookmarklet 的重新设计，并提出 Defensive JavaScript；这是作者所知唯一旨在保护"JS 小工具"免受宿主页面影响的既有工作。
- **M. Blanchou, P. Youn（iSEC Partners）, *Password managers: Exposing passwords everywhere*, 2013**（[PDF](https://www.isecpartners.com/media/106983/password_managers_nov13.pdf)）以及 **Silver 等（同期工作）**——发现了密码管理器**自动填充**的缺陷；本文覆盖面更广，但只看第三方 Web 版管理器。
- **D. Belenko 等, *移动端密码管理器密码学性质***——暴力破解移动端管理器，属于相邻的设备侧威胁。

后续工作让这个问题保持开放，并转向新的攻击面：

- **S. Oesch, S. Ruoti, *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*, USENIX Security 2020**（[usenix.org](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch)）——时隔五年，重新评估口令生成、存储与自动填充（本书第 9 章）。
- **M. Carr, S. F. Shahandashti, *Revisiting Security Vulnerabilities in Commercial Password Managers*, SEC 2020**（[arXiv:2003.01985](https://arxiv.org/abs/2003.01985)）——重访商用密码管理器的漏洞。
- **S. Oesch, A. Gautam, S. Ruoti, *The Emperor's New Autofill Framework: A Security Analysis of Autofill on iOS and Android*, ACSAC 2021**（[arXiv:2104.10017](https://arxiv.org/pdf/2104.10017)）——把"皇帝的新衣"式的批判框架延伸到移动端自动填充框架。
- **A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart, *Exploiting Leakage in Password Managers via Injection Attacks*, USENIX Security 2024**（[usenix.org](https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega)）——注入/泄露研究这条线，直接建基于本文最早提出的共享与同步担忧（本书第 10 章）。

综合这条文献脉络，领域已就本文最早详细论证的判断形成共识：密码管理器的**理念**是成立的，风险集中在**实现与所处平台**，而非算法；而"服务器只看得到密文"这一说法，必须在每一个功能、每一个标识符、每一个服务端下发的脚本这个层面逐一检查。作者收尾时提出的议程——自动化的漏洞发现工具、以及一个原则性的、构造即安全的密码管理器——迄今大体仍未被完成。

## 6. 小结与回响

- 这是对 **Web 版**密码管理器最早的**系统性**安全分析；样本为五款产品：LastPass、RoboForm (Everywhere)、My1login、PasswordBox、NeedMyPassword。
- 威胁模型是 **Web 攻击者**；四条安全目标为：主账号安全、凭据库安全、协作者完整性、不可关联性。
- 攻击面被划为四类：**bookmarklet**、**经典 Web（CSRF/XSS）**、**授权**、**界面（UI）** 漏洞。
- 结果：五款**全部**存在严重漏洞，其中**四款**可被窃取任意网站凭据。
- 代表性攻击：LastPass bookmarklet 泄露（可预测的 `bml.php` URI + JS 劫持，另有 `h`/`_LASTPASS_RAND` 引发的可关联性）；LastPass **OTP 的 CSRF**（无 token，泄露明文入口点列表、可离线猜测、可 DoS）；My1login/PasswordBox 在自增 ID 上的**归属校验缺失**（分享并更新）；RoboForm 的 **iframe 登录框**这一钓鱼反模式。
- 修复建议宽而深：为 bookmarklet 提供隔离的 DOM API / iframe 架构、启用 CSP、CSRF token 加 `Referer`/`Origin` 校验、不发用户相关 JS、用密码学随机标识符、单一属主共享模型。
- 披露伦理：2013 年 8 月报告；五家厂商中四家回复，除不可关联性问题外的漏洞均在数日内修复；NeedMyPassword 从未回复。
- 边界：结论是 **Web/云端、运行于浏览器**这一架构所特有——浏览器内置管理器与独立 App 没有 bookmarklet 攻击面——但结构性教训（Web 源内的客户端加密、共享的授权、可预测 ID、可钓鱼的登录界面）可以迁移；后续工作（2020–2024）正是沿着同一条断层线继续推进。

**回响。** 本章开启全书的第五幕，它把全书那个问题翻到另一面来看：<strong>当服务器不可信时，秘密该放在哪？</strong> Lamport 的答案（第 1–2 章）是把秘密从服务器上拿走；HOTP 与 TOTP（第 3–4 章）为了好用，又把一个<strong>共享</strong>密钥放回了服务器与客户端两边；第 6 章眼看着伤害转移到了实现里；T/Key（第 5 章）则试图再把秘密拿走。2014 年这批管理器兜售的是同一笔交易里最舒服的那一版——为每个站点配一个独立强口令，经由一个「号称读不到内容」的服务同步到你所有设备——并且立刻重演了整个模式：秘密又回到了一个被信任的中心，而失效点再次落在实现与平台，而不是那个想法本身。不同之处在于，这一次被宣传的性质有了明确的名字——<strong>零知识（zero knowledge）</strong>——于是「承诺」与「代码」之间的距离，就成了本幕第 9–12 章的主题。

## 参考文献

1. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*. 第 23 届 USENIX Security Symposium 会议论文集, 2014, 第 465–479 页. https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-li-zhiwei.pdf
2. Z. Li, W. He, D. Akhawe, D. Song. 上述论文的*扩展技术报告*（原文以 [27] 引用；收录 RoboForm/My1login bookmarklet 攻击与 NeedMyPassword XSS 的细节）。本次撰写未单独获取。
3. B. Adida 等. *Attacks on password manager bookmarklets*. 2009.（原文引用编号 [1]。）
4. K. Bhargavan 等. *Defensive JavaScript* 及云端加密存储研究.（原文引用编号 [7]、[8]。）
5. M. Blanchou, P. Youn. *Password managers: Exposing passwords everywhere*. iSEC Partners, 2013 年 11 月. https://www.isecpartners.com/media/106983/password_managers_nov13.pdf
6. D. Belenko 等. 移动端密码管理器的密码学性质与抗暴力破解能力.（原文引用编号 [6]。）
7. J. Bonneau, C. Herley, P. C. van Oorschot, F. Stajano. *The Quest to Replace Passwords: A Framework for Comparative Evaluation of Web Authentication Schemes*. IEEE Symposium on Security and Privacy, 2012. https://doi.org/10.1109/SP.2012.44
8. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. USENIX Security 2020, 第 2165–2182 页. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
9. M. Carr, S. F. Shahandashti. *Revisiting Security Vulnerabilities in Commercial Password Managers*. ICT Systems Security and Privacy Protection (SEC 2020), Springer, 第 265–279 页. https://arxiv.org/abs/2003.01985
10. S. Oesch, A. Gautam, S. Ruoti. *The Emperor's New Autofill Framework: A Security Analysis of Autofill on iOS and Android*. ACSAC 2021, 第 996–1010 页. https://arxiv.org/pdf/2104.10017
11. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega

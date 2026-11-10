# TOTP 的前向重放攻击

<div class="source-card">
<p><strong>本章文献：</strong> Giuseppe Bianchi, Lorenzo Valeriani. <em>Time Is on My Side: Forward-Replay Attacks to TOTP Authentication</em>. 收录于 B. Arief, A. Monreale, M. Sirivianos, S. Li 编, Security and Privacy in Social Networks and Big Data (SocialSec 2023), LNCS vol. 14097, Springer, Singapore, 2023, pp. 109–126. <a href="https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7">出版社页面（付费）</a>。作者本人的会议报告幻灯片由会议官网公开托管：<a href="https://nss2023.cyber.kent.ac.uk/presentations/6-3.pdf">报告 PDF</a>。</p>
<p><strong>一句话：</strong> 服务器时钟正确并不能让 TOTP 安全——只要能改动设备的时钟，攻击者就能把还没到期的验证码提前采集下来，等对应时间步真正到来时逐个回放。</p>
</div>

*关于原文获取。* 本文由 Springer 付费墙出版，写作时未能找到任何开放获取版本（预印本或机构库副本）：OpenAlex、Semantic Scholar 与出版社均标记为 closed。因此本章依据的是出版社免费公开的部分——摘要、作者注与完整参考文献表——以及作者本人在 SocialSec 2023 官网公开托管的会议报告幻灯片，后者给出了攻击参数与 PoC 结果。以下数字取自该报告；原文未明确说明之处，本章会标注。

<div class="hook">
<p>手机搁在桌上，主人排队买咖啡去了。接下来这几分钟里，屏幕亮过两次，一个六位数字闪过又暗下去，状态栏的时间被悄悄往后拨了一截、又被拨了回来。等他端着咖啡回到座位，手机看上去和离开时一模一样——可刚刚跟着攻击者一起离开的，既不是某个口令，也不是那个密钥，而是整整一天的验证码：每一个都已经生效，每一个都只是在安静地等着属于它的那一分钟到来。</p>
</div>

## 1. 背景与问题

双因素认证（two-factor authentication，2FA）如今已是密码之外的标准第二道防线，而基于时间的一次性密码（time-based one-time password，TOTP）是两种最常见的第二因素之一。它的好处在于登录时不需要联网：手机和服务器在注册时共享一个密钥（secret），之后手机就能独立算出正确的验证码。这种便利只建立在一条假设上——两端对"现在几点"有一致的、粗略的认识。

TOTP 的论文和它的 RFC 都是围绕**服务器**来写的，这可以理解。RFC 6238 的安全考量集中在保护共享密钥、选择时间步长、以及容忍时钟偏移上。隐含的保证是：服务器的时钟可信，因此"此刻有效"的验证码必然是"此刻生成"的，被截获的验证码几秒钟就失效了。

Bianchi 和 Valeriani 指出了这个框架漏掉的一半——**证明方（prover）**的时钟。TOTP 中没有任何东西把验证码与它真正生成的时刻绑定起来：时间步完全由生成那一刻设备时钟显示的数值决定；而服务器收到验证码时，只检查它是否匹配自己当前愿意接受的某个时间步。作者称这个缺口是一个"明显（却在某种程度上被忽视）的事实"：当攻击者能恶意地把设备时间设到**未来**的某些时刻、把这些时刻产生的验证码收集起来、等真实世界赶上后再回放时，一个安全的服务器时间基准是不够的。他们把这种攻击命名为**前向重放（forward-replay）攻击**。

他们的引入故事平实得有些好笑：两位作者是某款有"等待恢复体力"计时器的游戏的玩家，为了立刻回满体力，直接把手机时钟往前调。论文随即提出那个显而易见的问题——同样这套时钟操作，能不能用来绕过认证？答案是能，而且在一部未 root 的普通安卓手机和三个真实 App 上演示成功了。

## 2. TOTP 的基础，以及它为何允许这种攻击

TOTP 把 HOTP（RFC 4226）里递增的计数器换成一个由时钟导出的计数器。设 $X$ 为时间步长（秒，默认 30），$T_{0}$ 为计数的基准时刻（默认 0），喂给 HOTP 的值是

$$
T = \left\lfloor \frac{\text{当前 Unix 时间} - T_{0}}{X} \right\rfloor,
\qquad \text{TOTP}(K, T) = \text{HOTP}(K, T).
$$

整个方案都是**时间局部**的：$T$ 只是设备时钟的函数，密钥 $K$ 共享且固定，验证码是 $K$ 与 $T$ 的纯函数。因此，只要掌握密钥并控制时钟，攻击者就能算出**任意未来时间步**的验证码——不需要与服务器交互，不需要窃听，也不需要位于网络路径上。

验证端有三条性质（本意都是可用性特性）共同使前向重放变得可行：

- **服务器不知道验证码是何时生成的。** RFC 6238 说得很直白："当一个 OTP 到达验证系统时，它并不知道客户端生成该 OTP 的确切时间戳。" 验证只是拿收到的验证码与服务器*在收到时刻*愿意接受的时间步做比对，而不是核查其来源时间。
- **接受窗口比一个时间步更宽。** 为了吸收网络延迟，RFC 6238 建议也接受上一个时间步生成的验证码——"最多允许一个时间步作为网络延迟"。论文对本章的注释也表达了同一点：服务器可以接受落在延迟窗口内的、过去时刻生成的验证码，而实践中一般只允许一个时间步。以 30 秒时间步计，这把每个验证码的可用寿命拉宽到大约一分钟。
- **"一次性"只在成功验证之后才被强制。** RFC 6238 要求：某个验证码第一次验证成功后，验证方**不得**再接受它的第二次尝试。这能阻止一个验证码被用两次，却完全阻止不了它被用**一次**——而一次就够前向重放用了。

净效果是：把窗口放宽到约 60 秒，再以一分钟为粒度去采样设备时钟，就能得到"每一分钟一个"的验证码，而每一个都会在它对应的那一分钟真的到来时被接受一次。

## 3. 安全分析与实验

### 3.1 攻击流程：提前生成，延后使用

攻击是一个很短的序列：

1. **获得接触**：在一段有限时间内接触设备——手动接触（物理接触）或通过恶意 App。
2. **激活**受害者的 TOTP 认证器 App，让它显示验证码。
3. **把时钟往前推**：把设备日期/时间设为一系列未来时刻 $\{t_{1}, t_{2}, \dots, t_{n}\}$。
4. **读取并记录**：对每个时刻记下显示的验证码，形成一串有效的"时间戳–验证码"对 $\{(t_{1}, \text{OTP}_{1}), \dots, (t_{n}, \text{OTP}_{n})\}$。
5. **回放**：当服务器时钟到达每个 $t_{i}$ 时，提交 $\text{OTP}_{i}$；服务器看到的是一个对其当前时间步有效的验证码，于是接受。

由于验证码只与服务器的*当前*时间步比对，攻击者从不需要改动服务器时钟，也不必坐在网络路径上。它真正需要的是在设备上相当强的位置，可归纳为三项能力：**把时间往前推、截取验证码、把验证码从设备中取出**。

报告给出三种取得该位置的威胁场景：**手动接触**（攻击者短暂实际持有设备）、**恶意 App**（直接安装，或经由一次已经打到手机上的常规攻击性渗透注入），以及**恶意的公共 USB 充电口**（伪装成输入输出设备或网络设备，或用来触达 Android 调试桥 ADB）。一个让攻击难以被察觉的性质是：生成验证码之后，设备可以被恢复到未改动的状态；采集到的验证码不会留下"何时采集"的痕迹，所以受害者和服务器都缺乏"验证码被提前取走了"的明显信号。

### 3.2 与经典重放攻击的区别

针对认证协议的经典重放攻击，是指截获一个*此刻*有效的凭据并立刻使用——截获与使用在时间上紧挨着，攻击者通常位于通信信道上。前向重放恰好相反：它是**提前生成、很久之后使用**，针对的是一个未来才有效的凭据。这些验证码根本不是从信道上偷来的，而是受害者的 App 在一个由攻击者选定的时钟下、在本地算出来的。作者特意造了"forward-replay"这个词，以便与其他"时间旅行"类攻击区分；他们同时把这种攻击与两篇更早的、想法相近的博客报告区分开——一篇针对专用的 TOTP **硬件令牌**（Deeg, SYSS-2021-007），一篇关于回放 TOTP 验证码（Huseynov）。本文的贡献在于把这一想法推广到安卓上普通的 TOTP **App**，并证明它在不做任何操作系统级改动的情况下也能奏效。

### 3.3 安卓上的概念验证

作者开发了一个安卓 App，用于触发生成未来的验证码并记录结果，全程不需要 root，也不做任何系统级改动。所用构件都是安卓上普通且有文档支持的功能：

- **启动认证器**：恶意 App 通过包管理器用认证器的包名取出它的启动 intent，并在自己的清单文件里用一个 `<queries>` 元素声明该包名，从而在安卓的包可见性过滤下仍然可用。
- **改时间**：修改系统时钟通常需要系统应用或 root 权限。作者用安卓的**无障碍服务（Accessibility Service）**绕过这一限制——它被允许像用户亲手操作那样模拟触摸输入，这里就是模仿一个人手动修改"日期与时间"设置。
- **截取验证码**：当 TOTP 显示在屏幕上时会触发无障碍事件，服务随即读取该验证码，存进数据库或文件供之后取出，或直接传出设备。

把它适配到不同 App 只需很小的改动：FreeOTP 需要先点一下验证码区域才会显示验证码；Duo Mobile 不仅有显示验证码的按钮，还自带一个应用层的 30 秒刷新计时器。

该工具在一部完全普通、**未 root 的 Google Pixel 7 Pro（Android 13，2023 年 3 月安全补丁）**上测试，针对 **Google Authenticator**（下载量超过 1 亿）、**FreeOTP Authenticator**（超过 100 万）和 **Duo Mobile**（超过 1000 万）。

最关键的数字结果，是威胁有多具体的一个量化：**作者在约 35 分钟的连续运行中，取得了 Google Authenticator 一整天中每一分钟的 TOTP 验证码。** 一分钟的采样间隔并非随意设定——它既源于手动改时间所能达到的粒度，也源于 RFC 建议把当前和上一个验证码都视为有效，二者合起来"形成一个跨越一分钟的有效验证码窗口"。换言之，大约 1440 个采集到的验证码，就覆盖了未来整整一天的登录；而这只用一次拿着手机的短暂会话就完成了。报告给出了采集过程的图示，正文明确写出了一分钟节奏与约 35 分钟的运行时长。

## 4. 影响、缓解与局限

TOTP 常被当作"安全"的第二因素，而这份声誉很大程度上建立在验证码寿命很短之上。本文的贡献在于指出：短寿命只是**服务器**时钟的性质，一个愿意短暂接触设备的攻击者可以攒下一批未来有效的验证码。这个威胁之所以有说服力，正因为它不需要什么稀奇工具：不需要 root，不需要改系统，不需要攻破服务器，也不需要占据网络位置——只需要那部手机几分钟，和一个看起来正常的 App。

作者列出的缓解措施，一半是抬高接触设备的成本，一半是消除攻击的根因——那个由本地控制的时钟：

- **强锁屏与强密码**，抬高"手动接触"和"恶意 App"两种场景的门槛。
- **强制在线生成验证码并配合密码学同步**，使验证码无法仅凭被篡改的时钟在离线状态下产生。
- **密钥轮换**，一旦种子变更，已采集的验证码就失去价值。
- **当认证器从后台切回前台时弹出生物识别对话框**，让悄无声息的脚本化采集变得困难得多。
- **依赖专用硬件或可信执行环境（trusted execution environment，TEE）来认证验证码**，让被攻陷的应用层无法随意伪造未来验证码。

分析还引出另外两类防御。第一是**在服务端收紧并加固时钟检查**：RFC 6238 建议同时限制验证方允许证明方"失同步"的时间步数（前后都要限），并拒绝接受已经成功验证过的验证码的重复使用。收窄接受窗口能把每个验证码的可用寿命从约一分钟缩到三十秒，记录已用验证码则能防止采集到的验证码被用两次——但两者都**不能封堵**这种攻击，因为每个采集来的验证码只在它对应的未来时刻被用一次。它们抬高攻击成本，却拿不掉攻击能力本身。第二是**把时间同步当作安全特性来对待**：既然整套方案信任证明方的时钟，那么针对时钟本身的攻击就很重要。Malhotra 等人证明，未认证的 NTP 流量可被用来移动客户端时钟；作者则把 NTP 和 NITZ 列为自动化改时钟（取代手工点设置界面）的可行方向。自然的结论是：对高价值账号而言，出路不是把 TOTP 加固，而是从共享密钥、可被钓鱼的验证码转向抗钓鱼的认证器，例如 WebAuthn / passkey（本书第 13 章）。

**作者自述的局限。** 概念验证是一次安卓应用的测量，而非对所有 TOTP 部署的研究；其他平台与其他认证器 App 未做测试。攻击需要在设备上占据相当强的位置（前文三项能力），而且它并不是对 TOTP 密码学的破解——密钥和 HMAC 都未被触动。采集到的验证码必须被保存、并在正确的时刻递送，因此大规模采集既是采集问题，也是物流问题。最后，作者自己的定位是：这一威胁是"被忽视"而非"新出现的"——论文明确归功于更早的相关博客报告，并把自身贡献定位为面向主流 TOTP App 的推广与量化。

<div class="aside">
<p><span class="aside-label">题外话 · 用无障碍服务偷「未来的验证码」</span></p>
<p>这套概念验证跑的是一部完全普通、未 root 的 Google Pixel 7 Pro，也没有做任何系统级改动：作者用安卓的<strong>无障碍服务（Accessibility Service）</strong>去操作手机的「日期与时间」设置——这个服务本来就有权像人一样模拟触摸输入。每拨到一个未来的分钟，Google Authenticator 就把验证码重新画到屏幕上，服务随即读走。如此往复约 35 分钟，就采集齐了整整一天、每一分钟的验证码。作者并不是想说无障碍服务是个漏洞——恰恰相反，它是安卓上一个有正式文档、被设计出来供应用使用的功能；这次攻击从头到尾没用到任何更稀奇的东西。</p>
<p class="aside-source">出处：Bianchi 与 Valeriani，SocialSec 2023 会议报告幻灯片（由会议官网公开托管于 nss2023.cyber.kent.ac.uk）；论文本体在付费墙后。</p>
</div>

## 5. 相关文献

- **RFC 6238, TOTP**（[rfc-editor.org/rfc/rfc6238.txt](https://www.rfc-editor.org/rfc/rfc6238.txt)）——本章分析的标准。其 5.2 节同时给出了攻击所依赖的两条事实：验证方不知道验证码何时生成；最多应允许一个时间步作为网络延迟。第 6 节建议限制前后两个方向的时钟偏移。
- **C. Gilsenan, F. Shakir, N. Alomar, S. Egelman, *Security and Privacy Failures in Popular 2FA Apps*, USENIX Security 2023**（[usenix.org](https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan)）——本书第 6 章覆盖的、对真实 TOTP App 的生态研究。它发现许多流行 App 未能保护好共享密钥、被攻陷的设备会暴露第二因素；Bianchi 和 Valeriani 补上了互补的一问：攻击者上了设备之后，拿这个 App 能做什么。
- **D. Kogan, N. Manohar, D. Boneh, *T/Key: Second-Factor Authentication from Secure Hash Chains*, CCS 2017**（[arXiv:1708.08424](https://arxiv.org/abs/1708.08424)）——本书第 5 章的一种不在服务器保存密钥的基于时间的方案。它是本章的对照面：它去掉了服务端密钥，却仍把验证码绑在时间上，说明"加固 TOTP"是一个设计方向，而不是免费的升级。
- **S. Park, A. Shaik, R. Borgaonkar, J.-P. Seifert, *White Rabbit in Mobile: Effect of Unsecured Clock Source in Smartphones*, SPSM 2016**（[ACM DL](https://dl.acm.org/doi/10.1145/2994459.2994465)）——本文直接引用，说明智能手机上不安全的时钟来源（手动设置、NTP、NITZ、GNSS）如何被操纵。它为前向重放提供了技术前提。
- **A. Malhotra, I. E. Cohen, E. Brakke, S. Goldberg, *Attacking the Network Time Protocol*, NDSS 2016**（[eprint 2015/1020](https://eprint.iacr.org/2015/1020)）——本文亦引用，证明未认证的 NTP 可让网络攻击者移动客户端时钟，包括不易察觉的"小步—大步"偏移。这是加固 TOTP 必须把时间同步本身当作安全属性的原因。
- **M. Deeg, *To the Future and Back: Hacking a TOTP Hardware Token (SYSS-2021-007)***（[blog.syss.com](https://blog.syss.com/posts/syss-2021-007/)）——更早、独立地报告了同一核心想法，对象是专用 TOTP 硬件令牌。Bianchi 和 Valeriani 归功于它，并把技术推广到日常安卓 App。

## 6. 小结与回响

- TOTP 的时间步由**证明方**的本地时钟算出；服务器只把验证码与自己当前接受的时间步比对，无法判断验证码是何时生成的。
- **前向重放攻击**把设备时钟往前推、采集未来各时间步的验证码，等对应时间步真的到来时逐个回放——"提前生成、延后使用"。
- 攻击需要三项能力：把时间往前推、截取验证码、把验证码从设备取出。不需要攻破服务器、不需要网络位置，也不需要 root。
- 它与经典重放不同（经典重放是截获一个当前有效的凭据并立刻使用）；这里验证码是在本地算出来的，从未从信道上偷取，而且在很久之后才使用。
- 在**未 root 的 Google Pixel 7 Pro / Android 13** 上的概念验证针对 **Google Authenticator、FreeOTP 与 Duo Mobile**，仅使用安卓无障碍服务与一个构造的 App。
- 实测结果：在**约 35 分钟**内从 Google Authenticator 采集到**整整一天中每一分钟的验证码（约 1440 个）**；一分钟的节奏来自手动改时间的粒度与 RFC 的"当前步 + 上一步"接受策略（约 60 秒有效窗口）。
- 缓解措施包括抬高接触设备的成本（锁屏、生物识别提示）、消除本地时钟这一根因（在线生成 + 密码学同步、TEE 认证验证码）、密钥轮换，以及收紧/拒绝服务端窗口；最后一类有帮助但封不住缺口，因为每个采集到的验证码只会被使用一次。
- 长远的教训是架构性的：共享密钥、可被钓鱼的第二因素，应当让位于 WebAuthn / passkey 这类抗钓鱼认证器。

**回响。** 第 4 章把时间步当作一个既定的输入交到读者手上：TOTP 默认读到的时钟就是对的，安全考量只问服务器该容忍多大的偏移。本章把这个输入从底座上拿了下来——时钟不是一个假设，而是一个攻击面，而且它握在<strong>证明方</strong>手里，不在服务器手里。这正是全书第二条母题<strong>时间即信任</strong>：谁设定时钟，谁就决定了哪些验证码存在。它也给第四幕的诊断补上了后半段——第 6 章的失效在实现（共享密钥被泄露），本章连实现都没坏：算法原封不动，App 只是照着别人告诉它的时间，做了它本来就被造出来要做的事。走出共享密钥是下一幕的功课（第 13 章）：在那里，认证器面对服务器现给的新鲜挑战做一次签名，而不是拿本地时钟算出一个纯函数式的验证码，因此根本不存在可以提前采集的「未来的验证码」。

## 参考文献

1. G. Bianchi, L. Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication*. 收录于 B. Arief 等编, Security and Privacy in Social Networks and Big Data (SocialSec 2023), LNCS vol. 14097, Springer, 2023, pp. 109–126. DOI: https://doi.org/10.1007/978-981-99-5177-2_7
2. G. Bianchi, L. Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication*（会议报告）. NSS-SocialSec 2023, University of Kent, Canterbury, UK, 2023 年 8 月. https://nss2023.cyber.kent.ac.uk/presentations/6-3.pdf
3. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, 2011 年 5 月. https://www.rfc-editor.org/rfc/rfc6238.txt
4. D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm*. RFC 4226, IETF, 2005 年 12 月. https://www.rfc-editor.org/rfc/rfc4226.txt
5. H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message Authentication*. RFC 2104, IETF, 1997 年 2 月. https://www.rfc-editor.org/rfc/rfc2104.txt
6. D. M'Raihi, J. Rydell, S. Bajaj, S. Machani, D. Naccache. *OCRA: OATH Challenge-Response Algorithm*. RFC 6287, IETF, 2011 年 6 月. https://www.rfc-editor.org/rfc/rfc6287.txt
7. C. Gilsenan, F. Shakir, N. Alomar, S. Egelman. *Security and Privacy Failures in Popular 2FA Apps*. USENIX Security 2023. https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan
8. D. Kogan, N. Manohar, D. Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains*. ACM CCS 2017, pp. 983–999. https://arxiv.org/abs/1708.08424
9. S. Park, A. Shaik, R. Borgaonkar, J.-P. Seifert. *White Rabbit in Mobile: Effect of Unsecured Clock Source in Smartphones*. 收录于 Proceedings of the 6th Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM), 2016, pp. 13–21. https://dl.acm.org/doi/10.1145/2994459.2994465
10. A. Malhotra, I. E. Cohen, E. Brakke, S. Goldberg. *Attacking the Network Time Protocol*. NDSS 2016. https://eprint.iacr.org/2015/1020
11. M. Deeg. *To the Future and Back: Hacking a TOTP Hardware Token (SYSS-2021-007)*. SYSS Tech Blog, 2021. https://blog.syss.com/posts/syss-2021-007/
12. E. Huseynov. *TOTP Replay Attack — Yubikey et al.* Medium. https://medium.com/@eminhuseynov_37266/totp-replay-attack-yubikey-et-al-adde8e8c62d3
13. V. Iovino, S. Vaudenay, M. Vuagnoux. *On the Effectiveness of Time Travel to Inject COVID-19 Alerts*. CT-RSA 2021, LNCS vol. 12704, pp. 422–443. https://eprint.iacr.org/2020/1393
14. L. C. Meier. *On Security Against Time Traveling Adversaries*. IACR Cryptology ePrint Archive, Report 2022/1148. https://eprint.iacr.org/2022/1148
15. C. Ozkan, K. Bicakci. *Security Analysis of Mobile Authenticator Applications*. ISCTURKEY 2020, pp. 18–30. IEEE.
16. P. Polleit, M. Spreitzenbarth. *Defeating the Secrets of OTP Apps*. 2018, pp. 76–88. IEEE.
17. H. Sun, K. Sun, Y. Wang, J. Jing. *TrustOTP: Transforming Smartphones into Secure One-Time Password Tokens*. ACM CCS 2015, pp. 976–988. https://dl.acm.org/doi/10.1145/2810103.2813679
18. Android Developers. *AccessibilityService* 参考文档. https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
19. J. Selvi. *delorean*（时间操纵工具）. https://github.com/jselvi/delorean

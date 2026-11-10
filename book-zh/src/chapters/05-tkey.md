# T/Key：来自安全哈希链的第二因素认证

<div class="source-card">
<p><strong>本章文献：</strong> Dmitry Kogan, Nathan Manohar, Dan Boneh. <em>T/Key: Second-Factor Authentication From Secure Hash Chains</em>. ACM CCS 2017, pp. 983–999. <a href="https://acmccs.github.io/papers/p983-koganA.pdf">原文 PDF</a> · <a href="https://arxiv.org/abs/1708.08424">arXiv:1708.08424</a></p>
<p><strong>一句话：</strong> 一个基于时间的动态口令方案，服务器端完全不存任何秘密——它只保留哈希链上的一个值——并且论文证明它的破解难度与求逆一次哈希函数几乎相同。</p>
</div>

<div class="hook">
2011 年 RSA Security 被攻破时，损失并没有留在 RSA 内部——论文援引这一事件，指出厂商被攻陷后，其客户接连遭到入侵。TOTP 的服务器是一块同样诱人的靶子：那把能算出每个用户 6 位验证码的密钥，手机上有一份，服务器上也有一份；于是一次入侵就能同时拿到所有账号的第二因素，而且这些验证码明天照样有效。本章讲的正是另一种方案——它把共享密钥整个从服务器上取走，代价又是什么。
</div>

## 1. 背景与问题

TOTP（RFC 6238）之所以能工作，是因为手机和服务器共享同一把密钥 $k$，双方对同一时间步 $t$ 计算 $\mathrm{HMAC}(k,(t-t_{0})/I)$。这把共享密钥正是该方案的结构性弱点：服务器必须明文保存 $k$，否则无法校验用户输入的 6 位口令。因此一次服务器入侵就会同时泄露系统内所有用户的第二因素。论文援引 2011 年 RSA SecurID 被攻破一事作为典型：厂商被攻陷后，其客户接连遭到入侵。

S/KEY（RFC 1760）走的是相反的取舍。客户端取一个随机种子，把它连续哈希 $k$ 次，只把最终值 $y_{0} = h^{(k)}(x)$ 交给服务器。第 $i$ 次认证时客户端出示 $y_{i} = h^{(k-i)}(x)$，服务器只需算**一次**哈希，与已存的值比对即可。服务器始终不知道种子，其数据库对攻击者毫无价值。但 S/KEY 带来论文明确指出的三个问题：

- 口令在未被使用之前一直有效，被窃取后仍可长期使用；而且如果服务器把计数器值下发给客户端（S/KEY 与更新的 OPIE 都这么做，为的是让客户端无需保存状态），冒充服务器的攻击者就能发起所谓的「小 $n$ 攻击」，从客户端套出未来的一次性口令。
- 链条的每一步都在迭代**同一个**哈希函数 $h$。Håstad 与 Näslund 证明，此时求 $k$ 次迭代的原像比求单次 $h$ 的原像大约容易 $k$ 倍（即论文的定理 4.1，下文复述）。而链条越长，这个损失越大。
- 若把 S/KEY 改成基于时间（这正是解决第一个问题的办法），链长就必须与**总运行时间**成比例，而不是与支持的登录次数成比例。以 30 秒为一个时间步，两年的链条需要约两百万个节点，上述的 $k$ 倍安全损失也随之放大。

T/Key 的目标是把两种方案各自的优点合到一起，同时去掉两者的缺点：像 TOTP 一样口令是时间受限的，同时像 S/KEY 一样服务器不存秘密。它保留长链条（这是基于时间的必然要求），但通过**从不重复使用同一个哈希函数**来修补安全损失。

## 2. 核心构造

**公开参数。** 口令长度 $n$（比特）、时间片长度 $I$（秒）、以及最大支持认证时长 $k$（以长度 $I$ 的片数计）。使用一个公开哈希函数 $H:\{0,1\}^{m}\to\{0,1\}^{m}$，其中 $m \ge n+s+c$，$s$ 为盐（salt）长度，$c$ 为表示时间所需的比特数。论文给出的典型取值为 $n = 130$、$s = 80$、$c = 32$、$m = 256$、$k = 2\times10^{6}$、$I = 30$ 秒。

**域分离（domain separation）。** 借助同一个公开的 $H$ 与初始化时刻 $t_{\text{init}}$，可以诱导出 $k$ 个**相互独立**的哈希函数 $h_{1},\dots,h_{k}:\{0,1\}^{n}\to\{0,1\}^{n}$：

$$h_{i}(x) = H\big(\langle t_{\text{init}} + k - i\rangle_{c} \;\Vert\; \text{id} \;\Vert\; x\big)\big|_{n},$$

其中 $\langle t\rangle_{c}$ 表示 $t$ 的 $c$ 比特编码，$\Vert$ 表示拼接，末尾的 $n$ 下标表示只保留 $H$ 输出的 $n$ 比特前缀。把步序号和随机盐 `id` 拼进输入，就让每个 $h_{i}$ 实际上成为不同的函数——这正是消除 S/KEY 那 $k$ 倍损失的机制。由于所有输入长度相同，该构造不会遭受长度扩展攻击，因此直接用 SHA-256 即可，无需改用 HMAC。

**初始化（只由客户端发往服务器）。** 客户端选取均匀随机的密钥 $sk \in \{0,1\}^{n}$ 与随机盐 $\text{id} \in \{0,1\}^{s}$，记下初始化时刻 $t_{\text{init}}$，并计算

$$p_{\text{init}} = h_{k}\big(h_{k-1}\big(\cdots h_{1}(sk)\cdots\big)\big).$$

把 $(p_{\text{init}}, \text{id})$ 发给服务器；服务器将 $p_{\text{init}}$ 存为 $p_{\text{prev}}$、把 $t_{\text{init}}$ 存为 $t_{\text{prev}}$。客户端自己保留 $sk$，它是整个系统中唯一的秘密。

**认证。** 记 $t_{\max} = t_{\text{init}} + k$。在较晚的时刻 $t \in (t_{\text{init}}, t_{\max}]$ 认证时，客户端计算

$$p_{t} = h_{t_{\max}-t}\big(h_{t_{\max}-t-1}\big(\cdots h_{1}(sk)\cdots\big)\big),$$

当 $t = t_{\max}$ 时直接取 $p_{t} = sk$。注意索引的方向：种子 $sk$ 在链条的一端（时刻 $t_{\max}$），服务器保存的 $p_{\text{init}}$ 在另一端（时刻 $t_{\text{init}}$），随时间推移，客户端从近服务器的一端逐步走向自己种子所在的一端，披露的点**越来越接近种子**。

**验证。** 服务器拿到声称的口令 $p$ 与当前计数器值 $t > t_{\text{prev}}$ 后，对 $p$ 连续施加哈希，把它推进到此前保存的节点：

$$p_{\text{prev}}^{\prime} = h_{t_{\max}-t_{\text{prev}}}\big(\cdots h_{t_{\max}-t+1}(p)\cdots\big).$$

若 $p_{\text{prev}}^{\prime} = p_{\text{prev}}$ 则接受，并把 $p_{\text{prev}} \leftarrow p$、$t_{\text{prev}} \leftarrow t$。这里正是 T/Key 与 S/KEY 在开销上的差别所在：服务器要计算 $t - t_{\text{prev}}$ 次哈希，即距上次成功登录经过了多少个时间步——而不是一次哈希。用户登录频繁时这很便宜，登录间隔很长时会逼近 $k$。

**重新初始化与时钟。** 链条有限，$k$ 个时间片用完后客户端必须开启新链。重新初始化与认证同样是单向的：客户端生成新的 $sk$ 与盐，把新的 $p_{\text{init}}$ 发给服务器，服务器无需回传任何东西。取 $I = 30$ 秒、$k = 2\times10^{6}$ 时，一条链可用约两年，在现代手机上初始化不到 15 秒。论文认为这不构成主要限制，因为密码学界本就建议按一到两年的「密码周期」（cryptoperiod）轮换密钥，而且与 TOTP 的注册过程不同，该初始化过程对被动窃听者是安全的。与 TOTP 一样，双方时钟必须同步；服务器可以允许口令在若干早先的时间步上被接受，并把 $t_{\text{prev}}$ 更新为实际验证成功的那一步。

## 3. 安全分析

**威胁模型。** 攻击者可以反复入侵服务器，取走验证口令所需的全部信息；他可以在自己选定的时刻收集多个有效口令；他也可以自行选择发起冒充的时机。由于伪造必须发生在所有已见口令**之后**，这恰好就是哈希链求逆问题。

**为何复用同一个函数是致命的。** 论文先复述 Håstad–Näslund 的结论。对随机函数 $h:[N]\to[N]$（$N = 2^{n}$）以及 $2k \le T \le N/k$，存在一个只做 $T$ 次预言机查询、就能以概率 $\Omega(Tk/N)$ 求 $k$ 次迭代原像的算法——相比求逆单次 $h$，安全损失是 $k$ 的乘积因子。

**为何独立函数几乎恢复安全性。** 当 $h_{1},\dots,h_{k}$ 是 $\{0,1\}^{n}$ 上相互独立的随机函数时，论文证明（定理 4.2）任何做 $T$ 次查询的算法满足

$$\Pr\big[h_{k}\big(A(h_{[1,k]}(x_{0}))\big) = h_{[1,k]}(x_{0})\big] \le \frac{2T+3}{N}.$$

推论 4.3 把结论推广到「猜出整条链的原像」，给出上界 $\frac{2T+2k+1}{N}$。证明的思路是统计那些与真实链条「碰撞」的查询，用延迟判决原理（principle of deferred decision）逐次分析，最后得到一个可望远镜化的乘积。关键对比在于因子：复用同一函数要付出 $k$ 倍的代价，而使用独立函数只付一个常数因子（约 2）。该上界在某种意义上是最优的：不能指望得到 $O(T/(kN))$，因为每次迭代都会压缩像集、额外制造碰撞，反而给攻击者提供便利。

**完整方案的安全性。** 在随机预言机模型下，定理 4.6 给出敌手在形式化博弈（定义 4.4 与攻击博弈 4.5：把验证方状态交给敌手，且口令查询的时间必须单调递增）中的优势上界：

$$\mathrm{Adv}_{A} \le \frac{2T+2k+1}{2^{n}}.$$

**具体参数。** 要让 T/Key 与 $\lambda$ 比特的随机函数一样安全，取 $n = \lambda + 2$ 即可：在典型 $k$ 下上界约为 $4T / 2^{\lambda+2}$。面向标准的 128 比特安全目标，这要求 130 比特的口令——这就是为什么应用无法显示 6 位数字。

**预处理攻击。** 最后一节放弃了「$h$ 是新随机函数」的假设，允许敌手在看到挑战之前，把**公开**函数（SHA-256）预处理成一个建议串（advice string）。不加盐时，论文把成功概率限制在 $(ST/N)^{2/3}$；当使用长度为 $n$ 的盐（取盐空间 $M = N$）后，这一上界降到 $(T/N)^{2/3}$，形式化地由时空下界 $T(1 + S/M) \ge \tilde\Omega(\epsilon^{3/2}N)$（定理 8.2）给出。换言之，给哈希函数加盐可以抵消预处理攻击者的优势。作者明确留下两个未解缺口：一是对成功概率 $\epsilon$ 的依赖很可能不是最优的；二是该定理只界定了「求逆整条链」，而安全博弈需要更强的结论——对手可以选择链条的任意一个**后缀**来求逆。

**作者列出的非威胁。** 论文明确不把手机或笔记本上的恶意软件、笔记本到服务器之间（受 TLS 保护）的中间人、以及在线钓鱼纳入威胁范围；其中钓鱼是任何「与手机单向通信」方案的固有代价，只是短暂的有效窗口让被窃口令的使用具有时间敏感性。

<div class="aside">
<p><span class="aside-label">题外话 · 工程上的量级</span></p>
<p>S/KEY 在现实里的链条很短，通常只有 500 到 1000 节，用完就得让用户重新初始化。T/Key 把链条从「按登录次数」改成「按时间」，于是默认链长是两百万节——按 30 秒一片算大约两年——而在现代手机上初始化这样一条链只要不到 15 秒。这两个数量级的差距正是设计的关键：链条再长，也不再用安全性来买单，因为没有任何一个哈希函数被重复使用。</p>
<p class="aside-source">出处：RFC 2289（S/KEY 链长的现实取值）；Kogan、Manohar、Boneh, CCS 2017（典型链长 2 × 10⁶、初始化不足 15 秒）。</p>
</div>

## 4. 代价、实现与局限

客户端当然不能每次都从头重算两百万节点的链条。它改为保存若干「检查点」（checkpoint，也叫 pebble）。由于登录间隔可能长达数月，这里要解决的不是「一次前进一格」，而是「快速跳到当前时间所对应的那一点」。既有的顺序遍历方案（Coppersmith–Jakobsson、Jakobsson 等）在这里优化的是错误的目标：它们假设链条被顺序遍历，并把重排 pebble 的开销计入成本；而 T/Key 只关心口令生成的延迟，把重排检查点当作后台的空闲工作，不计入成本。

把 $q$ 个检查点放在最优化期望生成代价的位置上，归结为解一个小型方程组；论文还给出一个递归变体，每次在某个子区间里最优地放一个检查点。若把登录建模为泊松过程（间隔服从指数分布，$p(t) = \lambda e^{-\lambda t}$），可以通过 Lambert-W 函数得到闭式解：区间 $[a,b]$ 内的最优检查点位置为

$$x = \frac{-W\big(e^{\lambda(x-a)+1}\big)}{\lambda} + b + \frac{1}{\lambda}.$$

再额外加几个检查点，就可以把最坏情况也限制住。

实测性能（130 比特口令、30 秒时间片、20 个混合检查点；客户端为三星 Galaxy S7，服务器为 2.6 GHz i7 上的 Linux PAM 模块）：

| 认证周期 | 平均登录间隔 | 初始化（秒） | 口令生成均值（秒） | 口令生成最坏（秒） | 验证（秒） |
|---|---|---|---|---|---|
| 1 年 | 1 周 | 7.5 | 0.3 | 0.6 | 0.4 |
| 2 年 | 2 周 | 14 | 0.5 | 0.9 | 0.8 |
| 4 年 | 1 个月 | 28 | 0.8 | 1.6 | 1.6 |

论文认为初始化几秒、生成与验证亚秒级都是可接受的。作为与 TOTP 的对比，论文表 1 在 $2^{128}$ 安全级别下列出：S/KEY——服务器不存秘密、非时间受限、无同级可比长度；TOTP——服务器存秘密、时间受限、20 比特；数字签名（ECDSA/EdDSA）——服务器不存秘密、时间受限、512 比特；T/Key——服务器不存秘密、时间受限、130 比特。

**口令编码。** 130 比特无法敲成 6 位数字，因此 Android 实现把口令编码成 $21\times21$ 的二维码，由笔记本摄像头扫描；相比之下 ECDSA 的 512 比特令牌需要更密的 $33\times33$ 二维码。对没有摄像头的设备，还提供词表编码：2048 词表对应 12 个单词，4096 词表对应 11 个单词。

**实现。** 原型在 Google Authenticator 上做了扩展——同时改了 Android 应用与 Linux PAM 模块，可作为其直接替代。具体地，对 $0 \le i < 2^{32}$ 取 $h_{i}(x) = \mathrm{SHA\text{-}256}(\langle i\rangle_{32} \Vert \text{id} \Vert x)|_{130}$，盐为 80 比特，时间片 30 秒、以 UNIX 纪元为起点，默认链长 $2^{21}$。

**局限。** 作者承认：口令远长于 TOTP（这是「服务器被攻破也不泄密」的代价）；需要定期重新初始化，且用户离线过久会导致链过期；时钟必须同步；服务器端的验证开销随距上次登录的间隔增长。论文还建议用能模拟键盘的 USB 令牌（如 YubiKey）作为合适载体——它既能敲入长口令，又能把种子保存在硬件里。

## 5. 相关文献

- **Leslie Lamport, 1981.** *Password Authentication with Insecure Communication*, CACM 24(11):770–772。基于哈希链的一次性口令的源头，T/Key 是对这一思想的直接现代化。([链接](https://dl.acm.org/doi/10.1145/358790.358797))
- **Neil Haller, 1995.** *The S/KEY One-Time Password System*, RFC 1760。Lamport 方案的实际部署版本，也是 T/Key 明确要改进的起点，其缺点（永久有效、小 $n$ 攻击、哈希复用）正是 T/Key 要解决的。([链接](https://www.rfc-editor.org/rfc/rfc1760))
- **M'Raihi, Machani, Pei, Rydell, 2011.** *TOTP: Time-Based One-Time Password Algorithm*, RFC 6238。T/Key 想要取代、同时要去掉其服务器端存储秘密的方案。([链接](https://www.rfc-editor.org/rfc/rfc6238))
- **Johan Håstad, Mats Näslund, 2007.** *Practical Construction and Analysis of Pseudo-Randomness Primitives*, J. Cryptology 21(1)。证明把同一哈希函数迭代 $k$ 次会让求逆容易约 $k$ 倍——即论文复述为定理 4.1、并用域分离化解的结果。([链接](https://doi.org/10.1007/s00145-007-9009-3))
- **Yih-Chun Hu, Markus Jakobsson, Adrian Perrig, 2005.** *Efficient Constructions for One-way Hash Chains*, ACNS'05。提出 Sandwich chain 与 Comb Skipchain 以加速验证，但要求证明方额外提供数值，会加长 T/Key 的口令，故不适用。([链接](https://doi.org/10.1007/11496137_29))
- **Don Coppersmith, Markus Jakobsson, 2003.** *Almost Optimal Hash Sequence Traversal*, FC'03（另有 Jakobsson, *Fractal Hash Sequence Representation*, ISIT 2002）。pebbling 与时空遍历这一脉络，T/Key 有意改变了其优化目标，因为它的登录是稀疏而不规则的，而非顺序的。([链接](https://doi.org/10.1007/3-540-36504-4_8))
- **Yevgeniy Dodis, Siyao Guo, Jonathan Katz, 2017.** *Fixing Cracks in the Concrete: Random Oracles with Auxiliary Input, Revisited*, EUROCRYPT'17。T/Key 的预处理上界所依赖的结果，说明加盐能限制预计算（参见 Hellman 1980 与 Oechslin 2003 的彩虹表）。([链接](https://doi.org/10.1007/978-3-319-56614-6_16))
- **Ercan Uysal 等, 2023.** *P/Key: PUF based second factor authentication*, PLOS ONE。直接的后继工作，引入物理不可克隆函数（PUF），以摆脱 T/Key 中「可用口令数量受链长约束」的限制。([链接](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0280181))
- **Xiaojun Yin 等, 2020.** *An Efficient Two-Factor Authentication Scheme Based on the Merkle Tree*, Sensors。在 T/Key 基础上用 Merkle 树构造出大量一次性口令，针对的同样是链耗尽与生成开销这两个限制。([链接](https://pmc.ncbi.nlm.nih.gov/articles/PMC7599477/))

## 6. 小结与回响

- TOTP 在手机与服务器两端都存共享密钥，服务器一旦被攻破，全部用户的第二因素尽失。S/KEY 去掉了服务器秘密，但口令永久有效、存在「小 $n$ 攻击」，并因复用同一哈希函数而损失 $k$ 倍安全性。
- T/Key 同时做到「基于时间」与「服务器不存秘密」。服务器只保存链上的一个值 $p_{\text{prev}}$ 与一个时间戳 $t_{\text{prev}}$，种子 $sk$ 只在客户端。
- 域分离把同一个公开哈希 $H$ 变成 $k$ 个独立函数 $h_{i}(x) = H(\langle t_{\text{init}}+k-i\rangle_{c} \Vert \text{id} \Vert x)|_{n}$，这是消除 $k$ 倍损失的关键一步；又因输入定长，天然免于长度扩展攻击、无需 HMAC。
- 认证披露的是按时间索引的链元素，服务器把新口令向前哈希到已存节点来验证；服务器代价是 $t - t_{\text{prev}}$ 次哈希而非一次，随距上次登录的时间增长。
- 随机预言机模型下，做 $T$ 次查询的敌手优势至多 $(2T+2k+1)/2^{n}$。取 $n = \lambda + 2$，故 128 比特安全需要 130 比特口令。
- 使用独立函数时求逆只损失常数因子（约 2），而复用同一哈希要损失 $k$ 倍；该上界近乎最优，链上的碰撞使 $O(T/(kN))$ 不可能成立。
- 预处理攻击（Hellman 式）靠加盐化解：使用 $n$ 比特盐后，成功概率上界由 $(ST/N)^{2/3}$ 降为 $(T/N)^{2/3}$。论文对 $\epsilon$ 依赖与「链后缀求逆」两处明确留作未解问题。
- 检查点在泊松登录模型下达到近乎最优的生成开销，并有 Lambert-W 闭式解；实测两年链的初始化不到 15 秒，生成与验证亚秒级，代价是口令变长——130 比特，以二维码或词表呈现。

**回响。** T/Key 是全书主线的转折点——它是**第二次把秘密从服务器上拿走**。第 1 章 Lamport 第一次这么做，服务器只留哈希链上的一个值；第 2 章的 S/KEY 把这套做法真正部署出去，却让每个口令在被使用之前一直有效。到了第 3、4 章的 HOTP 与 TOTP，为了好用，共享密钥又被请回了服务器——而本章正是把这个决定重新翻转过来。代价写得很清楚：口令从 6 位数字变成 130 比特，需要周期性重新初始化，验证开销随距上次登录的间隔增长，而且依赖双方时钟同步。它换回的是 Lamport 那种「服务器数据库被拿也不泄密」，而不是 Lamport 那种短口令。而 T/Key 这一回依赖的时钟，本身又是一个攻击者能够着手的假设——这正是第 7 章要接住的线索。

## 参考文献

1. Dmitry Kogan, Nathan Manohar, Dan Boneh. *T/Key: Second-Factor Authentication From Secure Hash Chains.* ACM CCS 2017, pp. 983–999. https://acmccs.github.io/papers/p983-koganA.pdf · https://arxiv.org/abs/1708.08424
2. Leslie Lamport. *Password Authentication with Insecure Communication.* Communications of the ACM 24(11):770–772, 1981. https://doi.org/10.1145/358790.358797
3. Neil Haller. *The S/KEY One-Time Password System.* RFC 1760, IETF, 1995. https://www.rfc-editor.org/rfc/rfc1760
4. David M'Raihi, Salah Machani, Mingliang Pei, Johan Rydell. *TOTP: Time-Based One-Time Password Algorithm.* RFC 6238, IETF, 2011. https://www.rfc-editor.org/rfc/rfc6238
5. David M'Raihi, Mihir Bellare, Frank Hoornaert, David Naccache, Ohad Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm.* RFC 4226, IETF, 2005. https://www.rfc-editor.org/rfc/rfc4226
6. Johan Håstad, Mats Näslund. *Practical Construction and Analysis of Pseudo-Randomness Primitives.* Journal of Cryptology 21(1):1–26, 2007. https://doi.org/10.1007/s00145-007-9009-3
7. Yih-Chun Hu, Markus Jakobsson, Adrian Perrig. *Efficient Constructions for One-way Hash Chains.* ACNS 2005, pp. 423–441. https://doi.org/10.1007/11496137_29
8. Don Coppersmith, Markus Jakobsson. *Almost Optimal Hash Sequence Traversal.* Financial Cryptography 2003, pp. 102–119. https://doi.org/10.1007/3-540-36504-4_8
9. Markus Jakobsson. *Fractal Hash Sequence Representation and Traversal.* IEEE ISIT 2002. https://doi.org/10.1109/ISIT.2002.1023709
10. Vipul Goyal. *How To Re-initialize a Hash Chain.* Cryptology ePrint Archive, Report 2004/097. https://eprint.iacr.org/2004/097
11. Yevgeniy Dodis, Siyao Guo, Jonathan Katz. *Fixing Cracks in the Concrete: Random Oracles with Auxiliary Input, Revisited.* EUROCRYPT 2017, pp. 473–495. https://doi.org/10.1007/978-3-319-56614-6_16
12. Martin Hellman. *A Cryptanalytic Time-Memory Trade-Off.* IEEE Transactions on Information Theory 26(4):401–406, 1980. https://doi.org/10.1109/TIT.1980.1056220
13. Philippe Oechslin. *Making a Faster Cryptanalytic Time-Memory Trade-Off.* CRYPTO 2003, pp. 617–630. https://doi.org/10.1007/978-3-540-45146-4_36
14. Ralph C. Merkle. *Secrecy, Authentication, and Public Key Systems.* PhD thesis, Stanford University, 1979.
15. Ercan Uysal et al. *P/Key: PUF based second factor authentication.* PLOS ONE 18(1):e0280181, 2023. https://doi.org/10.1371/journal.pone.0280181
16. Xiaojun Yin et al. *An Efficient Two-Factor Authentication Scheme Based on the Merkle Tree.* Sensors 20(9), 2020. https://doi.org/10.3390/s20092518

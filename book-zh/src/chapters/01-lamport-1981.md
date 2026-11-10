# 哈希链一次性口令：Lamport, 1981

<div class="source-card">
<p><strong>本章文献：</strong> Leslie Lamport. <em>Password Authentication with Insecure Communication</em>. Communications of the ACM, 24(11), pp. 770–772, November 1981. DOI: <a href="https://doi.org/10.1145/358790.358797">10.1145/358790.358797</a></p>
<p><strong>一句话：</strong> 把一个口令做成单向哈希链上的一环、让服务器只保存一个值，就能把经由「可被窃听、可被篡改的信道」传输的口令，变成只能用一次的凭证，从而抵挡窃听与重放。</p>
</div>

<div class="hook">
<p>1981 年的一次登录：用户在终端上敲下口令，这条线路上有人顺手把它抄了下来。系统没有任何地方出故障——口令是对的，主机核对通过，登录成功。第二天夜里，抄口令的人把同一串口令再敲一遍，也进去了。链路上跑的每个值都是真的；问题在于，一个真的值可以被用第二次。</p>
</div>

## 1. 背景与问题

传统的口令认证有一个结构性缺陷：口令本身要在网络上传输。任何能读到流量的人——共享线路上的窃听者、内部运维人员、被攻陷的路由器——都能拿到这个凭证，之后原样再发一次即可登录。在服务器上对口令文件做哈希，能防住服务器数据库被偷，但对线路毫无帮助，因为每次登录明文口令依然要经过网络。

Lamport 这篇 1981 年的论文正是针对这一场景，并为它起了名字。论文已发表的摘要用两句话点明威胁模型与承诺：该方法「即使入侵者能够读取系统的数据、能够篡改或窃听用户与系统之间的通信，也依然安全」，并且「假定存在一个安全的单向加密函数，且可在用户终端的微机上实现」。也就是说，攻击者被**假定具备**三种能力：读取服务器保存的数据、窃听信道、篡改信道上的报文。唯一被假定为不可能的能力，是求单向函数的逆。

由此，设计目标就是直接的：让每一个经过线路的值，对窃听者都无用、被重放时也无效；让被窃取的服务器数据不泄露任何可用口令。

*文献获取情况说明。* 未能找到原文的开放获取版本：ACM 将其放在付费墙后，也未找到合法的免费副本。下文依据的是论文已发表的摘要，以及公开的、描述并注明源自 Lamport 的材料——主要是 RFC 1760（其致谢部分把这一思想归于 Lamport），以及紧贴该论文的 Cornell CS513 课程讲义。比这些来源更具体、更细的论断，正文中会单独标注出处。

## 2. 核心内容：单向哈希链

**单向函数。** 方案假定存在函数 $F$：正向容易计算，求逆则在计算上不可行。给定 $x$，算 $F(x)$ 很便宜；由 $F(x)$ 反推 $x$，在假定的算力下做不到。这就是摘要所说的「安全的单向加密函数」，除此之外不依赖别的假设。

**构造一条链。** 用户选定一个秘密 $s$（种子，seed）和一个整数 $n$（链长），计算

$$x_{0} = s, \qquad x_{i} = F(x_{i-1}) \quad (i = 1, 2, \dots, n).$$

于是 $x_{i} = F^{i}(s)$：第 $i$ 个值，是从种子出发连续做 $i$ 次 $F$。这条链是有方向的：从 $x_{i-1}$ 做一次 $F$ 就得到 $x_{i}$；而从 $x_{i}$ 不做求逆就得不到 $x_{i-1}$。往下标大的方向走容易，往下标小的方向走才是困难方向。

**逆序使用这条链。** 方案恰恰利用这个不对称，让口令沿着攻击者无法前进的方向发出——最「多哈希了几次」的值最先用：

$$x_{n}, \; x_{n-1}, \; x_{n-2}, \; \dots, \; x_{1}.$$

每个口令都比前一个「落后」一次 $F$：用完 $x_{i}$ 后，下一次要发的是 $x_{i-1}$，而 $x_{i-1} = F^{-1}(x_{i})$，需要对 $F$ 求逆。RFC 1760 用起始值 $S$ 表述了同一条规则：「第一个一次性口令是把 $S$ 过一遍安全哈希函数 $N$ 次得到的……下一个一次性口令则是把 $S$ 过 $N-1$ 次得到的。」每登录一次，次数减一。

**服务器端的验证与状态。** 服务器从不保存种子 $s$，每个用户只保存一个值，而且这个值始终「比下一次要接受的口令超前一次 $F$」。收到口令 $v$ 时，服务器只做一次 $F$，然后比较：

$$F(v) \;=\; \text{（已保存的值）}.$$

若相等，$v$ 就是正确的下一个口令；服务器接受它，并把保存值更新为 $v$。RFC 1760 描述的就是这个机制：主机「把传来的一次性口令过一遍安全哈希函数。如果结果与保存的上一个一次性口令相吻合，认证成功，并把刚接受的一次性口令存下来供以后使用」。服务器在初始化时通过带外方式拿到合适的起始值（链的顶端 $x_{n}$，等价地说，比它将接受的第一个口令超前一步）。这个初始值究竟算作第一个口令，还是算作额外领先一步的锚点，只是记账约定；RFC 1760 与 RFC 2289 描述的是同一个机制。

由于保存值在每次成功登录后都会前移，每个口令确实是「一次性」的。

## 3. 安全分析

**窃听。** 设攻击者录下了一次登录，从而得知 $x_{i}$。要在下一次登录时冒充用户，它必须给出 $x_{i-1}$，也就是要算 $F^{-1}(x_{i})$——求单向函数的逆。安全性只压在这一步上。攻击者可以从 $x_{i}$ 顺着算出 $x_{i+1}, x_{i+2}, \dots$，但这些是用户早已用过、服务器也早已丢弃的口令。攻击者能到达的集合，与它需要的集合，互不相交。

**重放。** 任何被接受过的值再用一次都会失败。验证要求传来的值哈希后等于**当前**保存值，而一次登录成功之后保存值已经前移。重放旧口令 $x_{i}$ 时，$F(x_{i}) = x_{i+1}$ 已不再等于保存值，因此被拒绝。

**服务器数据泄露。** 服务器既不保存种子 $s$，也不保存下一个口令，只保存链上的一环——一个用户本来就要发出去的值。读到它并不会给出可用口令，因为要推出下一个仍需对 $F$ 求逆。这正是摘要所说「即使入侵者能读取系统数据也安全」的含义。

**篡改信道。** 被改动过的口令同样会在这「一次 $F$」的检查里失败，因此攻击者无法通过改写流量伪造一个能被接受的口令。方案认证的是「口令值」本身，它自己不提供保密性，也不对抗主动的拒绝服务。论文的模型允许入侵者篡改，而链式检查正是挡住篡改报文得逞的关键。

**一个后续被点明的细节：保护挑战值。** 这个构造有一个后来的分析常特别指出的微妙之处。客户端保存了种子，因此它会对任何挑战「有求必应」地计算链上相应位置的值；而从靠近种子端的一个值出发，顺着迭代 $F$ 就能算出链的其余部分。如果客户端接受了来自未认证来源的挑战（即被要求回答的序号），冒充服务器的攻击者就可以诱导客户端交出一个接近种子的值，从而推出用户还剩的大部分口令。防御办法是：客户端先认证挑战的来源，或者记住自己上次回答的挑战，对跳得过远的挑战一律忽略（Cornell CS513 讲义）。

## 4. 影响与局限

**影响。** 这篇论文是哈希链一次性口令的起点。S/KEY 与后来的 OTP 标准（RFC 1760、RFC 2289）都是对它的直接工程化；这一思路在后续工作中反复出现：同一种「单向函数串联」也构成了 Lamport 自己 1979 年的一次性签名方案、Merkle 的哈希树（1989）、哈希链小额支付、广播认证，以及现代哈希链口令系统 T/Key（2017）。它引入的两个做法沿用至今：服务器上无需保存任何秘密，每个凭证恰好只能用一次。

**局限。**
- *链长有限。* 长度为 $n$ 的链只能支持有限次登录；用尽后必须重新初始化，并把新的锚点安全地交给服务器。这是「不保存可重用秘密」的代价。
- *初始值的分发。* 链顶的值 $x_{n}$（以及每次重初始化后的新锚点）必须经认证信道送达服务器，种子 $s$ 必须在客户端保密。方案是把信任要求「转移」了，而不是消除了。
- *不可回退，难同步。* 保存值只能往前。若某条报文丢失，服务器与客户端可能失步；正确的恢复办法是**向前**跳到新的序号，绝不能重发同一个挑战，否则被截获的响应就能被重放。
- *客户端的状态与信任。* 客户端必须持有种子、知道自己处于链上的位置，并且不能被诱导交出一个靠链尾的值（见上）。
- *只做认证。* 方案不提供数据保密性，也明确不是对抗主动攻击的手段，后出的 RFC 对此都作了强调。

<div class="aside">
<p><span class="aside-label">题外话 · 链背后的人</span></p>
<p>写下这篇论文的 Leslie Lamport，也是 Lamport 逻辑时钟、Paxos 共识协议、面包店算法和 LaTeX 的作者，2013 年获得图灵奖。1981 年的这个口令方案，只是他漫长生涯里很小、很实用的一角。他 1979 年的报告《Constructing Digital Signatures from a One Way Function》用同一种单向函数串成链来为消息签名——这条线一直延伸到今天的后量子哈希签名。</p>
<p class="aside-source">出处：背景知识，非论文内容——2013 年 ACM 图灵奖；L. Lamport, SRI CSL-98, 1979。</p>
</div>

## 5. 相关文献

- **N. Haller, "The S/KEY One-Time Password System," RFC 1760, 1995** —— Lamport 方案的第一套完整工程实现：MD4 哈希链、公开种子、64 位输出与六词编码。 <https://www.rfc-editor.org/rfc/rfc1760.txt>
- **N. Haller, C. Metz, P. Nesser, M. Straw, "A One-Time Password System," RFC 2289, 1998** —— 从 S/KEY 演进而来的标准化 OTP 系统；增加了 SHA-1 支持、词编码里的校验和，以及对「竞速攻击」的明确防御。 <https://www.rfc-editor.org/rfc/rfc2289.txt>
- **D. Kogan, N. Manohar, D. Boneh, "T/Key: Second-Factor Authentication from Secure Hash Chains," CCS 2017** —— 把 S/KEY 现代化：基于时间、服务器不存秘密，并给出「求随机函数哈希链逆」的下界与低内存的遍历算法。 <https://arxiv.org/abs/1708.08424>
- **L. Lamport, "Constructing Digital Signatures from a One Way Function," SRI CSL-98, 1979** —— 同一作者的另一半思想：用单向函数、以「逆向串联」的方式为单条消息签名，是一次性签名的鼻祖。 <https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/>
- **R. C. Merkle, "A Certified Digital Signature," CRYPTO '89, LNCS 435, pp. 218–238** —— 把「串联」推广成哈希树：单个根即可承诺大量一次性密钥；今天在区块链、证书透明日志中仍在使用。 <https://doi.org/10.1007/0-387-34805-0_21>
- **C. Lefevre, B. Mennink, "Permutation-Based Hash Chains with Application to Password Hashing," ePrint 2024/557** —— 对哈希链口令系统（S/Key 与 T/Key）的现代安全性分析，区分离线/在线攻击者，并给出多用户证明。 <https://eprint.iacr.org/2024/557>

## 6. 小结与回响

- 问题：经由不安全信道传输的可重用的口令会被截获并重放；服务器数据库被偷也会泄露口令。
- 工具：单向函数 $F$，正向易算、求逆不可行。
- 构造：哈希链 $x_{i} = F^{i}(s)$，按逆序 $x_{n}, x_{n-1}, \dots, x_{1}$ 使用，使每个口令都是前一个口令「难以计算的」前驱。
- 服务器只保存一个值，用一次 $F$ 验证收到的口令，成功后把保存值更新为刚接受的那个口令。
- 窃听只能拿到已用过的口令，重放会因保存值已前移而失败；服务器上被窃取的值也推不出可用口令。
- 假定的威胁模型：入侵者可读服务器数据、可窃听或篡改信道——但不能求 $F$ 的逆。
- 局限：链长有限且需重初始化、初始值需安全分发、无法向后重新同步、且依赖客户端信任其挑战。
- 遗产：S/KEY、RFC 2289 与 T/Key 的直接源头，也是哈希链签名与 Merkle 树的共同根。

**回响。** 本章是全书那个中心问题的起点：*秘密该放在哪里？* Lamport 的答案是干脆把秘密从服务器上拿走——主机只保存链上的一环，从不保存种子，于是攻击者能偷到的，只是用户本来就要发出去的值。这正是「拿走—放回—再拿走」这条母题的第一次动作。它同时给下一章埋下钩子：一个在纸面上优雅的构造，还要经过工程化——真实的哈希函数、真实的输出长度、真实的人在键盘上敲——才谈得上部署。它也故意留下几个开口：链长有限、锚点必须带外交付、客户端必须被信任去保管种子；这些后面都会一一回来。

## 参考文献

1. L. Lamport. *Password Authentication with Insecure Communication.* Communications of the ACM, 24(11):770–772, November 1981. <https://doi.org/10.1145/358790.358797>
2. N. Haller. *The S/KEY One-Time Password System.* RFC 1760, Bellcore, February 1995. <https://www.rfc-editor.org/rfc/rfc1760.txt>
3. N. Haller, C. Metz, P. Nesser, M. Straw. *A One-Time Password System.* RFC 2289, February 1998. <https://www.rfc-editor.org/rfc/rfc2289.txt>
4. D. Kogan, N. Manohar, D. Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains.* In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (CCS), pp. 983–999, 2017. <https://arxiv.org/abs/1708.08424>
5. L. Lamport. *Constructing Digital Signatures from a One Way Function.* Technical Report SRI-CSL-98, SRI International, October 1979. <https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/>
6. R. C. Merkle. *A Certified Digital Signature.* In Advances in Cryptology — CRYPTO '89, LNCS 435, pp. 218–238, Springer, 1989. <https://doi.org/10.1007/0-387-34805-0_21>
7. C. Lefevre, B. Mennink. *Permutation-Based Hash Chains with Application to Password Hashing.* Cryptology ePrint Archive, Paper 2024/557, 2024. <https://eprint.iacr.org/2024/557>
8. F. B. Schneider. *Authentication — Lamport's One-Time Password Scheme.* Cornell CS513 System Security lecture notes, 2005. <https://www.cs.cornell.edu/courses/cs513/2005fa/NL11Lamport.html>

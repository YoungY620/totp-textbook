# S/KEY 与 RFC 1760：把哈希链一次性口令工程化

<div class="source-card">
<p><strong>本章文献：</strong> Neil Haller. <em>The S/KEY One-Time Password System</em>. RFC 1760, Bellcore, February 1995（Informational 类别）。<a href="https://www.rfc-editor.org/rfc/rfc1760.txt">原文</a>；对照材料为 <a href="https://www.rfc-editor.org/rfc/rfc2289.txt">RFC 2289</a>。</p>
<p><strong>一句话：</strong> RFC 1760 把 Lamport 的思想做成可部署的系统——MD4 哈希链、服务器下发的种子、64 位输出编成六个英文单词、以及一套挑战—应答协议——只用一次性口令，让窃听者截获到的口令无法被重放。</p>
</div>

<div class="hook">
<p>1995 年前后登录一台 UNIX 主机，系统不再向你索要口令。主机只打印一行挑战 `s/key sequence_integer seed`，你要回给它的不是口令短语，而是六个英文短词。旁边的人把这六个词全部抄下来也没有用——下一次登录要的是另外六个。线上跑过的值已经作废，而这条链只有一个方向。</p>
</div>

## 1. 背景与问题

RFC 1760 开篇就点出它的动机：「针对接入 Internet 的计算机系统的一种攻击，是窃听网络连接，以获取合法用户的登录名和口令。被截获的登录名与口令会在稍后被用来进入系统。」S/KEY 系统就是为了对抗这类攻击而设计的，文档称之为*重放攻击*（replay attack）。

它的两个卖点开宗明义。第一，「网络上传输的永远只是一次性口令」，而用户的秘密口令短语（pass-phrase）「任何时候都不会经过网络，包括登录时，以及执行其他需要认证的命令（如 UNIX 的 `passwd`、`su`）时」。第二，「包括被保护主机在内的任何系统上，都无需保存秘密信息」。

适用范围同样说得很清楚。S/KEY「防御的是针对认证子系统的外部被动攻击。它不能阻止网络窃听者获取私密信息，也不针对『内部作案』，或攻击者能够拦截并修改报文流的主动攻击」。换言之，这是针对被动窃听者的认证机制，而不是一条安全信道。

文档对自己的渊源也很坦诚。致谢部分写道：「S/KEY 认证背后的思想最早由 Leslie Lamport 提出。本文所描述的具体系统由 Phil Karn 提出，参考实现也大多由他编写。」因此 RFC 1760 就是 Lamport 1981 年构造的具体化与可交付版本。

## 2. 核心内容

**安全哈希函数。** RFC 1760 把安全哈希函数定义为「正向容易计算、但求逆在计算上不可行」的函数，并把 S/KEY 建立在 MD4 报文摘要算法（Rivest，RFC 1320）之上。文档指出，在 S/KEY 投入使用之后 MD5 才发布，但因为有大量客户端程序已经分发出去，所以继续沿用 MD4；一些站点也基于 MD5 做了功能相当的系统。客户端与主机必须使用同一个函数才能互通。

**64 位口令。** MD4 接受任意长度的比特输入，输出 128 位。S/KEY 的口令只有 64 位：把输出的两个 8 字节半块做异或（exclusive-OR）折叠而来。之所以是 64 位，是因为它「既被认为足够安全，又短到可以手工输入」。

**准备步骤。** 口令短语长度不限，但要与服务器明文下发的*种子*（seed）拼接。把种子与口令短语拼接，可让同一个秘密口令短语服务于多台机器（各用不同的种子），并可通过更换种子安全地回收该口令短语。拼接结果先做哈希，再折叠成 64 位。用伪代码表示（取自 RFC 的代码片段，种子写在前面）：

```text
buf = seed || passphrase
d   = MD4(buf)                # 128 位
S   = fold_to_64(d)           # 两个 8 字节半块做异或
```

**迭代成链。** 一次性口令序列，是把安全哈希函数反复作用于准备值 $S$ 得到的。RFC 1760 说：「第一个一次性口令，是把 $S$ 过一遍安全哈希函数 $N$ 次得到的，$N$ 由用户指定。下一个一次性口令，则是把 $S$ 过 $N-1$ 次得到的。」若用 $H$ 表示哈希、$S$ 表示准备值，口令序列就是 $H^{N}(S), H^{N-1}(S), \dots, H^{1}(S)$，按此顺序使用。每登录一次次数减一，而窃听过某个口令的人「无法生成任何后续口令，因为那需要求哈希函数的逆」。

**人类可读的输出：六个单词。** 64 位不好敲。S/KEY 把这个值转换成「六个短英文单词（每个 1 到 4 个字母）的序列。每个单词取自一本 2048 词的词典；每词 11 位，足以编码所有一次性口令」。标准词典附在 RFC 之后，所有主机与计算器必须使用同一本词典。（RFC 2289 之后又在最后一个词里加入 2 位校验和，并接受十六进制输出作为替代；RFC 1760 本身主要规定六词形式，并让计算器程序把口令直接灌入输入流。）

**挑战与应答。** 主机发出*挑战*（challenge），以固定且机器可识别的格式携带当前参数——序号与种子：

```text
s/key sequence_integer seed
```

客户端拿到挑战与秘密口令短语后，算出（或查表得到）对应的一次性口令并发回。挑战采用标准格式很重要，这样自动化客户端才能识别它、提取参数。

**验证与保存的状态。** 主机维护一个文件——参考实现中为 `/etc/skeykeys`——对每个用户保存上次成功登录所用的一次性口令，或者由 `keyinit` 命令用一条新序列的第一个口令初始化。验证一次登录尝试时，「它把传来的一次性口令过一遍安全哈希函数。如果结果与保存的上一个一次性口令吻合，认证成功，并把刚接受的一次性口令存下来供以后使用」。也就是说：服务器只存一个值，用一次哈希来校验，成功即更新。

**重新初始化。** 因为客户端的迭代次数每次都减一，「到某个时候用户必须重新初始化系统，否则将无法再登录」。`keyinit` 命令允许用户更换秘密口令短语、迭代次数和种子。RFC 指出一个常用做法：把种子的末尾数字加一，并把迭代次数重置「到 500–1000 这个范围」。

**客户端程序。** 参考实现包括 UNIX 与 PC 上的命令行计算器（`key`）、PC 上的常驻内存程序（`ctkey`、`termkey`、`popkey`），以及 Macintosh 与 Windows 的图形界面（`keyapp`）。最自动化的是 `termkey`：它扫描屏幕找出 S/KEY 挑战、提示输入口令短语，再把一次性口令塞进键盘缓冲区。

## 3. 威胁分析

**窃听。** 线路上传输的每个值都是一次性口令，且只要一次性口令过网；口令短语不过网。从被截获的口令无法推出下一个，因为那需要求哈希函数的逆。链的方向保证了窃听只能得到已用过的口令。

**重放。** 每个口令被接受一次后即被取代；服务器的保存值在每次成功后前移，因此被截获的值之后再发来无法匹配。这正是该系统的设计目标。

**字典与穷举。** 秘密在于口令短语，种子是公开的，所以强度取决于口令短语。RFC 1760 建议口令短语「应长于 8 个字符」；RFC 2289 进一步收紧，要求至少 10 个字符，以降低穷举搜索与字典攻击的风险。

**服务器保存值泄露。** 服务器只存最后一个一次性口令、从不存口令短语，因此读到该文件的入侵者学不到任何未来的口令：推出下一个同样需要求哈希的逆。这就是文档所宣传的性质——「任何系统上都无需保存秘密信息」。

**模型之外。** S/KEY 不提供保密性，挡不住「内部作案」，也防不了拦截并修改报文流的主动攻击。RFC 2289 重申了这一点，并建议用 IPsec 对抗会话劫持。

<div class="aside">
<p><span class="aside-label">题外话 · 为什么恰好是六个词</span></p>
<p>64 位的值不好念，S/KEY 就把它拼成六个英文短词，词全部取自已固定的 2048 词词表。2048 不是随便取的：2048 = $2^{11}$，正好每词 11 位，六个词共 66 位，覆盖 64 位的口令绰绰有余。RFC 2289 后来又在最后一个词里放了 2 位校验和，敲错了的口令在发出去之前就能被发现。</p>
<p class="aside-source">出处：RFC 1760（六词、2048 词词表、每词 11 位）与 RFC 2289（末词中的 2 位校验和）。</p>
</div>

## 4. 与 Lamport 的关系及局限

**S/KEY 在 Lamport 之上加了什么。** 底层构造是 Lamport 的：一条逆向使用的单向哈希链，服务器保存单个值、用一次哈希做校验。S/KEY 的贡献在于让它可部署的那些工程决策。它把哈希函数固定下来（MD4，以及后来的 MD5、SHA-1 变体），把输出长度固定下来（64 位，由 MD4 的 128 位折叠而来），并规定了人类编码（取自 2048 词词典的六个单词，互通的前提是共用同一本词典）。它把明文的*种子*提升为一等参数，使一个口令短语可服务多台机器并被安全回收。它还把*迭代次数*做成了用户可见、需要初始化的参数，而不只是一个抽象链长。

**局限。**
- *链长有限。* 一条 $N$ 个口令的序列只支持有限次登录；用尽后必须重新初始化，既中断服务又重复初始化问题。实践中 $N$ 取数百到数千（RFC 举例的范围是 500–1000）。
- *重放窗口与并发——竞速攻击。* RFC 1760 描述了固定的登录次序，对战干扰它的攻击者着墨不多。RFC 2289 正面处理了这个问题：攻击者可以「听到一个一次性口令的大部分、猜出其余部分，然后抢在合法用户之前完成认证」，针对六词形式最后一个词的猜测尤其容易得手。建议的防御是不允许同时进行多个认证会话，并设置超时以防拒绝服务。与之相关的失步问题——响应丢失导致服务器与客户端错位——必须靠把挑战**向前**跳来解决，绝不能重发同一个挑战，否则被窃听过的响应就能被重放。
- *需手工重初始化。* 重初始化要求用户带外地提交一个刚生成的口令；RFC 2289 还要求在每次重初始化时更换种子或口令短语。
- *原语老化。* RFC 2289 警告，MD4 普遍被认为不如 MD5 强，而且支持多种哈希算法的服务器「其安全性只取决于最弱的那种算法」。设计再灵活，安全性也只与所选哈希相当。

## 5. 相关文献

- **L. Lamport, "Password Authentication with Insecure Communication," CACM 24(11), 1981** —— S/KEY 所实现的原始哈希链一次性口令方案；RFC 1760 明确把功绩归于它。 <https://doi.org/10.1145/358790.358797>
- **N. Haller, C. Metz, P. Nesser, M. Straw, "A One-Time Password System," RFC 2289, 1998** —— 取代 RFC 1938、并对 S/KEY 作标准化的 OTP 系统：加入 MD5 与 SHA-1、词编码校验和、十六进制输入、`otp-` 挑战格式，以及竞速攻击防御。 <https://www.rfc-editor.org/rfc/rfc2289.txt>
- **D. Kogan, N. Manohar, D. Boneh, "T/Key: Second-Factor Authentication from Secure Hash Chains," CCS 2017** —— 把 S/KEY 现代化为基于时间、服务器不存秘密的系统，并给出求哈希链逆的下界与低内存的客户端遍历算法。 <https://arxiv.org/abs/1708.08424>
- **D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen, "HOTP: An HMAC-Based One-Time Password Algorithm," RFC 4226, 2005** —— 标准化进程的下一步：基于 HMAC 与计数器的口令，两端各存共享密钥，并规定了限流与重同步要求。 <https://www.rfc-editor.org/rfc/rfc4226.txt>
- **D. M'Raihi, S. Machani, M. Pei, J. Rydell, "TOTP: Time-Based One-Time Password Algorithm," RFC 6238, 2011** —— 把 HOTP 的计数器换成时间步长，就是今天验证器 App 所用的算法；S/KEY 这一脉的直系后代。 <https://www.rfc-editor.org/rfc/rfc6238.txt>
- **R. Rivest, "The MD4 Message-Digest Algorithm," RFC 1320, 1992** —— S/KEY 所依赖的哈希函数，也是 128 位摘要必须被折叠到 64 位的原因。 <https://www.rfc-editor.org/rfc/rfc1320.txt>

## 6. 小结与回响

- RFC 1760（Haller，Bellcore，1995）把 Lamport 的哈希链一次性口令工程化为可部署系统；文档把思想归功于 Lamport，把具体系统归功于 Phil Karn。
- 它针对登录信道上的窃听/重放：网络上只传输一次性口令，口令短语永不经过网络。
- 哈希函数是 MD4（RFC 1320），其 128 位输出被折叠成 64 位口令；在构造链之前，口令短语要与服务器明文下发的种子混合。
- 链为 $H^{N}(S), H^{N-1}(S), \dots$——每登录一次迭代次数减一——64 位结果编成取自共享 2048 词词典的六个单词。
- 协议是挑战—应答：服务器发 `s/key sequence_integer seed`，客户端回以匹配的口令，服务器把回值哈希一次、与保存的上一个口令比对来完成验证。
- 服务器只保存上一个口令——没有口令短语、没有可重用的秘密——因此其存储被攻陷也得不出可用口令；被截获的口令也无法重放。
- 局限：链长有限、需手工重初始化；对「只听了一部分的口令」存在竞速窗口（RFC 2289 用串行化会话修复）；只能向前重同步；且安全性取决于所选哈希的强度。

**回响。** S/KEY 是全书第一个动作被工程化的地方。上一章把秘密从服务器上拿走，这一章展示的是：真要把这个想法做出来，代价是什么——固定的哈希函数、折叠成 64 位的输出、让一个口令短语能服务多台机器的明文种子，以及一套人能通过 telnet 走完的挑战—应答。主机上依然没有可重用的秘密，六词编码又让整套东西真正好用。这是好消息；给后面埋下的钩子则是它的代价：链长有限、只能手工重初始化、只能向前重同步，以及登录过程会信任任何送来挑战的一方。接下来几章会看到，当「好用」把共享密钥重新推回服务器上时会发生什么——那是这条母题的第二次动作。

## 参考文献

1. N. Haller. *The S/KEY One-Time Password System.* RFC 1760, Bellcore, February 1995. <https://www.rfc-editor.org/rfc/rfc1760.txt>
2. L. Lamport. *Password Authentication with Insecure Communication.* Communications of the ACM, 24(11):770–772, November 1981. <https://doi.org/10.1145/358790.358797>
3. N. Haller, C. Metz, P. Nesser, M. Straw. *A One-Time Password System.* RFC 2289, February 1998. <https://www.rfc-editor.org/rfc/rfc2289.txt>
4. D. Kogan, N. Manohar, D. Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains.* CCS 2017, pp. 983–999. <https://arxiv.org/abs/1708.08424>
5. D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm.* RFC 4226, December 2005. <https://www.rfc-editor.org/rfc/rfc4226.txt>
6. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm.* RFC 6238, May 2011. <https://www.rfc-editor.org/rfc/rfc6238.txt>
7. R. Rivest. *The MD4 Message-Digest Algorithm.* RFC 1320, April 1992. <https://www.rfc-editor.org/rfc/rfc1320.txt>
8. N. Haller. *The S/KEY One-Time Password System.* Proceedings of the ISOC Symposium on Network and Distributed System Security, San Diego, February 1994.

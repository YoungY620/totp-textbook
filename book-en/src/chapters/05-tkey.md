# T/Key: Second-Factor Authentication from Secure Hash Chains

<div class="source-card">
<p><strong>Source:</strong> Dmitry Kogan, Nathan Manohar, Dan Boneh. <em>T/Key: Second-Factor Authentication From Secure Hash Chains</em>. ACM CCS 2017, pp. 983–999. <a href="https://acmccs.github.io/papers/p983-koganA.pdf">PDF</a> · <a href="https://arxiv.org/abs/1708.08424">arXiv:1708.08424</a></p>
<p><strong>In one line:</strong> A time-based one-time password scheme whose server stores no secret at all — it keeps only a value from a hash chain — and which is proven about as hard to break as inverting a single hash function.</p>
</div>

<div class="hook">
When attackers broke into RSA Security in 2011, the damage did not stay inside RSA — the paper cites it as a case where compromising the vendor led to follow-on intrusions at its customers. A TOTP server is the same shape of target, because the key that mints every user's six-digit code sits on the server as well as on the phone: one break-in hands over the second factor for every account at once, and the codes still work tomorrow. This chapter is about a scheme that takes the shared secret off the server entirely, and about what that manoeuvre costs.
</div>

## 1. Background and Problem

TOTP (RFC 6238) works because the phone and the server share a secret key $k$ and both compute $\mathrm{HMAC}(k,(t-t_{0})/I)$ for the same time step $t$. That shared key is the scheme's structural weakness: the server must keep $k$ in the clear, or it cannot check the user's six-digit code. One break-in therefore leaks the second factor for every user at once. The paper cites the 2011 RSA SecurID breach, where compromising the vendor led to follow-on intrusions at its customers.

S/KEY (RFC 1760) takes the opposite trade-off. The client hashes a random seed $k$ times and gives only the final value $y_{0} = h^{(k)}(x)$ to the server; to authenticate for the $i$-th time it reveals $y_{i} = h^{(k-i)}(x)$, which the server checks with a single hash. The server never learns the seed, so its database is useless to an attacker. But S/KEY carries three problems the paper calls out:

- A password stays valid indefinitely until used, so a stolen one remains exploitable; and if the server sends the counter value to the client (as S/KEY and OPIE do, to keep clients stateless), an impersonating server can mount a "small $n$" attack and extract a future password.
- Every step iterates the *same* function $h$. Håstad and Näslund showed that inverting the $k$-th iterate is then about $k$ times easier than inverting one call of $h$ (Theorem 4.1 below). A long chain is exactly what this weakens.
- Making S/KEY time-based — the natural fix for the first problem — forces the chain length to be proportional to the *total operating time* rather than the number of logins. At 30-second steps a two-year chain needs about two million links, and the $k$-fold loss grows with it.

T/Key's goal is to keep both good properties and drop both bad ones: passwords are time-limited like TOTP, yet the server stores no secret.

## 2. The Construction

**Public parameters.** Password length $n$ (bits), time-slot size $I$ (seconds), and maximal supported authentication period $k$ (a number of slots of length $I$). One public hash function $H:\{0,1\}^{m}\to\{0,1\}^{m}$ is used for some $m \ge n+s+c$, where $s$ is the salt length and $c$ the number of bits encoding time. Typical values: $n = 130$, $s = 80$, $c = 32$, $m = 256$, $k = 2\times10^{6}$, $I = 30$ seconds.

**Domain separation.** That one $H$, together with the start time $t_{\text{init}}$, induces $k$ *independent* functions $h_{1},\dots,h_{k}:\{0,1\}^{n}\to\{0,1\}^{n}$:

$$h_{i}(x) = H\big(\langle t_{\text{init}} + k - i\rangle_{c} \;\Vert\; \text{id} \;\Vert\; x\big)\big|_{n},$$

where $\langle t\rangle_{c}$ is the $c$-bit encoding of $t$, $\Vert$ is concatenation, and the $n$ subscript on the right keeps only the $n$-bit prefix of $H$'s output. Feeding the step index and a random salt `id` into the input makes each $h_{i}$ effectively a different function, which removes S/KEY's $k$-fold loss. Equal-length inputs also resist length-extension attacks, so plain SHA-256 suffices and HMAC is unnecessary.

**Setup (client → server only).** The client picks a uniformly random $sk \in \{0,1\}^{n}$ and a random salt $\text{id} \in \{0,1\}^{s}$, notes $t_{\text{init}}$, and computes

$$p_{\text{init}} = h_{k}\big(h_{k-1}\big(\cdots h_{1}(sk)\cdots\big)\big).$$

It sends $(p_{\text{init}}, \text{id})$ to the server, which stores $p_{\text{init}}$ as $p_{\text{prev}}$ and $t_{\text{init}}$ as $t_{\text{prev}}$. The client keeps $sk$ — the only secret in the system.

**Authentication.** With $t_{\max} = t_{\text{init}} + k$, the client computes for a later time $t \in (t_{\text{init}}, t_{\max}]$

$$p_{t} = h_{t_{\max}-t}\big(h_{t_{\max}-t-1}\big(\cdots h_{1}(sk)\cdots\big)\big),$$

and takes $p_{t} = sk$ at $t = t_{\max}$. Note the direction: the seed sits at the far end (time $t_{\max}$), the server's stored value at the near end (time $t_{\text{init}}$), and as time advances the client reveals points progressively *closer* to its seed.

**Verification.** Given a claimed password $p$ at the current counter value $t > t_{\text{prev}}$, the server applies the hashes that carry $p$ forward to the previously stored node:

$$p_{\text{prev}}^{\prime} = h_{t_{\max}-t_{\text{prev}}}\big(\cdots h_{t_{\max}-t+1}(p)\cdots\big).$$

If $p_{\text{prev}}^{\prime} = p_{\text{prev}}$ it accepts and updates $p_{\text{prev}} \leftarrow p$, $t_{\text{prev}} \leftarrow t$. This is where T/Key's cost differs from S/KEY's: the server performs $t - t_{\text{prev}}$ hash evaluations — the number of time steps since the last accepted login — not a single hash. That is cheap for frequent logins and approaches $k$ for a long gap.

**Reinitialization and clock skew.** After $k$ slots the chain is exhausted and the client starts a new one. Reinitialization is unidirectional like authentication: the client picks a fresh secret and salt and sends the new $p_{\text{init}}$; the server returns nothing. With $I = 30$ s and $k = 2\times10^{6}$ a chain lasts about two years and initializes in under 15 seconds on a modern phone. The paper argues this is acceptable because one-to-two-year key-rotation "cryptoperiods" are already recommended practice, and because, unlike TOTP enrollment, setup leaks nothing to a passive eavesdropper. As in TOTP the clocks must agree; the server may accept a password against several earlier steps, updating $t_{\text{prev}}$ to whichever verified.

## 3. Security Analysis

**Threat model.** The adversary may repeatedly break into the server and take everything needed to verify passwords, may collect valid passwords at chosen times, and may choose when to impersonate. Since the forgery must be *later* than every password seen, this is exactly hash-chain inversion.

**Why reusing one function is fatal.** The paper first restates Håstad–Näslund: for a random $h:[N]\to[N]$ with $N = 2^{n}$ and $2k \le T \le N/k$, an algorithm making $T$ oracle queries inverts the $k$-th iterate with probability $\Omega(Tk/N)$ — a multiplicative loss of $k$ over inverting $h$ once.

**Why independent functions nearly restore it.** With $k$ independent random functions, the paper proves (Theorem 4.2) that any $T$-query algorithm satisfies

$$\Pr\big[h_{k}\big(A(h_{[1,k]}(x_{0}))\big) = h_{[1,k]}(x_{0})\big] \le \frac{2T+3}{N},$$

with Corollary 4.3 extending this to a preimage of the *whole* chain: $\frac{2T+2k+1}{N}$. The contrast is the factor: reusing one function costs $k$, independent functions cost a constant near 2. The bound is near-tight — one cannot hope for $O(T/(kN))$, since each iteration shrinks the image and creates collisions an attacker can exploit.

**Security of the full scheme.** In the random oracle model, Theorem 4.6 bounds the advantage in the formal game (Definition 4.4, Attack Game 4.5, where the verifier's state is given to the adversary and password queries must use increasing times):

$$\mathrm{Adv}_{A} \le \frac{2T+2k+1}{2^{n}}.$$

**Concrete parameters.** Setting $n = \lambda + 2$ makes T/Key as secure as a $\lambda$-bit random function: the bound becomes roughly $4T / 2^{\lambda+2}$. For 128-bit security this yields 130-bit passwords, which is why the app cannot show six digits.

**Preprocessing attacks.** The paper then drops the assumption that $h$ is fresh and lets the adversary preprocess the *public* function (SHA-256) into an advice string before seeing the challenge. Without salting the success probability is bounded by $(ST/N)^{2/3}$; with an $n$-bit salt (salt space $M = N$) it drops to $(T/N)^{2/3}$, formally via the time-space bound $T(1 + S/M) \ge \tilde\Omega(\epsilon^{3/2}N)$ (Theorem 8.2). Salting thus cancels a preprocessing attacker's advantage. Two gaps are left open: the dependence on $\epsilon$ is likely suboptimal, and the theorem bounds inverting the *whole* chain where the game needs the stronger statement that any chosen *suffix* can be inverted.

**Stated non-threats.** The authors exclude malware on the phone or laptop, a man-in-the-middle on the TLS-protected channel, and online phishing — the last inherent to any scheme with one-way communication to the phone, though the short validity window keeps a stolen code time-sensitive.

<div class="aside">
<p><span class="aside-label">Aside · The engineering scale</span></p>
<p>S/KEY chains are short in practice — on the order of 500 to 1000 links — and once the links run out the user has to be re-enrolled. T/Key makes the chain time-based rather than login-based, so its default is two million links, about two years of 30-second slots, and it builds that chain in under 15 seconds on a modern phone. That jump of two orders of magnitude is the point of the design: a long chain is no longer paid for in security, because no hash function is ever reused.</p>
<p class="aside-source">Source: RFC 2289 (S/KEY chain lengths in practice); Kogan, Manohar, Boneh, CCS 2017 (typical chain length 2 × 10⁶ and sub-15-second setup).</p>
</div>

## 4. Cost, Implementation, and Limitations

The device never recomputes the two-million-link chain. It stores a handful of checkpoints (pebbles), and because login gaps can be months long, the goal is not stepping one link at a time but jumping quickly to whatever point the current time selects. Existing sequential-traversal schemes (Coppersmith–Jakobsson, Jakobsson) optimize the wrong metric: they count the cost of repositioning pebbles, whereas T/Key cares only about generation latency and treats repositioning as free background work.

Placing $q$ checkpoints to minimize expected generation cost means solving a small system of equations; a recursive variant places one checkpoint at a time in successive sub-intervals. Modeling logins as a Poisson process (exponential inter-login times, $p(t) = \lambda e^{-\lambda t}$) gives a closed form via the Lambert-W function — the optimal checkpoint in $[a,b]$ is

$$x = \frac{-W\big(e^{\lambda(x-a)+1}\big)}{\lambda} + b + \frac{1}{\lambda}.$$

Extra checkpoints bound the worst case. Measured performance for 130-bit passwords, 30-second slots, and 20 mixed checkpoints (client: Samsung Galaxy S7; server: Linux PAM module on a 2.6 GHz i7):

| Auth. period | Mean time between logins | Setup (s) | Password gen. avg (s) | Password gen. worst (s) | Verification (s) |
|---|---|---|---|---|---|
| 1 year | 1 week | 7.5 | 0.3 | 0.6 | 0.4 |
| 2 years | 2 weeks | 14 | 0.5 | 0.9 | 0.8 |
| 4 years | 1 month | 28 | 0.8 | 1.6 | 1.6 |

For comparison, the paper's Table 1 lists, at $2^{128}$ security: S/KEY — no server secret, not time-varying, no comparable length; TOTP — server secret, time-varying, 20 bits; digital signatures (ECDSA/EdDSA) — no server secret, time-varying, 512 bits; T/Key — no server secret, time-varying, 130 bits.

**Encoding.** Since 130 bits cannot be typed as six digits, the Android build encodes the password as a $21\times21$ QR code scanned by the laptop camera (ECDSA's 512-bit token would need a denser $33\times33$ code). For camera-less devices it offers word lists: 12 words from a 2048-word list, or 11 from a 4096-word list.

**Implementation.** The prototype extends Google Authenticator — both the Android app and the Linux PAM module — as a drop-in replacement. Concretely $h_{i}(x) = \mathrm{SHA\text{-}256}(\langle i\rangle_{32} \Vert \text{id} \Vert x)|_{130}$ for $0 \le i < 2^{32}$, with an 80-bit salt, 30-second slots from the UNIX epoch, and a default chain length of $2^{21}$.

**Limitations.** The authors acknowledge: passwords are far longer than TOTP's (the price of a secret-free server), periodic reinitialization is required and the chain expires if the user is offline too long, clocks must agree, and server-side verification cost grows with the gap since the previous login. Keyboard-emulating USB tokens (YubiKey) are suggested as a natural host, since they can type the long passwords while holding the seed in hardware.

## 5. Related Literature

- **Leslie Lamport, 1981.** *Password Authentication with Insecure Communication*, CACM 24(11):770–772. The original hash-chain one-time password; T/Key is its direct modernization. ([link](https://dl.acm.org/doi/10.1145/358790.358797))
- **Neil Haller, 1995.** *The S/KEY One-Time Password System*, RFC 1760. The deployed descendant of Lamport's scheme, and the starting point whose weaknesses — indefinite validity, the "small $n$" attack, hash reuse — T/Key fixes. ([link](https://www.rfc-editor.org/rfc/rfc1760))
- **M'Raihi, Machani, Pei, Rydell, 2011.** *TOTP: Time-Based One-Time Password Algorithm*, RFC 6238. The scheme T/Key aims to replace while removing its stored server secret. ([link](https://www.rfc-editor.org/rfc/rfc6238))
- **Johan Håstad, Mats Näslund, 2007.** *Practical Construction and Analysis of Pseudo-Randomness Primitives*, J. Cryptology 21(1). Iterating one hash function $k$ times makes inversion about $k$ times easier — restated as Theorem 4.1 and neutralized by domain separation. ([link](https://doi.org/10.1007/s00145-007-9009-3))
- **Yih-Chun Hu, Markus Jakobsson, Adrian Perrig, 2005.** *Efficient Constructions for One-way Hash Chains*, ACNS'05. The Sandwich chain and Comb Skipchain speed up verification but need the prover to send extra values, which would lengthen T/Key's passwords. ([link](https://doi.org/10.1007/11496137_29))
- **Don Coppersmith, Markus Jakobsson, 2003.** *Almost Optimal Hash Sequence Traversal*, FC'03 (with Jakobsson, *Fractal Hash Sequence Representation*, ISIT 2002). The pebbling line whose metric T/Key deliberately changes: its logins are sparse and irregular, not sequential. ([link](https://doi.org/10.1007/3-540-36504-4_8))
- **Yevgeniy Dodis, Siyao Guo, Jonathan Katz, 2017.** *Fixing Cracks in the Concrete: Random Oracles with Auxiliary Input, Revisited*, EUROCRYPT'17. The result behind T/Key's preprocessing bound, showing that salting limits precomputation (cf. Hellman 1980; rainbow tables, Oechslin 2003). ([link](https://doi.org/10.1007/978-3-319-56614-6_16))
- **Ercan Uysal et al., 2023.** *P/Key: PUF based second factor authentication*, PLOS ONE. A direct successor adding Physically Unclonable Functions to remove T/Key's dependence on chain length for the number of usable passwords. ([link](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0280181))
- **Xiaojun Yin et al., 2020.** *An Efficient Two-Factor Authentication Scheme Based on the Merkle Tree*, Sensors. Builds many one-time passwords from a Merkle tree on top of T/Key, addressing the same chain-exhaustion and generation-cost limits. ([link](https://pmc.ncbi.nlm.nih.gov/articles/PMC7599477/))

## 6. Summary and Callbacks

- TOTP shares a secret key between phone and server, so a server breach exposes every user's second factor. S/KEY removes the server secret but leaves passwords valid forever, suffers the "small $n$" attack, and loses a factor $k$ by iterating one hash function.
- T/Key is time-based *and* server-secret-free: the server stores only a chain value $p_{\text{prev}}$ and a timestamp $t_{\text{prev}}$, while the seed $sk$ stays on the client.
- Domain separation turns one public $H$ into $k$ independent functions, $h_{i}(x) = H(\langle t_{\text{init}}+k-i\rangle_{c} \Vert \text{id} \Vert x)|_{n}$; fixed-length inputs also avoid length extension, so HMAC is unneeded.
- The client reveals a time-indexed chain element; the server hashes forward from the new password to the stored node, costing $t - t_{\text{prev}}$ hashes — not one.
- In the random oracle model a $T$-query adversary wins with advantage at most $(2T+2k+1)/2^{n}$; taking $n = \lambda + 2$ makes 128-bit security need 130-bit passwords.
- Independent functions lose only a constant factor near 2, versus $k$ for a reused hash, and the bound is near-tight because chain collisions rule out $O(T/(kN))$.
- Preprocessing attacks are answered by salting: an $n$-bit salt bounds success by $(T/N)^{2/3}$ instead of $(ST/N)^{2/3}$; the $\epsilon$-dependence and chain-suffix inversion remain open.
- Checkpoints give near-optimal generation under a Poisson login model with a Lambert-W closed form; a two-year chain sets up in under 15 seconds, generation and verification are sub-second, and the price is 130-bit passwords shown as QR codes or word lists.

**Callbacks.** T/Key is the hinge of this book's main line, and the second time the secret is taken off the server. Lamport (chapter 1) first removed it, leaving the server only a value from a hash chain; S/KEY (chapter 2) deployed that idea but let each password stay valid until used. HOTP and TOTP (chapters 3 and 4) gave that property up for convenience, putting a shared secret back on the server — the trade this chapter now reverses. The price is stated plainly: 130-bit passwords instead of six digits, periodic re-initialisation, a verification cost that grows with the gap since the last login, and a dependence on synchronised clocks. It restores Lamport's database, not Lamport's short passwords. And the clock T/Key now leans on is itself an assumption an attacker can reach — the thread chapter 7 follows.

## References

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

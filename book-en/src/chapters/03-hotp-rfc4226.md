# HOTP: An HMAC-Based One-Time Password Algorithm

<div class="source-card">
<p><strong>Source:</strong> D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. <em>HOTP: An HMAC-Based One-Time Password Algorithm</em>. RFC 4226 (Informational), IETF, December 2005. <a href="https://www.rfc-editor.org/rfc/rfc4226.txt">Original text</a></p>
<p><strong>In one line:</strong> It defines a counter-based one-time password as a truncated HMAC-SHA-1 value, proves that brute force is the best possible attack on it, and shows that only throttling and a bounded resynchronization window make a six-digit code safe to deploy.</p>
</div>

<div class="hook">
Put one button on a plastic dongle: press it, six digits appear, type them into the login page and you are in. Reduce that to a recipe and it sounds like something anyone would have built years earlier — hash a shared key together with an incrementing number, cut the hash down to six digits. It was not built years earlier, because the naive recipe dies the moment you ask three questions: how many wrong guesses must the server tolerate, what happens when the dongle and the server disagree about which number they are on, and what does an attacker learn from simply collecting codes? RFC 4226 is the document that answered all three, and then argued that nothing cleverer than guessing is possible.
</div>

## 1. Background and problem

By the early 2000s static passwords were visibly failing: the document opens by observing that most Internet applications still relied on weak authentication, and that the rapid rise of network threats had exposed the inadequacy of static passwords as the primary authentication mechanism. Two-factor authentication existed, but hardware and software components were "tightly coupled through proprietary technology", which produced high costs, poor adoption and limited innovation. The authors' diagnosis was that the missing ingredient was not cryptography but an **open, freely available algorithm** that any vendor could embed.

RFC 4226 is presented as a joint effort of the **OATH (Open AuTHentication) initiative**, created in 2004 to facilitate collaboration among strong-authentication vendors, and it is deliberately published under IETF intellectual-property terms so that the technical community can freely distribute it.

An earlier design, S/KEY (RFC 1760), had already delivered one-time passwords with hash chains, but its scheme is tied to a pre-generated chain and its reverse traversal. HOTP instead makes the moving factor an **event counter**, and the algorithm is built from a standard primitive, HMAC-SHA-1. The design requirements (Section 4) make the priorities explicit:

- **R1** — the algorithm MUST be sequence- or counter-based, so it can live in high-volume devices such as Java smart cards, USB dongles and GSM SIM cards.
- **R2** — it SHOULD be economical in hardware: minimal battery, buttons, computation and LCD size.
- **R3** — it MUST work with tokens that support no numeric input at all.
- **R4** — the displayed value MUST be easy to read and enter; at least 6 digits, and preferably numeric only.
- **R5** — there MUST be user-friendly resynchronization mechanisms.
- **R6** — the shared secret MUST be at least 128 bits, with 160 bits RECOMMENDED.

That tension between cheap hardware and real security is the thread that runs through the whole document.

## 2. Core content

### 2.1 Notation and symbols

A string always means a binary string, and $\text{StToNum}(s)$ returns the number whose binary representation is $s$ (for example $\text{StToNum}(110) = 6$). The symbols are:

- $C$ — the 8-byte counter value, the moving factor, which MUST be synchronized between the HOTP generator (client) and the HOTP validator (server);
- $K$ — the shared secret; every generator has a different and unique $K$;
- $T$ — the throttling parameter: after $T$ unsuccessful attempts the server refuses further connections from a user;
- $s$ — the resynchronization parameter: the server checks a received authenticator across $s$ consecutive counter values;
- $\text{Digit}$ — the number of digits in an HOTP value.

The key, the counter and the data are hashed high-order byte first, and HOTP values are treated as big-endian.

### 2.2 Dynamic truncation: from 20 bytes to 6 digits

The HMAC-SHA-1 output is 160 bits, far too long for a human to type, so it is compressed:

$$\text{HOTP}(K, C) = \text{Truncate}(\text{HMAC-SHA-1}(K,C))$$

The computation proceeds in three steps:

1. **Generate the HMAC.** Let $HS = \text{HMAC-SHA-1}(K,C)$ — a 20-byte string.
2. **Dynamic truncation (DT).** Let $Sbits = \text{DT}(HS)$ — a 31-bit string.
3. **Reduce to digits.** Let $Snum = \text{StToNum}(Sbits)$, and return $D = Snum \bmod 10^{\text{Digit}}$, a number in the range $0 \dots 10^{\text{Digit}}-1$.

The dynamic truncation itself picks *where* in the HMAC output to read, using the last byte as an index:

```
DT(String) // String = String[0]...String[19]
  Let OffsetBits be the low-order 4 bits of String[19]
  Offset = StToNum(OffsetBits)      // 0 <= Offset <= 15
  Let P = String[Offset]...String[Offset+3]
  Return the Last 31 bits of P
```

Because $\text{Offset}$ ranges over $0 \dots 15$ and four bytes are read, the window always fits inside the 20-byte value. The most significant bit of $P$ is then masked off, so that only 31 bits remain: the stated reason is "to avoid confusion about signed vs. unsigned modulo computations", since processors disagree on signed arithmetic. The reference code from Section 5.4 makes this concrete:

```
int offset   = hmac_result[19] & 0xf ;
int bin_code = (hmac_result[offset]    & 0x7f) << 24
             | (hmac_result[offset+1]  & 0xff) << 16
             | (hmac_result[offset+2]  & 0xff) <<  8
             | (hmac_result[offset+3]  & 0xff) ;
```

**Worked example.** For a certain HMAC value whose bytes end $\dots 0x94, 0x5b, 0x55, 0x5a$, the last byte is $0x5a$, whose low nibble is $0xa = 10$, so the offset is byte 10. Bytes 10–13 are $0x50ef7f19$; the MSB of $0x50$ is already 0, so the dynamic binary code is $0x50ef7f19 = 1{,}357{,}872{,}921$, and

$$1{,}357{,}872{,}921 \bmod 10^{6} = 872921.$$

Implementations MUST extract at least a 6-digit code; the authors note that $\text{Digit} = 7$ or more SHOULD be considered where security requirements demand it.

### 2.3 Why reduce modulo $10^{\text{Digit}}$?

The final reduction exists for **usability, not security**. A 31-bit number is unmemorable and unenterable on the restricted keypads of the devices target (R3, R4); the modulo $10^{\text{Digit}}$ step turns it into a short decimal code. The cost is that a 6-digit code has only $10^{6}$ possible values, so a single guess succeeds with probability $10^{-6}$. As the security analysis makes explicit, this is affordable *only* because the server can rate-limit guesses — entropy was traded away deliberately, and the throttling parameter is the thing that buys it back.

### 2.4 Counter synchronization and resynchronization

The client increments its counter every time the user requests a new HOTP value, but the server increments its counter only after a *successful* authentication. The two counters therefore drift apart whenever a user presses the button without completing a login. To recover, the server sets a **look-ahead window** $s$: on receiving a value it recomputes the next $s$ HOTP values and checks the received one against all of them; if it matches at position $i$, it sets its counter to $i+1$. Optionally the system MAY demand a short sequence of consecutive values (say 2 or 3), since forging a *sequence* of consecutive values is much harder than guessing one. The bound $s$ is essential: it keeps the server from checking forever — an attacker could otherwise force a denial-of-service by making it grind through an unbounded number of candidate values — and it also bounds the space an attacker can search.

### 2.5 Security requirements around the algorithm

The algorithm is only as good as its deployment. The RFC requires the protocol to support two-factor authentication (something you know plus the token), to run over a secure channel, and to throttle on the server side. Throttling has a parameter $T$, the maximum number of validation attempts, tracked per device; the document recommends keeping $T$ small, and offers a delay scheme as an alternative — after failed attempt $A$ the server waits $T \cdot A$ seconds (with $T = 5$: 5 s after the first failure, 10 s after the second, and so on). Crucially, "the delay or lockout schemes MUST be across login sessions", otherwise an attacker simply opens many parallel sessions. On secrets, the RFC distinguishes **deterministic generation** (derived from a master seed, both at provisioning and verification) from **random generation** (generated at provisioning and stored securely for life), and requires the secret to be at least 128 bits, recommending 160.

## 3. Security analysis: brute force is the best attack

The heart of the document is Appendix A, which studies an idealized algorithm, **HOTP-IDEAL**, in which the role of $H = \text{HMAC-SHA-1}$ is played by a *random function* $h : \{0,1\}^{c} \to \{0,1\}^{n}$ drawn as the key. This separates the quality of the construction from the quality of HMAC-SHA-1.

**The model.** The adversary $B$ knows everything except the key $K$. It has two oracles: $\text{AuthO}()$, which returns the user's next authenticator and advances the counter, and $\text{VerO}(A)$, which accepts a candidate $A$ if it equals $\text{ALG}(K,i)$ for some $i$ in the windows $C \dots C+s-1$. It wins if the server accepts an authenticator for a counter value the user never used. The goal is to bound this success probability as a function of $v$ (verification queries), $a$ (authenticator queries) and running time $t$.

**Step 1 — the reduction is slightly biased.** Lemma 1 says that if $N \ge m \ge 1$ with $(q,r) = \text{IntDiv}(N,m)$, then for $x$ uniform on $Z_{N}$,

$$P_{N,m}(z) = \frac{q+1}{N} \text{ for } 0 \le z < r, \qquad P_{N,m}(z) = \frac{q}{N} \text{ for } r \le z < m.$$

With $N = 2^{31}$ and $m = 10^{6}$ we get $q = 2147$ and $r = 483{,}648$: the values $0 \dots 483{,}647$ appear with probability $2148/2^{31}$, and the rest with $2147/2^{31}$. Equivalently, roughly $1.00024045 \times 10^{-6}$ versus $0.99977478 \times 10^{-6}$. So taking $x \bmod 10^{6}$ does *not* give a perfectly uniform 6-digit number — but the bias is tiny.

**Step 2 — brute force, and its exact probability.** Proposition 1 gives the attack that submits the most likely values ($0 \dots r-1$) using $v \le r$ verification queries:

$$\text{Adv}(B\text{-bf}) = 1 - \left(1 - \frac{v(q+1)}{2^{31}}\right)^{s} \approx \frac{s v (q+1)}{2^{31}},$$

and for $m = 10^{6}$,

$$\text{Adv}(B\text{-bf}) \approx s v \cdot \frac{2148}{2^{31}} \approx s v \cdot \frac{1.00024045}{10^{6}}.$$

Two things stand out. First, the success probability is proportional to $s$: a wider resynchronization window directly weakens the system, so $s$ cannot be made large "just for usability". Second, the ceiling is a plain exhaustive search over $10^{\text{Digit}}$ candidates.

**Step 3 — nothing beats brute force.** Proposition 2 states that for *any* adversary attacking HOTP-IDEAL with $v$ verification queries and $a \le 2^{c}-s$ authenticator queries,

$$\text{Adv}(B) \le \frac{s v (q+1)}{2^{31}},$$

so observing and cryptanalyzing the user's authenticators confers no advantage. Lifting this to the real algorithm needs Assumption 1: if $\text{HMAC-SHA-1}$ is a secure pseudorandom function, then an adversary with running time $t$ and $p$ oracle queries has

$$\text{Adv}(A) \le \frac{t/T}{2^{k}} + \frac{p^{2}}{2^{n}}.$$

Under that assumption, Theorem 1 bounds the real HOTP:

$$\text{Adv}(B) \le \frac{s v (q+1)}{2^{31}} + \frac{t/T}{2^{k}} + \frac{(s v + a)^{2}}{2^{n}}.$$

In practice the last two terms are negligible. Taking $k = n = 160$, a running time of $2^{60}$ and $2^{40}$ observed authentications gives an excess advantage of about $2^{-78}$ — "much smaller than the success probability of Equation 1 and negligible compared to it". Section 6 therefore summarizes the security of the whole scheme in one line:

$$\text{Sec} = \frac{s v}{10^{\text{Digit}}}.$$

**What this means operationally.** (i) The algorithm's own strength is *nothing but* the size of the guess space, so *throttling* — the bound on $v$ — is not a nicety but the load-bearing wall. (ii) The window $s$ multiplies the attacker's chances, so it must be kept as small as usability allows. (iii) Since the design is event-based, the same authenticator can be replayed if it is captured and used within the same counter step; RP3 (secure channel) and one-time acceptance are what prevent that. (iv) A counter-synchronization attack — pushing the client's counter forward faster than the server's — is a denial of service, not an impersonation, but it forces the user into resynchronization.

Appendix B addresses the SHA-1 collision attacks announced in February 2005. The authors argue they have **no impact on HOTP**: HMAC is a keyed MAC, and what matters is forgery, not collisions. Finding a collision $SHA\text{-}1(K_{i}, x) = SHA\text{-}1(K_{i}, y)$ ("hidden-key collision") is harder than finding a plain collision, because the attacker does not know $K_{i}$; the historical parallel is HMAC-MD5, still with no attack better than the trivial $2^{64}$ birthday bound.

<div class="aside">
<p><span class="aside-label">Aside · A formal proof inside an RFC</span></p>
<p>Appendix A of RFC 4226 is unusual for an RFC: it carries a <strong>security proof</strong> instead of an assurance. HMAC-SHA-1 is replaced by an abstract random function drawn as the key, so the construction is judged on its own, apart from the quality of the hash, and the analysis lands on an explicit bound — brute force is optimal, and its success probability is at most <code>sv/10^Digit</code>. That is the same quantity Section 6 condenses into a single line. The author list includes Mihir Bellare, co-author of HMAC itself in RFC 2104, and the practical consequence of the theorem, as the document says, is that throttling a verifier stops being a nicety and becomes the load-bearing wall.</p>
<p class="aside-source">Source: RFC 4226 Appendix A and Section 6; the author list on the title page (M. Bellare is also a co-author of RFC 2104).</p>
</div>

## 4. Impact and limitations

RFC 4226 gave the industry what it had been missing: one free, vendor-neutral OTP algorithm. It became the foundation of the OATH ecosystem and, through it, of the hardware tokens and soft tokens that dominated two-factor authentication for the next two decades; its construction is reused almost verbatim in TOTP (Chapter 4). Its security analysis is unusually explicit for an IETF document, and the conclusion that brute force is optimal is why "throttling" is now standard advice.

The limitations are equally clear. It is an **Informational** RFC, not a standards-track specification. A shared symmetric secret must exist on both sides, so the server's key database is a high-value target. Transit must be protected by an external channel; the algorithm "is not a substitute for encryption". And the design is not phishing-resistant at all: a six-digit code typed into a page is exactly as convincing as a code typed into a proxy — the point taken up in Chapter 13.

Formal corrections and later findings include a number of errata, several of which matter in practice: the maximum supported code length is **9 digits** (because the dynamic binary code is 31 bits), which should have been stated explicitly; the masking of the most-significant bit should be described as masking the **sign bit**; and Appendix E.4's resynchronization pseudocode has inconsistent variable names. The 2005 statement that SHA-1 collisions do not affect HMAC-SHA-1 has held up, but the general discomfort with SHA-1 is part of why RFC 6238 later permitted SHA-256 and SHA-512.

## 5. Related literature

- **RFC 2104 — HMAC: Keyed-Hashing for Message Authentication** (Krawczyk, Bellare, Canetti, 1997). <https://www.rfc-editor.org/rfc/rfc2104.txt> — The keyed-MAC construction that HOTP is built on, and whose PRF property Assumption 1 in the security analysis relies upon.
- **RFC 6238 — TOTP: Time-Based One-Time Password Algorithm** (2011). <https://www.rfc-editor.org/rfc/rfc6238.txt> — Replaces the counter $C$ with a time step; Section 6 of RFC 4226's model (throttling, the window $s$) carries over unchanged. The subject of Chapter 4.
- **RFC 6287 — OCRA: OATH Challenge-Response Algorithm** (2011). <https://www.rfc-editor.org/rfc/rfc6287.txt> — The same HMAC-truncation machinery generalized into a challenge-response protocol, showing how far the DT construction was pushed.
- **RFC 1760 — The S/KEY One-Time Password System** (Haller, Atkinson, 1995). <https://www.rfc-editor.org/rfc/rfc1760.txt> — The hash-chain predecessor whose usability limits motivated an HMAC-based, freely licensed alternative.
- **RFC 6030 — Portable Symmetric Key Container (PSKC)** (2010). <https://www.rfc-editor.org/rfc/rfc6030.txt> — The provisioning container for HOTP/TOTP secrets; it is the reason RFC 4226 and RFC 6238 treat provisioning as out of scope.
- **RFC 4226 errata** <https://www.rfc-editor.org/errata/rfc4226> — Documented fixes to the specification, including the 9-digit maximum and the sign-bit wording; useful for reading the document as implementers must interpret it.

## 6. Summary and Callbacks

- HOTP is a **counter-based** OTP: $\text{HOTP}(K,C) = \text{Truncate}(\text{HMAC-SHA-1}(K,C))$, with the counter synchronized between token and server.
- The truncation is **dynamic** (DT): the low nibble of byte 19 selects a 4-byte window, whose top bit is masked off, yielding a 31-bit value; the code is that value modulo $10^{\text{Digit}}$, with $\text{Digit}$ at least 6 (7 or more where needed, 9 at most).
- The modulo reduction is a **usability** decision: it compresses the value to a short decimal code and simultaneously shrinks the guess space to $10^{\text{Digit}}$.
- Under an ideal-HMAC assumption the **best attack is brute force**; Proposition 2 rules out anything smarter, and Theorem 1 shows the extra terms are negligible ($\sim 2^{-78}$ for a very powerful adversary).
- The practical security is $\text{Sec} = sv/10^{\text{Digit}}$: it grows only if you **throttle** attempts ($T$) and keep the resynchronization window $s$ small.
- The **look-ahead window** $s$ resynchronizes drifted counters, at a direct cost in attacker success probability; delays and locks must persist across login sessions.
- The SHA-1 collision attacks do **not** break HMAC-SHA-1, because HMAC's security rests on forgery resistance rather than collision resistance.
- Known limits survive to this day: a symmetric secret on the server, the need for a secure channel, replay within a counter step, and no defence against phishing.

### Callbacks

This is the point where the book hands the shared secret back to the server. In [Chapter 1](01-lamport-1981.md) the move was the opposite one — Lamport *took the secret away*, leaving the host with nothing but the tail of a hash chain, nothing it could use to impersonate a user. HOTP reverses that trade on purpose, because the thing it wanted to sell — a cheap, freely licensed token any vendor could embed — needs both ends to hold the same key $K$. The security argument travels with the algorithm; it never promised anything about the copy of $K$ sitting in the server's database, and that is where the story goes next. [Chapter 5](05-tkey.md) is T/Key taking the secret away again, leaving the server with only a public value from a hash chain. [Chapters 6](06-2fa-apps-gilsenan.md) and [7](07-forward-replay.md) then show where the failure actually lands: not in the algorithm, but in the secret itself, in its backups, and in the clock.

## References

1. D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm*. RFC 4226, IETF, December 2005. <https://www.rfc-editor.org/rfc/rfc4226.txt>
2. H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message Authentication*. RFC 2104, IETF, February 1997. <https://www.rfc-editor.org/rfc/rfc2104.txt>
3. N. Haller, C. Atkinson. *The S/KEY One-Time Password System*. RFC 1760, IETF, February 1995. <https://www.rfc-editor.org/rfc/rfc1760.txt>
4. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, May 2011. <https://www.rfc-editor.org/rfc/rfc6238.txt>
5. D. M'Raihi, J. Rydell, S. Bajaj, S. Machani, D. Naccache. *OCRA: OATH Challenge-Response Algorithm*. RFC 6287, IETF, June 2011. <https://www.rfc-editor.org/rfc/rfc6287.txt>
6. P. Hoyer, M. Pei, S. Machani. *Portable Symmetric Key Container (PSKC)*. RFC 6030, IETF, October 2010. <https://www.rfc-editor.org/rfc/rfc6030.txt>
7. RFC Editor. *Errata for RFC 4226*. <https://www.rfc-editor.org/errata/rfc4226>

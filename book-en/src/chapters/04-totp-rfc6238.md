# TOTP: Time-Based One-Time Password Algorithm

<div class="source-card">
<p><strong>Source:</strong> D. M'Raihi, S. Machani, M. Pei, J. Rydell. <em>TOTP: Time-Based One-Time Password Algorithm</em>. RFC 6238 (Informational), IETF, May 2011. <a href="https://www.rfc-editor.org/rfc/rfc6238.txt">Original text</a></p>
<p><strong>In one line:</strong> It replaces HOTP's event counter with a time step, $T = (\text{current Unix time} - T_0)/X$, gives a reference implementation and a full set of test vectors, and recommends a 30-second step as the point where short-lived codes stop being a usability burden.</p>
</div>

<div class="hook">
Your phone is gone — dropped, stolen, or drowned in a sink. You buy a new one, install an authenticator app, sign in, and the site asks for six digits. The app computes them from the new phone's clock and the secret you just re-entered; the server computes them from its own clock and the secret it stored the day you enrolled. Nothing at all crosses the network at that moment. If those two clocks disagree by a few seconds too many, the door simply stays shut — and a document that changed exactly one thing in HOTP is what makes this everyday situation work.
</div>

## 1. Background and problem

RFC 4226 defined HOTP as an *event-based* algorithm: the moving factor is a counter that advances when the user asks for a value. That design has a property the RFC 6238 authors set out to change. Because the counter is driven by events, a code stays valid until it is used — a token that has not been used in a week will happily display the same next value all week, and an attacker who obtains it has an unlimited window in which to use it. RFC 6238 states the motivation plainly: "A time-based variant of the OTP algorithm provides short-lived OTP values, which are desirable for enhanced security." The proposal is deliberately minimal — it changes *only* the moving factor, keeping every other part of HOTP intact.

The document is again an OATH-driven effort, and again Informational rather than standards-track. Its stated requirements (Section 3) are:

- **R1** — prover and verifier MUST each know or be able to derive the current Unix time.
- **R2** — they MUST share a secret (or a transformation of one).
- **R3** — the algorithm MUST use HOTP as its key building block.
- **R4** — prover and verifier MUST use the same time-step value $X$.
- **R5** — there MUST be a unique secret per prover.
- **R6** — keys SHOULD be randomly generated or derived by a key-derivation algorithm.
- **R7** — keys MAY live in a tamper-resistant device and SHOULD be protected against unauthorised access and use.

## 2. Core content

### 2.1 From counter to time step

TOTP is *defined* as $\text{TOTP} = \text{HOTP}(K, T)$, where $T$ is an integer counting time steps:

$$T = \left\lfloor \frac{\text{Current Unix time} - T_0}{X} \right\rfloor.$$

Two system parameters appear here, both established at provisioning time and communicated to the prover:

- $X$ — the time step in seconds; default $X = 30$;
- $T_0$ — the Unix time at which to start counting time steps; default $T_0 = 0$, the Unix epoch.

The floor function is the default rounding. The RFC's own illustration: with $T_0 = 0$ and $X = 30$, $T = 1$ when the Unix time is 59 seconds, and $T = 2$ when it is 60 seconds — the step boundary falls at multiples of 30, not at "59.5 seconds after first use". One requirement is future-proofing rather than present need: an implementation MUST support a value of $T$ larger than a 32-bit integer when it goes beyond the year 2038.

### 2.2 Everything else is HOTP

Because $T$ is just an integer moving factor, the truncation and reduction are inherited verbatim. The dynamic truncation still reads the low nibble of the last byte of the HMAC as an offset, takes a 4-byte window, masks the top bit to obtain a 31-bit value $Snum$, and returns $Snum \bmod 10^{\text{Digit}}$. Likewise, the counter fed into HMAC is the 8-byte big-endian encoding of $T$, exactly as HOTP encodes $C$.

One deliberate freedom is added: TOTP implementations **MAY** use HMAC-SHA-256 or HMAC-SHA-512 (based on SHA-256/SHA-512) in place of the HMAC-SHA-1 specified for HOTP. This matters because the HOTP security analysis establishes its guarantee under the assumption that the underlying HMAC is a good pseudorandom function; allowing a stronger hash gives deployments a migration path without changing the outer construction. The reference implementation in Appendix A therefore carries three entry points — `generateTOTP`, `generateTOTP256` and `generateTOTP512` — around a single shared truncation routine.

### 2.3 Validation, time-step size, and one-time use

A subtlety the RFC treats at length is that OTPs are compared *after* they travel over a network. An OTP generated near the end of a time step can easily arrive during the next one, so a validator that only compares against the receipt timestamp will reject legitimate users. The document's recommendation is a policy window of **at most one time step** of network delay: the validator should compare against the receipt time and the immediately preceding step as well. It is explicit that widening this window also widens the attack surface.

The choice of $X$ is presented as a balance between security and usability:

- a **larger** step means a longer validity window, so a code observed by a third party can be consumed for longer within that window;
- a **larger** step also means a longer wait for the *next* valid code: a user who generated a code halfway through a step waits only half the step length, but someone who just succeeded must wait for the next boundary;
- $X = 30$ seconds is RECOMMENDED as the compromise, while something as large as 10 minutes "most probably won't be suitable for typical Internet login use cases".

Finally, and importantly for replay: a prover may submit the same value several times within one time step, and "the verifier MUST NOT accept the second attempt of the OTP after the successful validation has been issued for the first OTP, which ensures one-time only use of an OTP".

### 2.4 Resynchronization

HOTP's counter drift becomes clock drift here. The recommendation is a bounded tolerance in time steps, applied **both forward and backward** from the computed step: the validator accepts a prover that is "out of synch" by no more than the configured limit. The RFC's worked example is worth following, because the arithmetic is easy to get wrong: with $X = 30$ seconds and a limit of **two steps backward**, the maximum elapsed drift is "around 89 seconds, i.e., 29 seconds in the calculated time step and 60 seconds for two backward time steps". A validation therefore involves up to three computations — the current step plus two backward steps.

On success the validator can *record* the observed drift, in steps, for that token and correct future comparisons by it. The authors also flag the failure mode: the longer a prover goes without sending a value, the more clock drift can accumulate, so if the drift exceeds the configured threshold automatic resynchronization will not work and a separate, explicitly authenticated procedure is needed.

### 2.5 Reference implementation and test vectors

Appendix A gives a complete Java implementation. Its structure mirrors the algorithm: a `hmac_sha` helper, a HEX-to-bytes converter, a `DIGITS_POWER` table, and a `generateTOTP(key, time, returnDigits, crypto)` core that left-pads the time to 16 hex characters, computes the HMAC, takes `offset = hash[hash.length - 1] & 0xf`, assembles the 31-bit binary value, and reduces modulo `DIGITS_POWER[codeDigits]`.

Appendix B gives official test vectors. The 20-byte SHA-1 secret is the ASCII string `12345678901234567890` (hex `3132333435363738393031323334353637383930`); the SHA-256 and SHA-512 seeds are the same string extended to 32 and 64 bytes respectively, so that each is as long as its HMAC output.

| Time (sec) | UTC time | T (hex) | TOTP SHA-1 | TOTP SHA-256 | TOTP SHA-512 |
|---|---|---|---|---|---|
| 59 | 1970-01-01 00:00:59 | 0000000000000001 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 2005-03-18 01:58:29 | 00000000023523EC | 07081804 | 68084774 | 25091201 |
| 1111111111 | 2005-03-18 01:58:31 | 00000000023523ED | 14050471 | 67062674 | 99943326 |
| 1234567890 | 2009-02-13 23:31:30 | 000000000273EF07 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 2033-05-18 03:33:20 | 0000000003F940AA | 69279037 | 90698825 | 38618901 |
| 20000000000 | 2603-10-11 11:33:20 | 0000000027BC86AA | 65353130 | 77737706 | 47863826 |

Note that the last row is beyond any 32-bit timestamp; it is a direct test of the "support values larger than 32 bits" requirement.

## 3. Security analysis and known weaknesses

RFC 6238 adds no new cryptographic analysis: it points to RFC 4226 and states the conclusion, that "for all practical purposes, the outputs of the dynamic truncation on distinct inputs are uniformly and independently distributed strings" and that "the best possible attack against the HOTP function is the brute force attack". The security of TOTP is exactly the security of HOTP, with the moving factor relabelled.

What TOTP changes is the **shape** of that security:

- **Replay window.** A code is valid for one time step (plus the accepted drift). A passive attacker who observes a code can replay it within that window; the RFC's one-time-use rule — never accept a second submission of the same value after a successful validation — is what limits the damage, and it must be implemented by the verifier. The forward-replay study in [Chapter 7](07-forward-replay.md) is the modern follow-up on exactly this window.
- **Throttling still needed.** The guess space is unchanged, so the rate-limiting argument of RFC 4226 carries over. A five-digit-or-fewer space with unlimited attempts would be unbroken by any hash function.
- **Key protection.** Keys SHOULD be of the length of the HMAC output for interoperability; random generation SHOULD follow RFC 4086 and pass a recognised randomness test; all communication SHOULD run over SSL/TLS ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.txt)) or IPsec; the key store MUST sit in a secure area, ideally with tamper-resistant hardware encryption that decrypts a key only while verifying an OTP and re-encrypts it immediately, "to limit exposure in the RAM to a short period of time".
- **No phishing resistance.** Nothing in TOTP binds a code to the site it was generated for. A proxy that obtains a code and relays it in real time defeats TOTP completely — a limitation this book returns to in Chapter 13.

Later errata and practical reports sharpen a few of these points:

- The Appendix B preamble says the shared secret is the ASCII string `12345678901234567890`, but the SHA-256/SHA-512 vectors in fact require the longer, padded seeds shown in Appendix A. This inconsistency was reported as an erratum in 2017 and is a classic trap for implementers who reuse the 20-byte seed for all modes.
- The reference implementation builds the digit string by repeated prepending, which is not constant-time; a reported erratum proposes a constant-time construction so that the time taken to format an OTP cannot leak its digits.
- The "support $T$ larger than 32 bits" wording is underspecified: what actually matters is that $T$ is fed into HMAC as a **64-bit big-endian** integer and that the division $(\text{time}-T_0)/X$ is performed on 64-bit values, otherwise the output is silently wrong.

## 4. Impact and limitations

TOTP is the algorithm behind essentially every "authenticator app" code people have typed in the last fifteen years. Its strengths were exactly the ones its authors aimed for: it reuses HOTP unchanged, so implementing it is trivial once HOTP exists; it needs no server-side counter, only a synchronized clock; and its short-lived values close the long validity window that made an unused HOTP code dangerous. The decision to permit SHA-256/SHA-512 also gave the ecosystem room to move off SHA-1 when SHA-1 became uncomfortable.

Its limitations are structural rather than accidental. The secret is still symmetric and still lives on the server, so a compromised authenticator database compromises every enrolled user. A code is still a shared secret typed into a page, so TOTP provides no protection against phishing or against a real-time man-in-the-middle, and it requires the user to have a working clock and a charged device. The time step trades security for usability in a way that is visible to users: waiting for a code to refresh is the everyday symptom. And the specification leaves a great deal — provisioning, key storage, recovery and backup — to other documents, which is precisely why practice has accumulated on top of it, in the form of the de facto `otpauth://` URI convention rather than an RFC.

<div class="aside">
<p><span class="aside-label">Aside · <code>otpauth://</code> never became an RFC</span></p>
<p>Every time you scan a QR code to add an account to an authenticator, what that code carries is an <code>otpauth://totp/...</code> URI. RFC 6238 does not define it, and neither does any other RFC: the format lives in a page of Google's Authenticator wiki, and its status is a de facto convention that implementations agreed on rather than anything ratified. That is exactly why enrolling the "same" account in two apps can still produce codes that never match — the URI carries the algorithm, the digit count and the time step, and two sides that disagree on any one of them agree on nothing. It is the hole Section 4 describes: the specification left provisioning and key transfer to other documents, and practice filled it with a format that has no standards standing at all.</p>
<p class="aside-source">Source: Google Authenticator wiki, "Key URI Format" (a de facto convention, not an RFC); cf. RFC 6238 Section 4.</p>
</div>

## 5. Related literature

- **RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm** (2005). <https://www.rfc-editor.org/rfc/rfc4226.txt> — The building block; TOTP is literally $\text{HOTP}(K,T)$, and all of TOTP's cryptographic security argument lives in its Appendix A. Chapter 3.
- **RFC 2104 — HMAC: Keyed-Hashing for Message Authentication** (1997). <https://www.rfc-editor.org/rfc/rfc2104.txt> — The MAC construction underneath both HOTP and the SHA-256/SHA-512 variants of TOTP.
- **Google Authenticator — Key URI Format** <https://github.com/google/google-authenticator/wiki/Key-Uri-Format> — The `otpauth://totp/...` URI that authenticator apps and websites actually exchange. Note carefully: this is **not an RFC** and has no standards status — it is a widely implemented de facto convention, which is why parameter mismatches (algorithm, digits, period) are a common interoperability failure.
- **RFC 6030 — Portable Symmetric Key Container (PSKC)** (2010). <https://www.rfc-editor.org/rfc/rfc6030.txt> — The provisioning container for OTP secrets, cited by RFC 6238 as the place where provisioning is standardised.
- **RFC 4086 — Randomness Requirements for Security** (2005). <https://www.rfc-editor.org/rfc/rfc4086.txt> — The randomness guidance RFC 6238 explicitly recommends for key generation.
- **RFC 6238 errata** <https://www.rfc-editor.org/errata/rfc6238> — Reported technical issues, including the Appendix B seed mismatch, constant-time code formatting, and the 64-bit big-endian counter requirement; essential reading alongside the specification.

## 6. Summary and Callbacks

- TOTP **is** HOTP with a time-derived moving factor: $\text{TOTP} = \text{HOTP}(K, T)$ and $T = \lfloor (\text{current Unix time} - T_0)/X \rfloor$, with defaults $T_0 = 0$ and $X = 30$ seconds.
- Truncation and modulo reduction are inherited **unchanged** from RFC 4226; the only additions are the time parameters and the option to use HMAC-SHA-256 or HMAC-SHA-512.
- Implementations MUST handle $T$ beyond 32 bits (the 2603 test vector exists for that reason), which in practice means a 64-bit big-endian counter.
- The validator should tolerate **at most one time step** of network delay, and **MUST NOT** accept the same value twice — that rule is what delivers one-time use.
- Resynchronization allows a bounded number of steps forward and backward; the RFC's example gives roughly 89 seconds of tolerance for $X = 30$ with two backward steps, and the observed drift can then be recorded per token.
- The security argument is unchanged from RFC 4226 — brute force is optimal — so **throttling and key protection** remain the load-bearing parts of a deployment.
- $X = 30$ seconds is a deliberate balance: shorter steps are safer but harder to use, longer steps are more convenient but leave a wider replay window.
- TOTP is **not phishing-resistant**, and its de facto interoperability layer (`otpauth://`) is a convention rather than a standard — two gaps that the rest of this book takes up.

### Callbacks

TOTP is the second half of the book's largest piece of foreshadowing. [Chapter 3](03-hotp-rfc4226.md) is where HOTP handed the shared secret back to the server, undoing Lamport's original move in [Chapter 1](01-lamport-1981.md); TOTP keeps that secret exactly where HOTP left it and only changes when the moving factor advances, so the same symmetric key still sits on both sides. What it adds is the other recurring theme: **time as a trust input**. A code is only correct because two machines independently agree on what time it is, and the RFC's tolerance of one step of delay, plus a couple of steps of drift, is precisely the width of the window an attacker can use — the thread [Chapter 7](07-forward-replay.md) follows to its conclusion. The next chapter, [Chapter 5](05-tkey.md), asks the question this one leaves open: can it stay this easy to use while the server stops holding a secret at all?

## References

1. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, May 2011. <https://www.rfc-editor.org/rfc/rfc6238.txt>
2. D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm*. RFC 4226, IETF, December 2005. <https://www.rfc-editor.org/rfc/rfc4226.txt>
3. H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message Authentication*. RFC 2104, IETF, February 1997. <https://www.rfc-editor.org/rfc/rfc2104.txt>
4. Google. *Key URI Format* (Google Authenticator wiki). <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
5. P. Hoyer, M. Pei, S. Machani. *Portable Symmetric Key Container (PSKC)*. RFC 6030, IETF, October 2010. <https://www.rfc-editor.org/rfc/rfc6030.txt>
6. D. Eastlake 3rd, J. Schiller, S. Crocker. *Randomness Requirements for Security*. RFC 4086, IETF, June 2005. <https://www.rfc-editor.org/rfc/rfc4086.txt>
7. T. Dierks, E. Rescorla. *The Transport Layer Security (TLS) Protocol Version 1.2*. RFC 5246, IETF, August 2008. <https://www.rfc-editor.org/rfc/rfc5246.txt>
8. RFC Editor. *Errata for RFC 6238*. <https://www.rfc-editor.org/errata/rfc6238>

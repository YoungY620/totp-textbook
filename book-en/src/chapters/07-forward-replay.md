# Forward-Replay Attacks to TOTP Authentication

<div class="source-card">
<p><strong>Source:</strong> Giuseppe Bianchi, Lorenzo Valeriani. <em>Time Is on My Side: Forward-Replay Attacks to TOTP Authentication</em>. In: B. Arief, A. Monreale, M. Sirivianos, S. Li (eds), Security and Privacy in Social Networks and Big Data (SocialSec 2023), LNCS vol. 14097, Springer, Singapore, 2023, pp. 109–126. <a href="https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7">Publisher page (paywalled)</a>. Authors' own talk slides, openly hosted by the conference: <a href="https://nss2023.cyber.kent.ac.uk/presentations/6-3.pdf">presentation PDF</a>.</p>
<p><strong>In one line:</strong> A server's correct clock does not make TOTP safe, because an attacker who can push a device's clock into the future can harvest codes before they are due and replay each one at the moment its time step finally arrives.</p>
</div>

*Availability note.* The chapter is paywalled and no open-access version could be located: OpenAlex, Semantic Scholar and the publisher all mark it closed. This chapter draws on the material the publisher exposes freely (abstract, author note, reference list) plus the authors' own conference presentation, which the SocialSec 2023 site hosts openly and which states the attack parameters and proof-of-concept results. Numbers below come from that presentation; anything the source does not state is flagged as such.

<div class="hook">
<p>Picture a phone left on a café table while its owner queues for coffee. Over the next few minutes the screen lights up twice, a six-digit number appears and fades, and the clock in the status bar is nudged a little further ahead and then back. When the owner returns, the phone looks exactly as it did before — but what has just walked out with the attacker is not a password and not a secret. It is a full day of codes, each one already valid, each one waiting patiently for the minute it belongs to.</p>
</div>

## 1. Background and the problem

Two-factor authentication (2FA) is now a standard second layer over passwords, and the time-based one-time password (TOTP) is one of the two most common second factors. It is attractive because it needs no connectivity at login: phone and server share a secret at enrolment, after which the phone computes the right code on its own. That convenience rests on one assumption — that both sides agree, loosely, on what time it is.

The TOTP literature and its RFC are framed around the *server*: RFC 6238 spends its security considerations on protecting the shared secret, choosing the time-step size and tolerating clock drift. The implicit reassurance is that a trustworthy server clock means a code valid *now* was generated *now*, and a captured code expires within seconds.

Bianchi and Valeriani point at the half this framing leaves out: the *prover's* clock. Nothing in TOTP binds a code to the instant it was produced. The time step is computed from whatever the device's clock says at generation time, and the server, when the code arrives, only checks whether it matches a step it is currently willing to accept. The authors call the gap "obvious (but somewhat overlooked)": a secure server time reference is not sufficient when an attacker can set *future* time instants on the device, collect the codes those instants produce, and play them back later once the real world catches up. They name this the **forward-replay attack**.

Their framing story is mundane: as players of a game with a "wait for lives" timer, the authors set their phones' clocks ahead to refill lives instantly. The paper asks whether the same manipulation can bypass authentication. Demonstrated on a stock, non-rooted Android phone and three real apps, the answer is yes.

## 2. The TOTP foundation and why it permits the attack

TOTP derives its code from HOTP (RFC 4226) by replacing the incrementing counter with a clock-derived one. With $X$ the time step in seconds (30 by default) and $T_{0}$ the epoch to count from (0 by default), the value fed to HOTP is

$$
T = \left\lfloor \frac{\text{Current Unix time} - T_{0}}{X} \right\rfloor,
\qquad \text{TOTP}(K, T) = \text{HOTP}(K, T).
$$

The scheme is entirely time-local: $T$ depends only on the device's clock, the secret $K$ is shared and fixed, and the code is a pure function of $K$ and $T$. Given a secret and control of the clock, an attacker can compute *any* code for *any* future step — no server interaction, no eavesdropping, no network position.

Three properties of the validation side, all intended as usability features, make forward-replay practical:

- **The server does not know when the code was generated.** RFC 6238 is explicit: "When an OTP is received at a validation system, it doesn't know a client's exact timestamp when an OTP was generated." Validation compares the code against the steps accepted *at receipt time*; it is not a check of provenance.
- **The acceptance window is wider than one step.** To absorb network delay, RFC 6238 recommends also accepting a code generated one step earlier — "at most one time step is allowed as the network delay." The paper's own note agrees: servers may accept past-timestamp codes within a delay window, and in practice at most one step is allowed. With a 30-second step this widens each code's usable life to roughly a minute.
- **One-time-use is enforced only after a successful validation.** RFC 6238 requires a verifier not to accept the *second* attempt of a code once the first has been validated. That stops a code being used twice; it does nothing to stop a code being used once, which is all forward-replay needs.

So widen the window to ~60 seconds, and sampling the device clock at one-minute granularity yields a code for every minute, each accepted exactly once when its minute arrives.

## 3. Security analysis and the proof of concept

### 3.1 The attack: generate early, use later

1. **Obtain access** to the device for a bounded interval, manually (physical access) or through a malicious app.
2. **Activate** the victim's TOTP authenticator and let it display a code.
3. **Move the clock forward** to a sequence of future instants $\{t_{1}, t_{2}, \dots, t_{n}\}$.
4. **Read and log** the displayed code for each instant, building valid timestamp–code pairs $\{(t_{1}, \text{OTP}_{1}), \dots, (t_{n}, \text{OTP}_{n})\}$.
5. **Replay**: when the server's clock reaches each $t_{i}$, submit $\text{OTP}_{i}$; the server sees a code valid for its current step and accepts.

Because codes are compared only against the server's *current* step, the attacker never touches the server's clock or sits on the network path. What it demands is a strong position on the device, captured by three capabilities: **moving time forward, capturing the code, and extracting the code from the device**.

The presentation names three ways to get that position: **manual access** (holding the device briefly), a **malicious app** (installed directly or injected by an offensive penetration that already reached the phone), and a **hostile public USB charging socket** (posing as an input/output or network device, or used to reach the Android Debug Bridge). The attack is hard to notice because the device can be restored to an unaltered state afterwards: the collected codes carry no trace of when they were harvested, so neither victim nor server has an obvious signal that codes were pre-collected.

### 3.2 How this differs from a classic replay

A classic replay intercepts a credential valid *now* and uses it immediately, before it expires — capture and use close together, attacker on the channel. Forward-replay inverts this: **generate early, use much later**, against a credential valid only in the future. The codes are not stolen off the wire at all; they are computed locally by the victim's app under an attacker-chosen clock. The authors coin "forward-replay" to separate it from other "time traveller" attacks and from two earlier blog reports of a similar idea — one on a dedicated TOTP *hardware token* (Deeg, SYSS-2021-007), one on replaying TOTP codes (Huseynov). Their contribution is to generalise the idea to ordinary Android TOTP *apps* and show it needs no operating-system modification.

### 3.3 Proof of concept on Android

The authors built an Android app that triggers future code generation and logs the results, without root or OS-level change, using ordinary documented features:

- **Launching the authenticator.** The app resolves the authenticator's package name through the package manager to get its launch intent, and declares that name in a `<queries>` manifest element so it survives Android's package-visibility filtering.
- **Moving the clock.** Changing the system clock normally needs system-app or root permissions. The authors use an Android **Accessibility Service**, allowed to simulate touch input as if a user typed it — here, mimicking a human editing the Date & Time settings.
- **Capturing the code.** When the TOTP appears, an accessibility event fires and the service reads the code, saving it to a database or file, or transmitting it off the device.

Adapting to other apps needed small changes: FreeOTP requires a tap on the code area before it shows the code, and Duo Mobile adds a reveal button plus its own 30-second application-level refresh timer.

The tool was tested on a completely standard, **non-rooted Google Pixel 7 Pro running Android 13** with the March 2023 security patch, against **Google Authenticator** (over 100M downloads), **FreeOTP Authenticator** (over 1M) and **Duo Mobile** (over 10M).

The headline result is the concrete measure of the threat: **the authors obtained TOTP codes from Google Authenticator for every minute of an entire day in about 35 minutes of execution.** The one-minute interval follows from the granularity manual time-setting allows and from the RFC's recommendation to treat both the current and previous code as valid, which together "creates a time window of valid codes that spans one minute." Roughly 1,440 harvested codes therefore cover a full day of future logins, gathered in one short session with the phone.

## 4. Impact, mitigations and limitations

TOTP is widely treated as the "safe" second factor, and much of that reputation rests on its short code lifetime. The paper shows that lifetime is a property of the *server's* clock only, and that an attacker with brief device access can build a store of valid future codes. The threat convinces because it needs no exotic tooling: no root, no OS patch, no server compromise, no network position — only the phone, for a few minutes, and a legitimate-looking app.

The mitigations the authors list mix raising the cost of device access with removing the root cause, the locally-controlled clock:

- **Strong lock-screen protection and strong passwords**, raising the bar for manual access and malicious apps.
- **Forcing online code generation with cryptographic synchronisation**, so codes cannot be produced offline from a manipulated clock.
- **Key rotation**, so a harvested code loses value once the seed changes.
- **A biometric prompt whenever the authenticator moves from background to foreground**, making silent scripted harvesting far harder.
- **Dedicated hardware or a trusted execution environment (TEE) certifying the code**, so a compromised application layer cannot manufacture future codes.

Two further families of defence follow. First, *tightening the server-side clock check*: RFC 6238 recommends bounding how many time steps a prover may be "out of synch", forward and backward, and rejecting reused codes after a successful validation. Narrowing the acceptance window shrinks each code's life (from about a minute to thirty seconds), and tracking used codes prevents a captured code being used twice — but neither closes the attack, because each harvested code is used exactly once, at its correct future instant. Second, *treating time synchronisation as a security feature*: since the scheme trusts the prover's clock, attacks on that clock matter. Malhotra et al. show unauthenticated NTP traffic can shift a client's clock, and the authors list NTP and NITZ as promising ways to automate the clock manipulation. For high-value accounts, the natural conclusion is not a hardened TOTP but a move away from shared secrets and phishable codes toward phishing-resistant authenticators such as WebAuthn/passkeys (this book's chapter 13).

**Limitations, as the authors frame them.** The proof of concept is an Android application measurement, not a study of every TOTP deployment; other platforms and apps were not tested. It requires a substantial foothold on the device (three capabilities above), and it is not a break of TOTP cryptography — the secret and the HMAC are untouched. The codes must be stored and delivered at the right moments, so a large harvest is a logistics problem as much as a collection one. Finally, the authors position the threat as under-considered rather than new: they credit earlier blog reports and frame their contribution as generalising and quantifying the idea for mainstream TOTP apps.

<div class="aside">
<p><span class="aside-label">Aside · Stealing "future" codes with an accessibility service</span></p>
<p>The proof of concept ran on a completely standard Google Pixel 7 Pro that was not rooted and had no operating-system modification: the authors drove the phone's Date &amp; Time settings with an Android Accessibility Service, which is permitted to simulate the touch input a human would make. As each future minute was dialled in, Google Authenticator redrew its code and the service read it straight off the screen. In roughly 35 minutes it collected a code for every minute of an entire day. The authors' point is not that accessibility services are a flaw — they are a documented, intended Android feature. The attack simply never needed anything more exotic than that.</p>
<p class="aside-source">Source: Bianchi &amp; Valeriani, conference presentation for SocialSec 2023 (hosted openly at nss2023.cyber.kent.ac.uk); the paper itself is paywalled.</p>
</div>

## 5. Related literature

- **RFC 6238, TOTP** ([rfc-editor.org/rfc/rfc6238.txt](https://www.rfc-editor.org/rfc/rfc6238.txt)) — the standard this chapter analyses. Section 5.2 states both facts the attack leans on (the validator does not know when a code was generated; at most one time step is allowed as network delay); Section 6 recommends bounding drift in both directions.
- **C. Gilsenan, F. Shakir, N. Alomar, S. Egelman, *Security and Privacy Failures in Popular 2FA Apps*, USENIX Security 2023** ([usenix.org](https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan)) — the ecosystem study of real TOTP apps covered in chapter 6, finding that many apps fail to protect the shared secret. Bianchi and Valeriani answer the complementary question of what an attacker does with the app once on the device.
- **D. Kogan, N. Manohar, D. Boneh, *T/Key: Second-Factor Authentication from Secure Hash Chains*, CCS 2017** ([arXiv:1708.08424](https://arxiv.org/abs/1708.08424)) — a time-based scheme keeping no secret on the server, covered in chapter 5. It still binds codes to time, showing that "hardened TOTP" is a design direction, not a free upgrade.
- **S. Park, A. Shaik, R. Borgaonkar, J.-P. Seifert, *White Rabbit in Mobile: Effect of Unsecured Clock Source in Smartphones*, SPSM 2016** ([ACM DL](https://dl.acm.org/doi/10.1145/2994459.2994465)) — cited by the paper; it shows how smartphones' unsecured clock sources (manual setting, NTP, NITZ, GNSS) can be manipulated, the technical precondition for forward-replay.
- **A. Malhotra, I. E. Cohen, E. Brakke, S. Goldberg, *Attacking the Network Time Protocol*, NDSS 2016** ([eprint 2015/1020](https://eprint.iacr.org/2015/1020)) — also cited; unauthenticated NTP lets a network attacker shift a client's clock, including stealthy "small-step-big-step" shifts, which is why a hardened TOTP must treat time synchronisation itself as a security property.
- **M. Deeg, *To the Future and Back: Hacking a TOTP Hardware Token (SYSS-2021-007)*** ([blog.syss.com](https://blog.syss.com/posts/syss-2021-007/)) — an earlier, independent report of the same core idea on a dedicated TOTP hardware token, which the authors credit and generalise to everyday Android apps.

## 6. Summary and Callbacks

- TOTP's time step comes from the **prover's** local clock; the server only compares the code against the step it currently accepts and cannot tell when the code was generated.
- A **forward-replay attack** moves the device clock forward, harvests codes for future steps, and replays each when its step arrives — "generate early, use later."
- It needs three capabilities: move time forward, capture the code, extract it from the device. No server compromise, network position or root.
- It differs from a classic replay (capture a currently-valid credential and use it immediately): here codes are computed locally, never stolen off the wire, and used much later.
- A proof of concept on a **non-rooted Google Pixel 7 Pro / Android 13** targeted **Google Authenticator, FreeOTP and Duo Mobile**, using only Android's Accessibility Service and a crafted app.
- Measured result: codes for **every minute of a full day (~1,440 codes)** were harvested from Google Authenticator in **about 35 minutes**; the cadence follows from manual time-setting granularity and the RFC's "current and previous step" acceptance (a ~60-second window).
- Mitigations span raising the cost of device access (lock screen, biometric prompts), removing the local-clock root cause (online generation with cryptographic sync, TEE-certified codes), key rotation, and tighter server-side windows — the last helps but does not close the gap, since each harvested code is used once.
- The durable lesson is architectural: shared-secret, phishable second factors should give way to phishing-resistant authenticators such as WebAuthn/passkeys.

**Callbacks.** Chapter 4 handed the time step to the reader as a given input: TOTP takes the clock as read, and its security considerations ask only how much drift the server should forgive. This chapter lifts that input off its pedestal — the clock is not an assumption but an attack surface, and it belongs to the *prover*, not to the server. That is the second of this book's motifs, **time is trust**: whoever sets the clock decides which codes exist. It also finishes the fourth act's diagnosis, begun in chapter 6 with implementations that leak the shared secret; here the algorithm is untouched, and the app is doing precisely what it was built to do, on the time it was told. Leaving shared secrets behind is the next act's work (chapter 13), where the authenticator signs a fresh challenge supplied by the server instead of computing a code from a locally read clock, so no future code exists to be harvested in advance.

## References

1. G. Bianchi, L. Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication*. In: B. Arief et al. (eds), Security and Privacy in Social Networks and Big Data (SocialSec 2023), LNCS vol. 14097, Springer, 2023, pp. 109–126. DOI: https://doi.org/10.1007/978-981-99-5177-2_7
2. G. Bianchi, L. Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication* (conference presentation). NSS-SocialSec 2023, University of Kent, Canterbury, UK, August 2023. https://nss2023.cyber.kent.ac.uk/presentations/6-3.pdf
3. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, May 2011. https://www.rfc-editor.org/rfc/rfc6238.txt
4. D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache, O. Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm*. RFC 4226, IETF, December 2005. https://www.rfc-editor.org/rfc/rfc4226.txt
5. H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message Authentication*. RFC 2104, IETF, February 1997. https://www.rfc-editor.org/rfc/rfc2104.txt
6. D. M'Raihi, J. Rydell, S. Bajaj, S. Machani, D. Naccache. *OCRA: OATH Challenge-Response Algorithm*. RFC 6287, IETF, June 2011. https://www.rfc-editor.org/rfc/rfc6287.txt
7. C. Gilsenan, F. Shakir, N. Alomar, S. Egelman. *Security and Privacy Failures in Popular 2FA Apps*. USENIX Security 2023. https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan
8. D. Kogan, N. Manohar, D. Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains*. ACM CCS 2017, pp. 983–999. https://arxiv.org/abs/1708.08424
9. S. Park, A. Shaik, R. Borgaonkar, J.-P. Seifert. *White Rabbit in Mobile: Effect of Unsecured Clock Source in Smartphones*. In: Proceedings of the 6th Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM), 2016, pp. 13–21. https://dl.acm.org/doi/10.1145/2994459.2994465
10. A. Malhotra, I. E. Cohen, E. Brakke, S. Goldberg. *Attacking the Network Time Protocol*. NDSS 2016. https://eprint.iacr.org/2015/1020
11. M. Deeg. *To the Future and Back: Hacking a TOTP Hardware Token (SYSS-2021-007)*. SYSS Tech Blog, 2021. https://blog.syss.com/posts/syss-2021-007/
12. E. Huseynov. *TOTP Replay Attack — Yubikey et al.* Medium. https://medium.com/@eminhuseynov_37266/totp-replay-attack-yubikey-et-al-adde8e8c62d3
13. V. Iovino, S. Vaudenay, M. Vuagnoux. *On the Effectiveness of Time Travel to Inject COVID-19 Alerts*. CT-RSA 2021, LNCS vol. 12704, pp. 422–443. https://eprint.iacr.org/2020/1393
14. L. C. Meier. *On Security Against Time Traveling Adversaries*. IACR Cryptology ePrint Archive, Report 2022/1148. https://eprint.iacr.org/2022/1148
15. C. Ozkan, K. Bicakci. *Security Analysis of Mobile Authenticator Applications*. ISCTURKEY 2020, pp. 18–30. IEEE.
16. P. Polleit, M. Spreitzenbarth. *Defeating the Secrets of OTP Apps*. 2018, pp. 76–88. IEEE.
17. H. Sun, K. Sun, Y. Wang, J. Jing. *TrustOTP: Transforming Smartphones into Secure One-Time Password Tokens*. ACM CCS 2015, pp. 976–988. https://dl.acm.org/doi/10.1145/2810103.2813679
18. Android Developers. *AccessibilityService* reference. https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
19. J. Selvi. *delorean* (time-manipulation utility). https://github.com/jselvi/delorean

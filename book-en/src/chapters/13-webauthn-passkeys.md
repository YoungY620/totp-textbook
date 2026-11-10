# WebAuthn and Passkeys

<div class="source-card">
<p><strong>Standards:</strong> W3C. <em>Web Authentication: An API for accessing Public Key Credentials, Level 3</em>. Candidate Recommendation Snapshot, 26 May 2026. <a href="https://www.w3.org/TR/webauthn-3/">w3.org/TR/webauthn-3</a>. FIDO Alliance. <em>FIDO2 / CTAP specifications</em>. <a href="https://fidoalliance.org/specifications/">fidoalliance.org/specifications</a>.</p>
<p><strong>Research:</strong> Alaa Daffalla, Arkaprabha Bhattacharya, Jacob Wilder, Rahul Chatterjee, Nicola Dell, Rosanna Bellini, Thomas Ristenpart. <em>A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal Threat Models</em>. USENIX Security 2025. <a href="https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf">PDF</a>. · Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. <em>"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments</em>. ACM CCS 2023. <a href="https://arxiv.org/abs/2306.09708">arXiv:2306.09708</a>.</p>
<p><strong>In one line:</strong> TOTP fails against phishing because its code is a transferable shared secret; WebAuthn replaces it with a per-origin key pair the server never holds — trading the shared-secret risk for new trust assumptions in syncing and recovery.</p>
</div>

<div class="hook">
<p>A six-digit code is on your screen, ticking down from 30. The page in front of you looks exactly like your bank's login — same layout, same favicon, same "Welcome back". You type the code in. Half a second later a phishing site has relayed it to the real bank, inside the window where it is still valid, and your correct code has just authenticated the attacker's session. Nothing looks wrong at the server: the right code arrived at the right time.</p>
</div>

## 1. Background and Motivation

Every scheme in this book has been a variation on one question: **where does the secret live?** Lamport (1981) took the secret off the server entirely; S/KEY, HOTP and TOTP put a shared secret back on both sides for the sake of usability; T/Key (Chapter 5) removed the server's secret again. Password managers repeated the same argument under a "zero knowledge" banner (Chapters 8–12). This closing chapter looks at the answer the industry converged on: stop sharing a secret, and instead give each account a **key pair**.

TOTP (RFC 6238) is not phishing-resistant, and the reason is structural rather than a bug. The six-digit code is a function of a shared key $K$ and the current time step: $\mathrm{TOTP}(K,T)=\mathrm{HOTP}(K,T)$. It carries no information about *who* is presenting it or *where* it was entered. RFC 6238's own security considerations acknowledge that "when an OTP is received at a validation system, it doesn't know a client's exact timestamp when an OTP was generated" — the validator compares the code against the steps it will accept *now*, not against a record of provenance. So a phishing site that stands between the user and the real server can simply relay the code in real time, inside the ~30–60 second acceptance window, and log in as the victim. This is the classic real-time man-in-the-middle; it is what "TOTP is not phishing-resistant" means precisely.

Chapter 7 showed a second, clock-oriented failure — the forward-replay attack — with the same root: a TOTP code is a *bearer token* valid for a time window regardless of who enters it. Phishing and forward-replay differ in how the attacker obtains the code, but both would be neutralised if the credential could not be used outside the context it was created for.

That is exactly what WebAuthn specifies. The W3C Web Authentication API (Level 3) and the FIDO2/CTAP authenticator protocols bind a credential to the *origin* — the site's identity — so a credential created for `example.com` is unusable at an attacker's look-alike domain. Motivationally, the goal is not a stronger sixth digit; it is removing the shared secret from the picture so that a stolen or relayed code has nothing to be stolen from.

## 2. The Core Mechanism

**Actors.** WebAuthn names three parties. The **Relying Party (RP)** is "the entity whose web application utilizes the Web Authentication API to register and authenticate users"; it holds a server-side component (spec §4). The **client** is the browser or platform that mediates. The **authenticator** is the hardware or software component that generates and stores credentials — a platform authenticator (e.g. a built-in fingerprint sensor) or a roaming authenticator (e.g. a USB security key).

**The credential.** A public key credential is a public–private key pair. It is unique per RP, per user account, and per authenticator. The private key never leaves the authenticator; the RP learns only the public key.

**Two ceremonies.** The spec describes "two distinct, but related, ceremonies": **Registration**, "where a public key credential is created on an authenticator, and scoped to a Relying Party with the present user's account"; and **Authentication**, "where the Relying Party is presented with an Authentication Assertion proving the presence and consent of the user who registered the public key credential". Both are challenge/response: the RP supplies a fresh challenge, the authenticator signs over it with the private key, and the RP verifies with the stored public key. Because the challenge is fresh per ceremony, a captured assertion cannot be replayed.

**RP ID and origin binding.** This is the security heart of the protocol. The spec defines the relying party identifier (RP ID) as "a valid domain string identifying the WebAuthn Relying Party", and states plainly that "a public key credential can only be used for authentication with the same entity (as identified by RP ID) it was registered with". The client passes the RP's origin and RP ID to the authenticator, and "the authenticator ensures that credentials created by a Relying Party can only be used in operations requested by the same RP ID" (§4). Scope is deliberately separated from origin so that one RP may span multiple origins, while still refusing to sign for anyone else.

**User verification (UV).** The spec defines UV as "the technical process by which an authenticator locally authorizes the invocation of the authenticatorMakeCredential and authenticatorGetAssertion operations", through a gesture such as "a touch plus pin code, password entry, or biometric recognition" — "the intent is to distinguish individual users" (§4). UV is configured by the RP per ceremony.

**No secret on the server.** Because the server stores only a public key, a server breach yields nothing a thief can authenticate with. This is the property T/Key pursued through hash chains (Chapter 5); WebAuthn reaches it through public-key cryptography, and it is the direct answer to the recurring failure of Chapters 6 and 7 — the shared secret that, once exfiltrated, is the second factor for *every* user.

**Passkeys and syncing.** The spec distinguishes two credential modes by a permanent property, **backup eligibility**: a backup-eligible credential is a **multi-device credential**, one that is not is a **single-device credential** (§4). Authenticator data carries two flags: the **BE** flag is set "if and only if the credential is a multi-device credential" and must not change after registration; the **BS** flag is set "if and only if the credential is a multi-device credential and is currently backed up" (§6.1). The allowed combinations are `00` (single-device), `10` (multi-device, not backed up), and `11` (multi-device, backed up); `01` is not allowed. Multi-device credentials are what the industry calls **synced passkeys**, and the spec's consumer use case advertises them as "phishing-resistant sign in" (§1.2.1); the workforce use case pairs a roaming key with a platform authenticator for single-device credentials (§1.2.2).

Syncing is where the book's central question returns. A synced passkey's private key is backed up to a cloud **passkey management service** (PMS) — iCloud Keychain, Google Password Manager, and others — so the secret no longer lives only on the device. The device-bound/phishing-resistant property of the *ceremony* survives, but a new copy of the secret now exists in the cloud.

## 3. Security Analysis and Empirical Findings

**What the origin binding does and does not buy.** Against *remote* phishing, RP-ID binding is decisive: a credential simply will not sign for the attacker's origin, and the challenge makes assertions non-replayable. But the guarantee is scoped to the signing ceremony. Once a private key can be *copied*, an attacker who holds a copy logs in legitimately from anywhere, and the origin check cannot tell the difference.

**Abusability in interpersonal threat models.** Daffalla et al. (USENIX Security 2025) build a six-stage abusability-analysis framework and apply it to passkeys, investigating **19 passkey-supporting services and four passkey providers**, hypothesising **seven abuse vectors**, and running stepthroughs across iOS, macOS, Windows and Android (the paper reports **87 stepthroughs** overall, e.g. 30 for the adversarial-biometric vector and 21 for cloning). The abuses are not remote phishing but local access — the threat model of an intimate partner, family member or co-worker with periodic physical access to an unlocked device:

- **Adversarial biometrics.** Because FIDO2 "does not support binding passkey operations to specific user biometrics", an attacker who unlocks the device with the known PIN can add their *own* fingerprint; any registered biometric then unlocks any passkey on the device. Adding a biometric triggers no notification on macOS, Android or Windows 10, and removal may require deleting *all* biometrics.
- **Passkey cloning.** Credential portability lets an attacker with one-time access copy a passkey — via AirDrop export, Apple's shared password groups, or by signing into the victim's iCloud and keeping a local keychain copy. The paper reports ongoing remote access for CVS, Porkbun and TikTok that the victim "could not detect" and for which they "could determine no way to revoke access".
- **Adversarial passkeys and denial of service.** Adding a remote passkey (successful on ten services), revoking the victim's passkeys (eleven services), or deleting them locally all deny or hijack access. Revocation often does **not** terminate live sessions: on Adobe, GitHub, LinkedIn and Samsung a passkey-authenticated session was still valid more than 60 minutes after revocation.
- **Gaslighting.** Service account-security interfaces are spoofable — by changing the user-agent string, using a VPN, or editing passkey labels — so an abuser can mislead a victim about who has access.

The paper's own framing is careful: many of these are implementation bugs in "immature" deployments (leaking credential IDs to unauthenticated clients at PayPal and Porkbun — a pattern the WebAuthn spec itself flags as a privacy consideration in §14.6.3, non-normatively; stale credentials; unrevocable passkeys), but some are "passkey-specific" and not inherited from passwords — notably that one account can hold many active passkeys, and that passkeys are conflated with passwords in UIs. Crucially, the authors state the security trade-off directly: because device compromise now grants access to *all* credentials on the device, "credential security is thus reduced to device security."

**Recovery is the weakest link.** Amft et al. (ACM CCS 2023) study MFA recovery precisely because a strong second factor is only as strong as the path to reset it. They evaluate the documented recovery procedures of **1,303 MFA-supporting websites** and then create accounts on and test recovery for a subset of **71 websites**. They regained access to **37 (52.11%)** and lost **30 (42.25%)** (with no answer from 4, 5.63%). The security finding is blunt: for **26 (70.27%)** of the accounts they recovered, "having access to the account's associated email address was sufficient for account recovery". In many cases the deployed procedure did not match the published help pages, so users following official documentation were often misled. A phishing-resistant first factor sitting behind an email-resettable recovery path is not phishing-resistant.

**Adoption and deployment cost.** Two further studies bound how far the migration has gone. Lassak et al. (USENIX Security 2024) interviewed **28** CISOs, authentication managers and FIDO2 experts; the biggest reported obstacles to FIDO2 deployment were **fallback and recovery options**, complexity and friction, technical issues (browser support, revocation), regulatory requirements, and security culture — and experts and deployers disagreed about which obstacles were most pressing. The large-scale crawl by Bhardwaj and Sastry (*State of Passkey Authentication in the Wild*, arXiv preprint 2602.15135, 2026) applies a browser crawler with **43 heuristics** to the top **100,000** Tranco domains and finds adoption "strongly correlates with site popularity": **20%** of the top 100 sites support passkeys versus **6.9%** of sites ranked 50K–100K, a nearly 3× gap; many deployments are delegated to external identity providers rather than native WebAuthn; and manual directories capture less than 4% of actual deployments. For scale, Daffalla et al. note that Google reported over 400 million accounts with passkeys enabled as of May 2024.

**Breach detection for synced keys.** Islam et al. (USENIX Security 2025) make the syncing risk explicit: because synced passkeys back up FIDO2 private keys to a PMS's cloud storage, "attackers can steal users' passkeys through breaches of PMS's cloud storage and use them to take over their web service accounts". Their CASPER framework — the first passkey-breach-detection framework — hides the real passkey among indistinguishable decoy passkeys so that a stolen credential is likely to trigger detection at the RP when used, without reintroducing account-recovery friction. That the leading remedy is *detection* rather than prevention is itself the point: once the secret is in the cloud, it is no longer solely on the device.

## 4. Applicability and Migration Boundaries

Chapter 7 ended by pointing, for high-value accounts, "away from shared secrets and phishable codes toward phishing-resistant authenticators such as WebAuthn/passkeys". This chapter makes that advice precise — including where it stops being true.

**Where WebAuthn is clearly better.** Any account whose main threat is *remote* credential theft — phishing, credential stuffing, a server breach that leaks secrets — gains decisively. There is no shared secret to relay, the RP ID refuses the attacker's origin, and a database breach yields only public keys. For a workforce with a roaming hardware key, the single-device (`BE=0`) model also gives a non-exportable credential.

**Where TOTP remains adequate or irreplaceable.** TOTP still fits when: a hardware token (or a platform authenticator with biometrics) is not available or not permitted; the second factor must work **offline**, without a browser or an online RP challenge; a **cross-device** login is needed **without** trusting any cloud sync; or a legacy/air-gapped system cannot implement a WebAuthn RP at all. TOTP's cost — a shared secret — is real, but it is a known, auditable risk, and RFC 6238's core analysis remains unbroken (Chapters 3–4). WebAuthn is not a drop-in replacement for these cases, and the RFC 6238 line of work remains the right tool for them.

**The preconditions of "phishing-resistant".** The phrase only holds when several conditions do:

1. **The ceremony is enforced by a trusted client.** Origin binding is implemented in the browser/OS; the spec notes that platforms mimicking the API "MAY define different rules" for binding a caller to an RP ID. Trusting the client is part of the assumption.
2. **The credential is not copyable in practice.** For synced (multi-device, `BE=1`) passkeys, phishing resistance protects the *signing ceremony*, not the key: a cloned or cloud-leaked key authenticates normally (Daffalla; Islam). The `BE`/`BS` flags let an RP see this state, but only if it acts on it.
3. **User verification verifies the right person.** FIDO2 does not bind a passkey to a specific biometric, so on a shared or physically accessible device, UV confirms "a" registered user, not necessarily the owner.
4. **Recovery is no weaker than authentication.** If an email address (Amft) or a session that outlives revocation (Daffalla) restores access, the phishing resistance of the front door is moot.

**Comparison.** The table summarises the two families across the dimensions this book has used throughout (threat model, usability, deployment cost); every cell traces to a source above.

| Dimension | TOTP (RFC 6238) | WebAuthn / Passkeys (W3C L3; FIDO2) |
|---|---|---|
| Credential | Symmetric key $K$ shared by phone and server | Public–private key pair, unique per RP, account and authenticator (§4) |
| Phishing (remote) | Not resistant: code is a transferable bearer token; validator cannot tell when/where it was generated (RFC 6238 §5.2) | Resistant at the ceremony: credential only signs for the RP ID it was registered with (§4) |
| Server breach | Leaks the shared secret for every user | Server holds only the public key; breach yields no usable credential |
| Clock / replay | Depends on local clocks; a step can be reused within the window; forward-replay (Chapter 7) | Fresh RP challenge per ceremony; no shared clock assumption |
| Recovery | Backup codes / support; in practice often bypassable via email (Amft: 70.27%) | Cloud sync / multiple passkeys; cloning and non-revocable credentials arise (Daffalla) |
| Usability | Type six digits; works offline | Biometric/PIN gesture; needs no code; cross-device needs sync |
| Deployment cost | Low: a shared secret on both sides | High: browser, OS and service must all support it; fallback/recovery gaps are the top obstacle (Lassak) |

<div class="aside">
<p><span class="aside-label">Aside · What the spec actually calls a "passkey"</span></p>
<p>"Passkey" is the word on every consumer sign-in screen, but in the WebAuthn specification's own terminology list it appears only as a synonym: the technical name is <em>client-side discoverable credential</em>, and "passkey" is listed beside it (§4). The same entry marks the older terms <em>resident credential</em> and <em>resident key</em> as [DEPRECATED]. A note explains why the old words linger: <code>ResidentKey</code> and <code>residentKey</code> are already written into API dictionary member names and operation parameters, so they cannot be renamed without breaking compatibility.</p>
<p class="aside-source">Source: W3C, <em>Web Authentication: An API for accessing Public Key Credentials, Level 3</em>, §4 Terminology (entry "Client-side discoverable Public Key Credential Source"; the [DEPRECATED] markers and the note on <code>residentKey</code> backwards compatibility come from that same entry).</p>
</div>

## 5. Related Literature

- **RFC 6238, TOTP** ([rfc-editor.org/rfc/rfc6238](https://www.rfc-editor.org/rfc/rfc6238)) and **RFC 4226, HOTP** ([rfc-editor.org/rfc/rfc4226](https://www.rfc-editor.org/rfc/rfc4226)) — the shared-secret schemes this chapter departs from; the "validator does not know when the code was generated" statement is RFC 6238 §5.2.
- **FIDO Alliance, FIDO2 / CTAP specifications** ([fidoalliance.org/specifications](https://fidoalliance.org/specifications/)) — the authenticator-side companion to WebAuthn (see the specification's relevant sections on authenticator operations).
- **W3C, Web Authentication Level 3** ([w3.org/TR/webauthn-3](https://www.w3.org/TR/webauthn-3/)) — the normative source for RP ID, origin binding, user verification, and the BE/BS backup flags.
- **Kogan, Manohar, Boneh, T/Key, CCS 2017** ([arXiv:1708.08424](https://arxiv.org/abs/1708.08424), Chapter 5) — the earlier attempt to keep a *time-based* factor with *no server secret*; WebAuthn answers the same design pressure with public-key cryptography.
- **Daffalla et al., USENIX Security 2025** ([PDF](https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf)) — the first analysis of passkeys in interpersonal threat models; seven abuse vectors, 19 services.
- **Amft et al., CCS 2023** ([arXiv:2306.09708](https://arxiv.org/abs/2306.09708)) — the recovery side of the MFA story, and why a strong first factor can be undone downstream.
- **Lassak, Pan, Ur, Golla, USENIX Security 2024** — *Why Aren't We Using Passkeys? Obstacles Companies Face Deploying FIDO2 Passwordless Authentication*; 28 interviews on deployment barriers.
- **Islam, Arora, Chatterjee, Wang, USENIX Security 2025** ([PDF](https://www.usenix.org/system/files/usenixsecurity25-islam.pdf)) — CASPER, detecting the abuse of synced passkeys leaked from cloud storage.

The literature does not present WebAuthn as a finished panacea. The research community treats the *cryptographic* direction (public keys, origin binding) as settled and correct, while treating *deployment* — syncing, recovery, revocation, and the interpersonal threat models that consumer products overlook — as an open and actively adversarial frontier. This is the same lesson the whole book has drawn: the algorithm is rarely the weakest link; the ecosystem around it is.

## 6. Summary and Callbacks

- TOTP is not phishing-resistant because its code is a transferable bearer token: it says nothing about the origin or the presenter, and a real-time relay works inside the RFC 6238 acceptance window (§5.2).
- WebAuthn replaces the shared secret with a per-account key pair, scoped to a Relying Party by **RP ID**: a credential can only be used for the entity it was registered with, and "the authenticator ensures" this scoping (§4).
- Registration creates a credential; authentication returns an assertion over a fresh **challenge**; **user verification** is a local gesture whose intent is "to distinguish individual users" (§4).
- The server stores only a public key, so a server breach is no longer a whole-population second-factor leak — the goal T/Key pursued by other means (Chapter 5).
- **Passkeys** are credentials by backup eligibility: **multi-device** (synced, `BE=1`) or **single-device** (`BE=0`), with the **BS** flag reporting current backup state (`00`/`10`/`11` allowed, `01` not; §6.1).
- Syncing moves the secret to a cloud passkey management service, reintroducing the book's core question: a PMS breach can leak usable keys (Islam et al.), and cloning defeats phishing resistance in practice (Daffalla et al.).
- Recovery is frequently the weakest link: with access to the account's email, Amft et al. recovered 26 (70.27%) of the accounts they recovered at all, and deployed procedures often contradicted the help pages.
- Migration is a spectrum, not a switch: WebAuthn is decisive against remote phishing and breach, while TOTP remains appropriate for offline, hardware-less, or non-syncing cross-device use; "phishing-resistant" holds only when the client is trusted, the key is not copyable, UV verifies the right person, and recovery is no weaker than authentication.

**Callbacks.** The book opened in Chapter 1 with Lamport's 1981 move: take the secret off the server, because a server that stores what logs you in is a server that can be made to surrender it. WebAuthn reaches that same end by a different road — public-key cryptography instead of a hash chain — and it is the destination T/Key sought in Chapter 5: a factor with an origin that leaves no usable secret behind on the server. But the secret did not vanish; it moved. For a synced passkey the private key is handed to the device and, through the platform's cloud, to a passkey management service, so the question that opened the book — <em>where does the secret live?</em> — has been pushed forward, not answered away. Chapter 5 could still ask whether a server can be trusted when it holds nothing; this closing chapter shows what happens when the secret is entrusted to the device and the platform instead. That makes this the book's last gesture rather than its last word: the shared secret has left the stage, and the question it posed remains open — now pointed at recovery, revocation, and the cloud.

## References

1. W3C. *Web Authentication: An API for accessing Public Key Credentials, Level 3.* Candidate Recommendation Snapshot, 26 May 2026. https://www.w3.org/TR/webauthn-3/
2. FIDO Alliance. *FIDO2 / CTAP specifications.* https://fidoalliance.org/specifications/
3. Alaa Daffalla, Arkaprabha Bhattacharya, Jacob Wilder, Rahul Chatterjee, Nicola Dell, Rosanna Bellini, Thomas Ristenpart. *A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal Threat Models.* USENIX Security 2025. https://www.usenix.org/system/files/usenixsecurity25-daffalla.pdf
4. Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments.* ACM CCS 2023. https://arxiv.org/abs/2306.09708
5. Leona Lassak, Elleen Pan, Blase Ur, Maximilian Golla. *Why Aren't We Using Passkeys? Obstacles Companies Face Deploying FIDO2 Passwordless Authentication.* USENIX Security 2024, pp. 7231–7248. https://www.usenix.org/system/files/usenixsecurity24-lassak.pdf
6. Mazharul Islam, Sunpreet S. Arora, Rahul Chatterjee, Ke Coby Wang. *Detecting Compromise of Passkey Storage on the Cloud.* USENIX Security 2025. https://www.usenix.org/system/files/usenixsecurity25-islam.pdf
7. Prince Bhardwaj, Nishanth Sastry. *State of Passkey Authentication in the Wild: A Census of the Top 100K sites.* arXiv preprint 2602.15135, 2026. https://arxiv.org/abs/2602.15135
8. David M'Raihi, Salah Machani, Mingliang Pei, Johan Rydell. *TOTP: Time-Based One-Time Password Algorithm.* RFC 6238, IETF, 2011. https://www.rfc-editor.org/rfc/rfc6238
9. David M'Raihi, Mihir Bellare, Frank Hoornaert, David Naccache, Ohad Ranen. *HOTP: An HMAC-Based One-Time Password Algorithm.* RFC 4226, IETF, 2005. https://www.rfc-editor.org/rfc/rfc4226
10. Neil Haller. *The S/KEY One-Time Password System.* RFC 1760, IETF, 1995. https://www.rfc-editor.org/rfc/rfc1760
11. Dmitry Kogan, Nathan Manohar, Dan Boneh. *T/Key: Second-Factor Authentication from Secure Hash Chains.* ACM CCS 2017, pp. 983–999. https://arxiv.org/abs/1708.08424
12. Sanam Ghorbani Lyastani, Michael Schilling, Michaela Neumayr, Michael Backes, Sven Bugiel. *Is FIDO2 the Kingslayer of User Authentication? A Comparative Usability Study of FIDO2 Passwordless Authentication.* IEEE S&P 2020. https://doi.org/10.1109/SP40000.2020.00048

## Fact-Check List

Every number and claim in the text above, with its source location.

| Claim in the text | Source |
|---|---|
| TOTP code is $\mathrm{TOTP}(K,T)=\mathrm{HOTP}(K,T)$ | RFC 6238 §4 |
| "validator does not know a client's exact timestamp when an OTP was generated"; at most one time step accepted as delay | RFC 6238 §5.2 (quoted) |
| Relying Party definition ("the entity whose web application utilizes the Web Authentication API…") | WebAuthn L3 §4 |
| "two distinct, but related, ceremonies" (Registration / Authentication) | WebAuthn L3 §4 |
| RP ID is "a valid domain string identifying the WebAuthn Relying Party"; credential usable only with the same entity it was registered with; authenticator ensures same-RP-ID use | WebAuthn L3 §4 (quoted) |
| Credential unique per RP, account, authenticator | Daffalla et al. §2 (FIDO2 background) |
| User verification definition and "intent is to distinguish individual users" | WebAuthn L3 §4 (quoted) |
| backup eligibility → multi-device / single-device credential; multi-device = "synced passkeys" | WebAuthn L3 §4; §1.2.1 (quoted for terminology) |
| BE flag set iff multi-device and immutable after registration; BS flag set iff multi-device and currently backed up; combinations 00/10/11 allowed, 01 not | WebAuthn L3 §6.1 (table and flag text) |
| Consumer (multi-device) use case described as "phishing-resistant sign in"; workforce use case uses single-device credentials | WebAuthn L3 §1.2.1, §1.2.2 |
| Platforms mimicking the API "MAY define different rules" for binding a caller to an RP ID | WebAuthn L3 §4 |
| Privacy leak via credential IDs with non-empty `allowCredentials` (non-normative) | WebAuthn L3 §14.6.3 |
| Daffalla method: six-stage abusability framework; 19 services, 4 providers; 7 abuse vectors; 87 stepthroughs; 30 biometric stepthroughs; 21 cloning | Daffalla et al., Abstract and §3–§5 |
| FIDO2 "does not support binding passkey operations to specific user biometrics"; adversarial biometric added with victim's PIN; no notification on macOS/Android/Windows 10 | Daffalla et al. §5.1 |
| Cloning via AirDrop, shared password groups, iCloud sign-in; ongoing undetectable, non-revocable access on CVS, Porkbun, TikTok | Daffalla et al. §5.2 (and Abstract) |
| Adversarial passkeys succeed on ten services; revocation succeeds on eleven; session still valid >60 min after revocation on Adobe, GitHub, LinkedIn, Samsung | Daffalla et al. §5.3, §5.5; Figure 7 |
| "credential security is thus reduced to device security" | Daffalla et al. §2 (quoted) |
| Credential-ID leak to unauthenticated clients at PayPal and Porkbun | Daffalla et al. §4(c) |
| Amft method: 1,303 websites documented; 71 tested; regained 37 (52.11%), lost 30 (42.25%), no answer 4 (5.63%); email access sufficient 26 (70.27%) | Amft et al. Abstract, §3.2.2, §3.2.3 |
| Lassak: 28 semi-structured interviews; biggest obstacles = fallback/recovery, friction, technical, regulatory, security culture | Lassak et al. Abstract and §1 |
| Bhardwaj & Sastry: 43 heuristics over 1,500 sites; top 100K Tranco; 20% of top 100 vs 6.9% of 50K–100K; adoption correlates with popularity; manual directories <4% | Bhardwaj & Sastry, Abstract and §5.3 |
| Islam: synced passkeys back up private keys to PMS cloud; breach enables account takeover; CASPER is first breach-detection framework | Islam et al. Abstract and §1 |
| Google reported 400 million accounts with passkeys as of May 2024 | Daffalla et al. §1 (citing Google) |

## Open / Unverified Items

- **FIDO2/CTAP text not read directly.** Only the FIDO Alliance specifications page was consulted; the chapter therefore names CTAP generically and cites the page rather than any clause number.
- **WebAuthn version.** The spec snapshot read is the Level 3 Candidate Recommendation Snapshot dated 26 May 2026; section numbers cited are from that snapshot and may shift in later drafts.
- **Daffalla stepthrough count.** The paper states "we performed 87 stepthroughs" in its Stage-5 summary, while its per-vector figures (30 + 21 + 21 + 12 + 12) do not obviously sum to 87. Both are reported as stated in the source; the discrepancy is not resolved here.
- **Bhardwaj & Sastry is a preprint (arXiv 2602.15135, 2026);** its numbers are not peer-reviewed and are labelled as such in the text.
- **Publication venue discrepancy.** The handoff and the project's material manifest list Amft et al., *"We've Disabled MFA for You"* as USENIX Security 2023. The paper's own ACM reference format places it at **ACM CCS '23** (November 2023, Copenhagen). The text above follows the source (CCS 2023); the manifest should be corrected.
- **The 29-day detection threshold and other CASPER internals** were not examined in detail; the chapter uses only the paper's framing and motivation.

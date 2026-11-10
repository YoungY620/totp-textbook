# A Formal Analysis of Master-Password-Protected Password Management Protocols (S&P 2025)

<div class="source-card">
<p><strong>Source:</strong> Yihe Duan, Ding Wang, Yanduo Fu. <em>Security Analysis of Master-Password-Protected Password Management Protocols</em>. 2025 IEEE Symposium on Security and Privacy (S&P), pp. 701–719. <a href="https://doi.org/10.1109/SP61157.2025.00050">DOI</a> · <a href="https://github.com/DanielNKU/pm-analysis">public artifact (raw data for the paper)</a></p>
<p><strong>In one line:</strong> The first formal, universal-composability treatment of the protocol that carries a master password between a client and a password manager's server: of 43 password managers, 38 fail against at least one of four offline-guessing adversaries, and only designs that add a second high-entropy secret resist all of them.</p>
</div>

<div class="hook">Picture the pitch: your vault is sealed with AES-256, the vendor never sees your master password, and the server holds nothing but ciphertext. Now hand that same server the keys to the conversation — the login handshake, the salt, the iteration count the client is told to use — and ask whether the vault still holds. The cipher can be impeccable while the protocol that carries the master password to it quietly hands a corrupted server everything it needs to test guesses offline.</div>

## 1. Background and Motivation

Password managers (PMs) are recommended by standards bodies (NIST, NCSC) and by security experts because they let users generate long, unique passwords instead of reusing short ones. The paper opens with the scale of the problem: users now have to track 80–168 accounts, and the coping behaviours — popular passwords such as `123456` and `password`, reuse, and passwords built from personally identifiable information — are precisely what makes guessing attacks damaging.

Concentrating every credential in one vault makes that vault a target. The paper cites LastPass, which suffered three breaches in as many years; although LastPass claimed no passwords were compromised in its 2022 breach, the incident has since been linked to a theft of about 4.4 million US dollars in cryptocurrency. Users' distrust is twofold: fear of a breach, and limited willingness to hand all their credentials to a third party. Vendors answer both with the phrase "zero-knowledge encryption".

The object of study is what the authors name the **Master-Password-Protected Password Management (M3PM) protocol**: the cryptographic protocol by which a client authenticates with a master password and retrieves credentials from the PM's server while the vault stays oblivious to the server. Their framing carries a warning: **secure encryption of a vault does not imply a secure M3PM protocol.** An unsuitable combination of authentication and encryption introduces vulnerabilities (§5.4 of the paper), and an M3PM protocol has security goals beyond the confidentiality of the vault (§4.1).

Earlier analyses had looked past the protocol. Gasti and Rasmussen (ESORICS 2012) gave the first rigorous analysis of PM vault *storage formats* with indistinguishability and non-malleability games, and Oesch and Ruoti (USENIX Security 2020) replicated that study three years later. Both evaluated a format, not a protocol, and so neglected client authentication and offline guessing of the master password. Zhao et al. and Zhao and Yue showed that insecure storage of the master-password/authenticator relationship leaves vaults open to offline cracking; Bojinov et al. (Kamouflage) and Chatterjee et al. (NoCrack) proposed honey vaults that resist guessing on a leaked vault. Closest in spirit, Davies et al. (CRYPTO 2023) formalised WhatsApp's backup protocol as a password-protected key retrieval (PPKR) functionality in the UC framework — but one password there retrieves *one* key, whereas a master password must protect *many* passwords simultaneously.

Three research questions structure the work: RQ1, which M3PM protocols do existing PMs actually use; RQ2, what defines a secure M3PM protocol; RQ3, whether existing PMs are secure under those definitions.

## 2. Core Content

**Two kinds of PM.** *Retrieval* PMs (1Password, LastPass) store credentials in an encrypted vault; *generative* PMs (LessPass, SPHINX) derive each password on demand from the master password plus site metadata through a deterministic function such as an OPRF or a hash. The paper covers the basic memorise/retrieve function, not sharing or single sign-on.

**Selection.** The authors collected candidate PMs in September–October from app stores, annual editorial lists, and GitHub (open-source projects with over 1,000 stars), and academic schemes from DBLP and Google Scholar. They then dropped PMs with fewer than 10,000 installations, academic schemes whose focus was not security, and PMs that could not be set up. The final set is **43 PMs: 36 popular industrial and 7 representative academic** ones.

**Collection methodology** cross-verifies three channels. *Documentation* (whitepapers, READMEs, expert blogs) supplies a first sketch; *data logs* add network traffic captured with Burp Suite **before TLS** and local storage files from Windows, Linux and macOS installs; *application code* is examined statically to locate algorithms (`AES256`, `PBKDF2`, `Argon2`, `master`, …) and then dynamically, by setting browser breakpoints and reading the real parameter values such as KDF iteration counts. Results: 24 of the 36 industrial PMs required reverse engineering, 32 produced useful data logs, only 6 were analysed mainly from documentation, and 27 yielded enough for in-depth analysis. All raw data is public. Not relying on TLS is deliberate: in this threat model the server itself may be malicious, so TLS between the client and a malicious server buys nothing.

**The anatomy of a protocol.** Every M3PM protocol has two stages.

*Authentication* (explicit, client to server) takes one of five forms:

1. sending a hash of the master password, $h_{\mathsf{pw}} = H(\mathsf{mpw}, \mathsf{salt})$;
2. sending a protected token, $\mathsf{eauth} = \mathrm{Enc}_{H(\mathsf{mpw})}(\mathsf{auth})$, alongside the plaintext $\mathsf{auth}$;
3. a PAKE such as SRP, with verifier $v = g^{H(\mathsf{mpw}, \mathsf{ID}_{C}, \mathsf{salt})}$;
4. answering a server challenge with the master password (*mpw challenge*);
5. answering a challenge with a public key (*pk challenge*), the server holding $\mathsf{pk}_{C}$ and the encrypted private key $\mathsf{esk}$.

*Password processing* then proceeds in one of four ways:

- **mpw encrypt**: $e\mathsf{Vault} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{Vault})$;
- **device-key encrypt**: the server receives $e\mathsf{vk} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{vk})$ and $e\mathsf{Vault} = \mathrm{Enc}_{\mathsf{vk}}(\mathsf{Vault})$;
- **encode-then-encrypt** (honey-vault style): $e\mathsf{Vault} = \mathrm{Enc}_{H(\mathsf{mpw},\mathsf{salt})}(\mathsf{encode}(X,\mathsf{Vault}))$;
- **generative**: only parameters are stored.

**The formal model.** The security goals are formalised in the universal composability (UC) framework, so that security is preserved when the protocol runs alongside others. The threat model gives the adversary the ability to corrupt the server and read all its stored data; the malicious server may send messages that deviate from the protocol; the channel is TLS-protected but this is assumed irrelevant; neither party operates in a trusted environment.

Seven security goals are required: **indistinguishability of passwords**; **non-malleability of passwords**; **obliviousness of the master password** (neither initialisation nor retrieval leaks information about it to the server); **pseudorandom generated passwords**; **resistance to password guessing**, captured by a `TESTMPW` query in the relaxed functionality; **resistance to leakage of partial passwords** (modelled one credential at a time, so that one leaked password does not break the others); and **authentication**, meaning retrieval must use the same master password as initialisation.

The authors define a base ideal functionality $F_{\mathsf{M3PM}}$, then refine it. $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ covers *explicit* authentication, where the server answers a failed attempt with a `FAIL` signal, and $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$ covers *implicit* authentication, where on failure the server returns a random, independently incorrect password drawn to follow Zipf's law, as honey encryption does. Because the base functionality demands resistance to guessing, which is a very strong requirement for a design whose only secret is a human password, they add a relaxed $F^{r}_{\mathsf{M3PM}}$ containing the `TESTMPW` query and placing **no bound** on the number of guesses — unlike the PPKR functionality, which allows 10. Finally $F^{\mathsf{ad}}_{\mathsf{M3PM}}$ replaces $\mathsf{mpw}$ throughout by a tuple $(\mathsf{mpw}, \mathsf{secretkey})$, to capture designs that add a second secret.

Only two parties are modelled: one-party local PMs are analysed by assigning them a server for synchronisation, and three-party device-assisted protocols are left to future work.

**Worked example — 1Password.** In the paper's Protocol OP the client inputs a master password $\mathsf{mpw} \in \mathrm{Zipf}(n)$, a secret key $\mathsf{SecretK} \in \{0,1\}^{n}$, login metadata and the password. Registration computes a master authenticator and a master key from *two* independent secrets:

$$x = H_{1}(\mathsf{mpw},\mathsf{ID}_{C}) \oplus H_{1}(\mathsf{SecretK},\mathsf{ID}_{C}), \qquad \mathsf{mk} = H_{2}(\mathsf{mpw},\mathsf{ID}_{C}) \oplus H_{2}(\mathsf{SecretK},\mathsf{ID}_{C}),$$

then $\mathsf{esk} = \mathrm{AE}.\mathrm{Enc}_{\mathsf{mk}}(\mathsf{sk})$, $e\mathsf{vk} = \mathrm{PKE}.\mathrm{Enc}_{\mathsf{sk}}(\mathsf{vk})$ and $e\mathsf{Vault} = \mathrm{AE}.\mathrm{Enc}_{\mathsf{vk}}(\mathsf{Vault})$. The server holds only $(e\mathsf{vk}, \mathsf{esk}, e\mathsf{Vault})$ plus the authenticator $x$ submitted through a password-authentication functionality. The XOR of two independently derived values is what lets this design resist every level of adversary below.

## 3. Security Analysis

Offline guessing rests on two facts. First, low entropy: human passwords carry roughly $2^{20}$–$2^{22}$ bits of entropy, whereas AES offers 128, 192 or 256-bit keys, so a guessed password succeeds with non-negligible probability. Second, offline verifiability: once the server's database is in hand, the adversary has a value against which guesses can be tested.

**GuessVerify.** The authors formalise this test as $\mathrm{GuessVerify}(m, X, \sigma)$: given a candidate string $m$, a distribution $X$ over correct values, and the adversary's confidence threshold $\sigma$, it returns $\delta = 1$ when the probability of $m$ under $X$ exceeds $\sigma$. With $X$ set to the Zipf distribution and $\sigma = 0.1$, for instance, `123456abc` is accepted as a plausible password while `Q!='GhEuk76!WH+92Rf` is not — even though the latter is the sort of value a generator produces.

**How a corrupted server verifies guesses.** Each authentication style fails differently. With hashed passwords the server checks $h_{\mathsf{pw}} \stackrel{?}{=} H(\mathsf{mpw}',\mathsf{salt})$; with protected tokens it decrypts $\mathsf{eauth}$ under $H(\mathsf{mpw}')$ and compares with the plaintext token; with SRP it recomputes $v' = g^{H(\mathsf{mpw}',\mathsf{ID}_{C},\mathsf{salt})}$; with an mpw challenge it already holds the plaintext master password; with a pk challenge it decrypts $\mathsf{sk}'_{C} = \mathrm{Dec}_{H(\mathsf{mpw}')}(\mathsf{esk})$ and validates against $\mathsf{pk}_{C}$. In the processing stage, both *mpw encrypt* and *device-key encrypt* let the server derive $\mathsf{mk}' = H(\mathsf{mpw}',\mathsf{salt})$, decrypt, and either observe an authenticated-decryption failure (AES-GCM) or run GuessVerify on a garbled plaintext.

**Honey vaults do not close the gap.** encode-then-encrypt assumes a wrong-key decryption still follows the same distribution $X$ as real passwords; an adversary that feeds the same $X$ into GuessVerify therefore accepts the decoys too. Adaptive distributions break it: `abc12345` is plausible under Zipf yet impossible for a site requiring a special character, and once the adversary knows one true password in the vault it can verify guesses with high confidence. Generative schemes resist offline guessing because there is nothing to verify against — until a single generated password leaks, after which the adversary guesses the master password and regenerates it.

**Four adversary types.** Type-I can only interact with the protocol (every PM resists, since there is nothing to verify against). Type-II corrupts the server: 1Password and Multipassword resist through their second secret, LessPass/Gokey/SPHINX/Amnesia store no vault value, NoCrack and Kamouflage use encode-then-encrypt, and BluePass and Tapas rely on another device. Type-III additionally knows partially leaked passwords, which defeats LessPass and Gokey. Type-IV combines the last two, and only a second secret (1Password, Multipassword) or a second device (BluePass, Tapas) resists it.

**The headline numbers.** 38 of the 43 PMs are vulnerable to at least one offline-guessing type; 34 of the 43 cannot fulfil $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ or $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$ once the server is compromised; 35 PMs use PBKDF2 or Argon2 to slow guessing down; and only 1Password and Multipassword achieve $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$. The authors give provable analyses of eight distinct protocols; six PMs could not be proven in the model (Norton, Chrome and Passwarden for lack of information; Amnesia, BluePass and Tapas because they use three parties). The analysis took nearly four months, treating every failed proof as a lead.

**Two concrete failures.** Delinea Web performs no client-side cryptography at all, so its communication is fully plaintext. Passbolt suffers an oracle attack in which a corrupted server can learn the encryption key (§5.4).

**Metadata privacy.** 30 of the 43 PMs leave metadata unencrypted, violating the indistinguishability and non-malleability of metadata. Tampered metadata is more dangerous than a tampered password: an adversary can rewrite a URL to a phishing site, and the autofill or click-to-jump feature then delivers the credential there. The authors verified that Zoho Vault's offline version lets an adversary tamper with the URL.

**Responsible disclosure.** Findings were reported to the two affected vendors. Delinea confirmed the vulnerability but replied that it does not consider a malicious server part of its threat model; the authors held an in-depth discussion with Passbolt and supplied mitigation recommendations.

**The insight.** Every PM that resists offline guessing adds another high-entropy secret — an extra secret string (1Password, Multipassword) or a second device (BluePass, Amnesia, Tapas). Without one, a single master password simply cannot supply enough entropy, and the protocol leans entirely on slow or memory-hard functions such as PBKDF2 or Argon2.

## 4. Applicability and Transfer Boundaries

The result that travels furthest is qualitative and model-level: **a vault protected by one human-chosen master password has a hard ceiling**, and that ceiling is the entropy of the password, not the strength of the cipher. Everything downstream — which products are secure, and under which adversary — follows from whether a second secret exists.

The premises matter. The adversary *corrupts the server* and reads its stored state; the server may deviate arbitrarily; TLS is assumed but irrelevant; the client is honest; the analysis is two-party. Within that model the conclusions are as strong as such results get: UC proofs for eight protocols plus a systematic case-by-case argument for the rest, not measurements. Beyond it the guidance thins. Three-party device-assisted designs are explicitly outside the model, so their apparent immunity is an artefact of scope. Metadata is deliberately excluded from the functionality (Remark 1) — bundled away so that unencrypted metadata in 1Password does not mask the strength of its dual-key mechanism — so the model says nothing about the phishing-via-autofill risk that §5.2 documents.

There is also a real gap between model and deployed implementations. Three PMs were analysed only from documentation and three could not be analysed at all; six more (Enpass, Sticky, Password Boss, SafeInCloud, iCloud Keychain, TeamPass) were judged from documentation descriptions rather than observed traffic, so their verdicts are weaker than those of the 27 with sufficient data. Only reverse engineering reveals actual KDF parameters. The formal results therefore describe protocols *as reconstructed*, not as vendors guarantee them.

For practice, the migration implications are concrete. A retrieval PM cannot escape the ceiling by tuning PBKDF2 or Argon2 — 35 products already do that, and 38 of 43 still fall to some adversary. The effective moves are: add a second high-entropy secret or a second device; encrypt metadata that is currently plaintext (30 of 43 do not); replace plaintext-auth or oracle-prone designs such as Delinea Web's and Passbolt's; and treat "zero-knowledge encryption" as a claim to be tested in the malicious-server model rather than a property. The Delinea reply is itself a transfer boundary: a vendor may define the malicious server out of scope, in which case the analysis still holds, but the product's advertised guarantee does not.

<div class="aside">
<p><span class="aside-label">Aside · The cost of a headline number</span></p>
<p>The one-line verdict — 38 of 43 — came out of a single effort the authors describe as taking nearly four months, in which every failed proof was treated as a lead rather than a reason to drop the protocol. The funnel behind it is worth seeing: they began with 145 industrial candidates and filtered by installations, security focus and launchability down to 36 industrial managers, then added 7 academic schemes. Seeing the real parameters was half the work — 24 of the 36 industrial products had to be reverse-engineered, because the KDF iteration count a client actually uses is not the one a white paper advertises.</p>
<p class="aside-source">Source: §3.1 (selection), §3.3 (collection and reverse engineering), §5 (analysis took nearly four months) of the paper's full version.</p>
</div>

## 5. Related Literature and Field Status

- **Gasti and Rasmussen, 2012.** *On the Security of Password Manager Database Formats*, ESORICS 2012. The first rigorous analysis of vault storage, with indistinguishability and non-malleability games; the authors call it a landmark but fault it for analysing the format rather than the protocol. ([link](https://doi.org/10.1007/978-3-642-33167-1_29))
- **Li, He, Akhawe and Song, 2014.** *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*, USENIX Security 2014, pp. 465–479. The systematic evaluation of deployed browser-based managers that opened this line of work. ([link](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei))
- **Oesch and Ruoti, 2020.** *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*, USENIX Security 2020, pp. 2165–2182. The three-years-later replication whose metadata findings the paper re-checks against its own data set. ([link](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch))
- **Scarlata, Torrisi, Backendal and Paterson, 2026.** *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers*, IEEE S&P 2026 / IACR ePrint 2026/058. Attacking the malicious-server model from the other direction: concrete protocol attacks on Bitwarden, LastPass, Dashlane and 1Password. ([link](https://eprint.iacr.org/2026/058))
- **Davies, Gellert, Jager et al., 2023.** *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol*, CRYPTO 2023. Source of the PPKR functionality in the UC framework that the M3PM functionalities adapt — one password, one key, ten guesses. ([link](https://eprint.iacr.org/2023/843))
- **Bellare and Rogaway, 1993.** *Entity Authentication and Key Distribution*, CRYPTO 1993. The model of entity authentication and session-key distribution that underpins the "authentication" goal. ([link](https://doi.org/10.1007/3-540-48329-2_21))
- **Bellovin and Merritt, 1992; Jarecki, Krawczyk and Xu, 2018.** Encrypted Key Exchange and *OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks*, EUROCRYPT 2018. The PAKE line that SRP-style M3PM authentication belongs to and that the field's phishing-resistant successors build on. ([EKE](https://doi.org/10.1109/RISP.1992.213269) · [OPAQUE](https://eprint.iacr.org/2018/163))
- **RFC 5869, RFC 8018, RFC 9106.** HKDF, PBKDF2 and Argon2 — the extract-then-expand KDF, the salted iterated KDF used by 35 of the analysed PMs, and the memory-hard function that replaces it. ([HKDF](https://www.rfc-editor.org/rfc/rfc5869) · [PBKDF2](https://www.rfc-editor.org/rfc/rfc8018) · [Argon2](https://www.rfc-editor.org/rfc/rfc9106))

Where does the paper place itself? As a systematic formaliser. It accepts that Gasti/Rasmussen and Oesch/Ruoti established what a *vault format* must guarantee, and that Bojinov/Chatterjee made honey vaults the standard answer to leakage — then argues that none of that covers authentication, cross-device retrieval, or the composition of authentication with encryption. It reads the field as one where vendors make an unfalsifiable "zero knowledge" claim, and where the right move is to define the protocol-level ideal functionality first and measure products against it. Its natural counterpart is the attack-oriented work that follows (Scarlata et al. 2026): both insist the malicious server is in scope, and diverge only in method.

## 6. Summary and Callbacks

- A **Master-Password-Protected Password Management (M3PM) protocol** is the whole client–server interaction — authentication plus retrieval — not just the vault's encryption; secure encryption alone does not make the protocol secure.
- The study reconstructed the M3PM protocols of **43 PMs (36 industrial, 7 academic)** from documentation, pre-TLS traffic, local storage files and static/dynamic reverse engineering; 24 of the 36 industrial PMs needed reverse engineering, and all raw data is public.
- Authentication comes in five shapes (hashed mpw, protected tokens, SRP, mpw challenge, pk challenge) and password processing in four (mpw encrypt, device-key encrypt, encode-then-encrypt, generative); their combinations are what the analysis compares.
- Security goals are formalised in the **UC framework** as $F_{\mathsf{M3PM}}$, refined into explicit/implicit authentication variants, a relaxed $F^{r}_{\mathsf{M3PM}}$ with a `TESTMPW` query, and $F^{\mathsf{ad}}_{\mathsf{M3PM}}$ for designs with a second secret.
- Offline guessing needs only two ingredients — a human password's $2^{20}$–$2^{22}$ bits of entropy and any stored value the adversary can test guesses against, modelled by the `GuessVerify` algorithm.
- Against **four adversary types** (no leak; corrupted server; partial leaked passwords; both), **38 of 43 PMs fail at least one**, **34 of 43 cannot fulfil the base functionality**, and only **1Password and Multipassword** reach $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$.
- Honey vaults do not close the gap (adaptive distributions defeat encode-then-encrypt); Delinea Web speaks plaintext; Passbolt leaks its encryption key through an oracle; 30 of 43 PMs leave metadata unencrypted, enabling URL tampering and phishing.
- The durable lesson: **every PM that withstands offline guessing adds a second high-entropy secret**; without one, protection rests entirely on slow or memory-hard KDFs such as PBKDF2 and Argon2, which 35 products already use to no avail.

**Callback.** Chapters 8 to 10 measured what deployed password managers actually do — Li et al. found broken autofill and generators, Oesch and Ruoti found the field creeping forward three years later, and Fábrega et al. showed injection attacks leaking vault secrets. All three assess implementations. This chapter attacks the same target from the other side: it formalises the *protocol* these products run, in the malicious-server model, and asks which designs have a proof at all. The gap it exposes is the one the book has carried since chapter 1 — the vault is encrypted, but the master password is still a shared secret that must travel to a server, and any server that sees a value derived from it can test guesses against it offline. Chapters 8–10 showed the damage; this chapter shows why, structurally, a single human-chosen password cannot close it. Chapter 13 takes the opposite route: stop sharing a guessable secret at all, and let the server hold a public key.

## References

1. Yihe Duan, Ding Wang, Yanduo Fu. *Security Analysis of Master-Password-Protected Password Management Protocols.* 2025 IEEE Symposium on Security and Privacy (S&P), pp. 701–719. https://doi.org/10.1109/SP61157.2025.00050
2. Duan, Wang, Fu. Full version of the paper (author's PDF, longer than the proceedings version), https://bit.ly/3zBPVUO — redirected to the authors' site at the time of writing; the site was intermittently unavailable during preparation of this chapter.
3. Public artifact with the paper's raw data for each password manager: https://github.com/DanielNKU/pm-analysis
4. Paolo Gasti, Kasper Bonne Rasmussen. *On the Security of Password Manager Database Formats.* ESORICS 2012, LNCS 7459, pp. 770–787. https://doi.org/10.1007/978-3-642-33167-1_44
5. Zhiwei Li, Warren He, Devdatta Akhawe, Dawn Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers.* USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei
6. Sean Oesch, Scott Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers.* USENIX Security 2020, pp. 2165–2182. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
7. Matteo Scarlata, Giovanni Torrisi, Matilda Backendal, Kenneth G. Paterson. *Zero Knowledge (About) Encryption: A Comparative Security Analysis of Four Cloud-based Password Managers.* IACR ePrint 2026/058 (USENIX Security 2026). https://eprint.iacr.org/2026/058
8. Gareth T. Davies, Sebastian Faller, Kai Gellert, Tobias Handirk, Julia Hesse, Máté Horváth, Tibor Jäger. *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol.* CRYPTO 2023. https://eprint.iacr.org/2023/843
9. Mihir Bellare, Phillip Rogaway. *Entity Authentication and Key Distribution.* CRYPTO 1993, pp. 232–249. https://doi.org/10.1007/3-540-48329-2_21
10. Steven M. Bellovin, Michael Merritt. *Encrypted Key Exchange: Password-Based Protocols Secure Against Dictionary Attacks.* IEEE S&P 1992, pp. 72–84. https://doi.org/10.1109/RISP.1992.213269
11. Stanislaw Jarecki, Hugo Krawczyk, Jiayu Xu. *OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks.* EUROCRYPT 2018, pp. 456–486. https://eprint.iacr.org/2018/163
12. Hugo Krawczyk, Pasi Eronen. *HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* RFC 5869, IETF, 2010. https://www.rfc-editor.org/rfc/rfc5869
13. Kathleen Moriarty (ed.). *PKCS #5: Password-Based Cryptography Specification Version 2.1.* RFC 8018, IETF, 2017. https://www.rfc-editor.org/rfc/rfc8018
14. Alex Biryukov, Daniel Dinu, Dmitry Khovratovich, Simon Josefsson. *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.* RFC 9106, IETF, 2021. https://www.rfc-editor.org/rfc/rfc9106
15. Hristo Bojinov, Elie Bursztein, Xavier Boyen, Dan Boneh. *Kamouflage: Loss-Resistant Password Management.* ESORICS 2010, LNCS 6345, pp. 286–302. https://doi.org/10.1007/978-3-642-15497-3_18
16. Rahul Chatterjee, Joseph Bonneau, Ari Juels, Thomas Ristenpart. *Cracking-Resistant Password Vaults using Natural Language Encoders.* IEEE S&P 2015, pp. 481–498. https://doi.org/10.1109/SP.2015.35

## Fact-Check List

Every item below was taken from the paper's text (the author's full version; section numbers refer to it) or, where noted, from the paper's public artifact.

| Claim in this chapter | Source in the original |
|---|---|
| Authors: Yihe Duan, Ding Wang, Yanduo Fu; IEEE S&P 2025, pp. 701–719; DOI 10.1109/SP61157.2025.00050 | Title page of the full version; IEEE CSDL; DBLP `conf/sp/DuanWF25` |
| Affiliation Nankai University (corresponding: wangding@nankai.edu.cn) | Full-version title page |
| Users must track 80–168 accounts | §1 |
| LastPass: three breaches in three years; 2022 breach linked to about 4.4 million US dollars | §1 |
| "Zero-knowledge" as a vendor claim | §1 |
| M3PM definition; secure vault encryption ≠ secure M3PM protocol; unsuitable auth+encryption combination | §1 (cross-reference to §5.4) |
| Gasti–Rasmussen 2012 first rigorous storage-format analysis; Oesch–Ruoti 2020 replication | §2.2 |
| Kamouflage and NoCrack honey vaults; Davies et al. CRYPTO'23 PPKR | §2.2 |
| PPKR: one password → one key, 10 offline guesses allowed | §2.2 |
| Retrieval vs generative PMs; LessPass/SPHINX examples | §2.1 |
| 43 PMs = 36 industrial + 7 academic; 145 industrial candidates | §3.1, contributions list |
| Selection filters (<10,000 installs; non-security academic; unlaunchable) | §3.1 |
| 24/36 reverse-engineered; 32 with useful data logs; 6 mainly from documentation; 27 sufficient for in-depth analysis | §3.3 |
| Five authentication types and their registration values ($h_{\mathsf{pw}}$, $\mathsf{eauth}$, $v$, mpw/pk challenge, $\mathsf{esk}$) | §3.3 and Figure 2 caption |
| Four password-processing types and their formulas ($e\mathsf{Vault}$, $e\mathsf{vk}$, encode-then-encrypt, generative) | §3.3 and Figure 3 caption |
| Threat model: corrupt the server, read all stored data; server may deviate; TLS assumed irrelevant | §4.1 |
| Seven security goals (indistinguishability, non-malleability, obliviousness, pseudorandom generation, guessing resistance, partial-leak resistance, authentication) | §4.1 |
| $F_{\mathsf{M3PM}}$, $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$, $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$, $F^{r}_{\mathsf{M3PM}}$ with `TESTMPW`, $F^{\mathsf{ad}}_{\mathsf{M3PM}}$ | §4.2 |
| Implicit-auth failure returns a Zipf-distributed decoy password | §4.2 |
| Two parties only (Remark 2); one-party modelled with a server; three-party future work | §4.2, Remark 2 |
| 1Password Protocol OP: $x$, $\mathsf{mk}$, $\mathsf{esk}$, $e\mathsf{vk}$, $e\mathsf{Vault}$ as written | §4.2 / Protocol OP |
| Password entropy $2^{20}$–$2^{22}$ bits vs AES 128/192/256 | §5.1 |
| `GuessVerify`($m$, $X$, $\sigma$) and the `123456abc` example | §5.1 |
| Per-scheme verification by the corrupted server | §5.1, Table 1 footnote |
| Encode-then-encrypt defeated by an adaptive distribution; `abc12345` example | §5.1 |
| Generative schemes resist until one generated password leaks | §5.1 |
| Four adversary types (Type-I … Type-IV) and which PMs resist each | §5.1, Table 1 footnote |
| 38 of 43 PMs vulnerable to at least one type | Abstract; §3.3 contributions; §5.1 |
| 34 of 43 cannot fulfil $F_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ or $F_{\mathsf{M3PM}\text{-}\mathsf{IA}}$ | §4.2 |
| 35 PMs use PBKDF2 or Argon2 | §4.2 |
| 30 of 43 PMs leave metadata unencrypted; Zoho Vault offline URL tampering | §5.2, Remark 1 |
| Only 1Password and Multipassword achieve $F^{\mathsf{ad}}_{\mathsf{M3PM}\text{-}\mathsf{EA}}$ | §5, §4.2, Table 1 note |
| Eight distinct protocols given provable analysis | §5 |
| Six PMs not provable: Norton, Chrome, Passwarden (no info); Amnesia, BluePass, Tapas (three parties) | §5 |
| Six further PMs assessed from documentation (Enpass, Sticky, Password Boss, SafeInCloud, iCloud Keychain, TeamPass) | Table 1 note |
| Analysis took nearly four months | §5 |
| Delinea Web: no client-side cryptography, plaintext communication | Abstract; §3.3; §5 |
| Passbolt: oracle attack, corrupted server learns the encryption key | Abstract; §5 (details in §5.4) |
| Responsible disclosure to Delinea and Passbolt; Delinea excludes the malicious server from its threat model | Introduction, "Responsible disclosure" |
| Insight: every guessing-resistant PM adds a second high-entropy secret | §5.1, "Insights" |
| PBKDF2/Argon2/AES/PBKDF2 parameters per product (Bitwarden PBKDF2+Argon2id, LastPass PBKDF2, Dashlane PBKDF2+Argon2, KeePass AES-256/SHA-256/KDF) | Paper's artifact repository (`Documentations sources/summary.md` per product); paper Appendix D |

## Uncertainties / Not Obtained

- **The tail of the full version was not retrieved.** The author's full-version PDF was fetched through a cache and was truncated after §5.2 and the 1Password protocol specification. Consequently the chapter does **not** describe: §5.3's security proof for 1Password (and its extension to other explicit-auth + mpw/device-key-encryption protocols), §5.4's mechanics of the Passbolt oracle attack, §5.5's proof for SPHINX, §6.1's specific mitigation recommendations, and Appendices A–E. The Passbolt oracle and the SPHINX proof are therefore described only at the level the abstract and §5 state; readers who need the mechanism should consult §5.4 directly.
- **No open-access version exists in a standard repository.** IACR ePrint, arXiv and Unpaywall report the paper as closed; the only free copy located is the authors' own full version (bit.ly link in the References), whose host returned 404 from this environment and from public proxies at the time of writing. The content above was extracted from that copy while it was reachable, plus the published abstract. No pirate mirror was used.
- **The artifact repository contains 36 product directories, fewer than the paper's 43 PMs** (the paper's 43 = 36 industrial + 7 academic; the repo's folders are largely the industrial set, plus academic ones such as LessPass, Gopass and Gokey). I therefore did not claim that the repository enumerates all 43.
- **Table 1 and Table 2 cell contents were not readable** as extracted text (the tables survive only as figure references), so per-product verdicts are reported only where the body text names them. Per-product metadata/privacy verdicts beyond the aggregate "30 of 43" are likewise unavailable.
- The proceedings version (8 pages shorter than the full version) may differ in wording; page numbers and the abstract wording were verified against the published metadata, not against the proceedings PDF itself.
- **Discrepancy with the task handoff:** the handoff places Ding Wang at Peking University; the paper's affiliation is **Nankai University** (Peking University is where he completed his PhD). The chapter follows the paper. The handoff's framing of this chapter as "formal/protocol-layer" analysis is confirmed.

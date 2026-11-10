# Injection Attacks and Cross-Item Leakage (2024)

<div class="source-card">
<p><strong>Source:</strong> Andrés Fábrega, Armin Namavari, Rachit Agarwal, Ben Nassi, Thomas Ristenpart. <em>Exploiting Leakage in Password Managers via Injection Attacks</em>. In: 33rd USENIX Security Symposium, Philadelphia, PA, USA, 2024, pp. 4337–4354. <a href="https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf">Open-access PDF</a>. Preprint: <a href="https://arxiv.org/pdf/2408.07054">arXiv:2408.07054</a>.</p>
<p><strong>In one line:</strong> An attacker who controls only their own, unmodified password-manager client can share chosen payloads with a victim and then recover the victim's passwords, URLs, usernames and attachments from the encrypted vault sizes and logged metadata that the client exports — a threat model that needs no client compromise, no cryptography break, and, in some cases, only a passive network observer.</p>
</div>

<div class="hook">
Consider the most harmless-looking action a password manager offers: another user shares a single login with you, and you click Accept. Nothing is decrypted that should not be, no key is broken, and the software on your machine is untouched and behaving exactly as designed. Yet out of that one shared entry — and the ordinary features the client runs on top of it — an attacker can read back your passwords, your URLs, your usernames and even your attachments. That is the whole of the injection attack: no cracked cipher, no rogue app, just a legitimate feature and a careful look at the size of the ciphertexts it produces.
</div>

## 1. Background and the problem

End-to-end encrypted (E2EE) password managers promise that a user's vault is confidential as long as the master password is not leaked: everything leaving the device is encrypted, so neither a breached server nor a network eavesdropper should learn anything. The academic attacks on password managers that came before — the browser-extension attacks of Li et al. (chapter 8) and the re-evaluation of Oesch and Ruoti (chapter 9) — mostly fit one of two models: an attacker who controls some *client-side resource* (a malicious website, a rogue app, a rogue Wi-Fi network, an XSS payload), or an attacker who has somehow obtained a copy of the encrypted vault and tries to crack the master password offline. State-of-the-art managers are built to resist both.

Fábrega and coauthors ask a question that neither model captures, and which became pressing once password managers stopped being single-user, non-interactive tools: *if the vault can hold entries shared by other people, what can a malicious sharer do?* Their threat model, which they call **injection attacks**, assumes an adversary who

1. **controls only their own application client** — unmodified software, speaking the standard protocol — and uses a built-in feature, credential or folder sharing, to place chosen payloads into the victim's vault; and
2. **passively observes some function of the data that leaves the victim's device** — for example encrypted vault backups, the network requests received by the application servers, or the HTTPS traffic itself.

Crucially, the attacker is not assumed to tamper with the victim's or its own client, to deploy backdoored code, or to break any cryptographic primitive. "Injections attacks assume strong cryptographic primitives," the paper states, "and thus low-level, cryptanalytic vulnerabilities are outside their scope; instead, the lengths of ciphertexts and plaintext metadata form the basis of our attacks." The payload travels through the E2EE protocol as legitimate data; the leak comes from the client's own logic combining that data with the victim's.

The paper's framing is that this is not a bug list but a **design problem of feature-rich clients**. As password managers add sharing, health reports, icon fetching and storage optimization, each new feature risks creating a *cross-user interaction* — a place where the client's treatment of one user's data depends on another user's data. In an E2EE system, any such interaction that is visible in the exported ciphertext is a channel. The authors argue this matters because the required adversary is weak and the required observability is realistic: server-side breaches are common and, per an IBM report they cite, take an average of 212 days to identify.

## 2. Core content: the model, the channels, and three attacks

### 2.1 The threat model

A vault is $V = \{e_1, \dots, e_m\}$, where each entry $e$ holds fields such as username $e_{user}$, URL $e_{url}$, password $e_{pw}$ and a list of attachments $e_{attach}$. **Injection** happens through sharing: the adversary shares an entry (or a folder) with the victim; the manager requires the victim to accept the *first* shared item, but — this is the load-bearing detail — all subsequent updates to a shared entry or folder need no further approval and are propagated automatically. So the victim accepts once, and thereafter the adversary can rewrite the payload at will.

**Observation** comes in two strengths:

- an **eavesdropper** with persistent access to the E2EE data and its plaintext metadata (a breached service or cloud provider, an insider, a compromised TLS layer);
- a weaker **network adversary** who sees only the HTTPS packets carrying that data.

Injections and observations alternate adaptively. Attacks are classified by noise tolerance: the **quiet device** setting assumes the victim adds nothing to the vault during the attack; the **noisy device** setting allows unrelated user activity. Because updates to shared entries propagate automatically, many attacks run in minutes.

### 2.2 The corpus

Starting from a popularity report and online polls, the authors screened 16 candidates against two inclusion criteria: the app must support cross-user credential sharing, and it must target *cryptographic* access control for shared credentials. All browser-integrated managers were dropped for lacking sharing. **Bitwarden** was dropped by the second criterion: it supports sharing, but all "collections" within an organization use the same secret key, so any member can already decrypt every organization credential — Bitwarden confirmed this is "at the authorization level, not at the encryption level." The final ten, with the versions tested, are LastPass (v4.123), Dashlane (v6.2346), Zoho Vault (v3.8), 1Password (v2.25.0), Enpass (v6.11.0), Roboform (v9.6.2), Keeper (v116.18.0), NordPass (v5.16), Proton Pass (v1.17.4) and KeePassXC (v2.7.6) — together over 30% of password-manager users. Only KeePassXC and Enpass do not run their own sync servers; they are designed to keep the encrypted database file on a third-party cloud drive.

The study is dominated by closed-source commercial services. The one clearly open-source product is KeePassXC, and the file-format attacks below land on the **KDBX 4 format** that the open-source KeePass lineage introduced, so they carry over to any application that reads it. The paper itself does not classify all ten apps by licence; it invokes public auditability and binary-transparency services only as a general means of trusting client software.

### 2.3 Attack 1 — vault-health metrics as an oracle

Many managers compute vault "health" statistics, notably the number of duplicate passwords $dup(V) = \tfrac{1}{2}\sum_{e^{\prime},e^{\prime\prime}\in V}(e^{\prime}_{pw} = e^{\prime\prime}_{pw})$, and log them outside the device. The vulnerability is that this count is computed across **both personal and shared** entries. So if the adversary injects an entry whose password is a candidate $p$ and observes whether $dup(V)$ grew, it learns whether $p$ already sits in the victim's vault. Three pre-conditions make an app vulnerable: it reports duplicate counts, computes them across all entries, and logs them off-device. Seven apps qualify: LastPass, Dashlane, Zoho Vault, Enpass, Roboform, Keeper and NordPass.

The generic attack is a dictionary attack with two injection strategies. If the app supports **shared folders**, the adversary binary-searches: split the candidate set, inject one half, observe $dup(V)$, recurse into whichever half changed. This costs $\lceil \log_2 n \rceil$ injections and the same number of observations. If only **individual entries** can be shared, a sequential strategy injects batches of $t$ items at a time, costing $n/t + \lceil \log_2 t \rceil$. Because $dup(V)$ is deterministic, both variants are false-positive-free: they find the password if present, and confirm absence otherwise. Zoho Vault leaks more: its log is a per-entry JSON array with a boolean `reused` field, so a single batch reveals which candidates match — and because the string `false` is one character longer than `true`, the HTTPS payload length shifts by one byte, letting even a **network adversary** run the attack.

### 2.4 Attack 2 — URL icons fetched once

Clients commonly show a logo beside each credential, fetched from the server by URL. Icons are fetched **only once per URL**: later entries for a site reuse the cached image. So injecting an entry with URL $w$ and watching whether the client issues a fetch tells the adversary whether $w$ is already in the vault. Six apps are vulnerable — Dashlane, 1Password, Enpass, Roboform, NordPass and Proton Pass — and because only the *presence* of a request matters, not its contents, this needs only a **network adversary**. The same binary-search and sequential strategies carry over.

### 2.5 Attack 3 — storage-saving mechanisms in KDBX 4

An adversary who holds an encrypted copy of the whole database can exploit compression and deduplication, which remove redundancy in the plaintext and therefore make ciphertext size depend on what the plaintext contained. KDBX 4 serializes a vault as an unencrypted outer header $H_{out}$ followed by an inner header and XML payload that are gzip-compressed and then encrypted. Only one copy of each attachment is stored, even across shared and personal entries (**deduplication**); and compression matches repeated substrings (**compression**). Among the ten apps only KeePassXC uses these mechanisms.

- **Deduplication → attachments.** Adding an attachment that is already in $A$ (the attachment blob store) does not grow the file. A naive probe is false-positive-free but linear; a binary-search variant needs a correction because gzip introduces noise, so the adversary "penalizes" each half by its locally measured compressibility, recursing into $W^{\prime}$ if $B_2/(B_1 + z^{\prime}) < B_3/(B_1 + z^{\prime\prime})$.
- **Compression → URLs and usernames.** Passwords are excluded because they sit under a second encryption layer, which prevents matches from being compressed. To control for the Huffman stage, the adversary injects two payloads per candidate — the string and a scrambled permutation of it with the same characters — and picks the candidate maximizing $|n^{\prime\prime}_i - n^{\prime}_i| / |w_i|$. A confirmation step re-injects the found string with a 32 KB pad (the zlib window) and checks the size does not grow.

## 3. Security analysis and experimental evaluation

The evaluation combines small proof-of-concept runs against real clients with larger simulations, a standard pattern for deployed-system work: real clients confirm correctness, and a local re-implementation yields success probabilities across many independent trials without overloading vendors.

For **Attack 1**, the authors deployed PoCs against LastPass, Dashlane and Zoho Vault on two accounts/devices with a proxy capturing the victim's outbound traffic (simulating a malicious server). All recover the target every time; they are tested on deliberately small workloads because correctness does not depend on dictionary size. LastPass logs $dup(V)$ after every shared-credential import and supports shared folders (binary search); Dashlane and Zoho log once per day, and Dashlane lacks shared folders (sequential). Significantly, no victim interaction is needed beyond being logged in: background scripts sync and trigger the requests, so the attack runs silently while the victim does other work — a **noisy device** attack.

For **Attack 2**, the PoC targets Dashlane, with URLs from the Majestic top-sites ranking, and always succeeds.

For **Attack 3**, the dedicated attack impacts only KeePassXC, tested in the same dual setup. Deduplication: the naive attack recovers the target every time; the binary-search success probability (Figure 4 of the paper) is high but degrades with candidate count, dataset and file size — on the Enron corpus, 92%, 81% and 52% for $|W| = 32, 128, 512$; for equal-size random files, 100% at all sizes. Compression: usernames and URLs are recovered with high probability (Figure 5); for real-world data, website recovery runs 99%/97%/92%/89%/84% as the dictionary grows from 4 to 100 items. Both attacks are "amplifiable via repetition" and have a confirmation step that removes false positives.

<div class="aside">
<p><span class="aside-label">Aside · One boolean worth a whole dictionary</span></p>
<p>Zoho Vault's vault-health log is not a single number but an array of JSON objects, one per entry, each carrying a <code>reused</code> field that is simply <code>true</code> or <code>false</code>. That granularity lets an adversary skip the binary search altogether: inject every candidate password in one batch, reread the log, and the flags already say which injected entries collided with a real one. The leak then sharpens further — because the string <code>false</code> is one character longer than <code>true</code>, a flip from one to the other shrinks the encrypted HTTPS payload by at least a byte, so a passive network observer who decrypts nothing at all can still watch that byte.</p>
<p class="aside-source">Source: Fábrega et al., USENIX Security 2024 — the per-entry <code>reused</code> field is in §5.1 ("Vulnerable Password Managers") and its "Extension to a network adversary" paragraph; the concrete Zoho Vault byte-level argument is in the Zoho Vault case study (Appendix B).</p>
</div>

## 4. Applicability and translation boundaries

The three attacks are not twelve separate bugs but three **design patterns**, and the paper makes this the point: "our attack vectors are features of password managers, instead of bugs that are specific to our case study applications." Read generically, the patterns are:

1. **Exporting state that is a function of both personal and external data** (metrics, health reports, aggregate statistics). Guiding principle: *separate data according to the trust assumptions of the system.*
2. **Fetching external content in a state-dependent way** (caching an icon, or any resource, so that a fetch reveals prior state). Guiding principle: *keep client-server communication resource-specific and independent of prior operations.*
3. **Applying similarity-sensitive functions — compression, deduplication — across data from different trust contexts.** Guiding principle: security and storage efficiency are in tension here and must be balanced deliberately.

That translation is not hypothetical. In a companion paper, *Injection Attacks Against End-to-End Encrypted Applications* (IEEE S&P 2024), the same group applies the model to E2EE messaging: WhatsApp attachment deduplication, zlib compression of the serialized database, and the FTS4 search index all leak message or attachment information to an adversary who injects messages and observes encrypted **backups** (assuming a compromised Google/Apple account); Signal's backup serialization leaks contact and conversation counts. The mitigations paper (Section 5) generalizes the pattern to any feature whose "filter" function is *similarity-sensitive*, and notes the same shape recurs in multi-tenant search services.

The **boundary conditions** are explicit. The victim must accept one shared item, so the model assumes some initial trust or a successful social-engineering of a share request — accepting a share should never leak a vault, but it is a precondition. A client that deviates from the E2EE protocol is out of scope, though the authors expect no extra attacks from it. Attacks 1 and 3 need a specific off-device artifact (metric logs, the whole encrypted database) and Attack 3 additionally needs a quiet device; only Attacks 1 (for Zoho Vault) and 2 reduce to a purely passive network adversary. The strongest single statement of the takeaway is that the mitigations vendors deployed are *bespoke patches*: the paper calls for general-purpose detection and mitigation techniques and a deeper theory of the threat model.

**How this differs from chapters 8 and 9.** The browser-manager attacks of Li et al. (2014) and the storage/autofill re-evaluation of Oesch and Ruoti (2020) assume an adversary who subverts some *part of the victim's own client-side environment* — a malicious login page, an XSS or bookmarklet, a rogue extension, a malicious app, the clipboard, or an autofill policy that hands the secret to the wrong origin — and the leak is the secret itself or a code-execution primitive. Fábrega et al. keep the victim's client *honest and unmodified*: the attacker is another user, the injection is ordinary shared data, and the leak is not the secret but *information about the secret* (its presence, or its bytes) inferred from ciphertext lengths and plaintext metadata. Two consequences follow. First, the attack surface is created by legitimate features, so it does not disappear when the classic browser bugs are fixed. Second, the defence is not a fix to a parser but a property of how the client partitions and processes data before encryption — precisely the property the 2025 partitioning work formalizes.

## 5. Related literature and the state of the field

- **Z. Li, W. He, D. Akhawe, D. Song, *The Emperor's New Password Manager*, USENIX Security 2014** ([usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei)) — chapter 8; the first systematic web-based password-manager analysis, in a client-side-resource threat model. Fábrega et al. answer the question that analysis raises once managers become multi-user.
- **S. Oesch, S. Ruoti, *That Was Then, This Is Now*, USENIX Security 2020** ([usenix.org](https://www.usenix.org/conference/usenixsecurity20/presentation/oesch)) — chapter 9; generation, storage and autofill re-evaluated in browser managers. Still a single-victim, client-side model.
- **A. Fábrega, C. Ortega Pérez, A. Namavari, B. Nassi, R. Agarwal, T. Ristenpart, *Injection Attacks Against End-to-End Encrypted Applications*, IEEE S&P 2024** ([arXiv:2411.09228](https://arxiv.org/abs/2411.09228), [NSF PAR](https://par.nsf.gov/servlets/purl/10522889)) — the generalization to E2EE messaging (WhatsApp, Signal); shows the pattern is not specific to password managers.
- **A. Fábrega, S. Breckenridge, A. Namavari, T. Ristenpart, *Mitigating Injection Attacks against E2EE Applications via View-Based Partitioning*, USENIX Security 2025** ([PDF](https://www.usenix.org/system/files/usenixsecurity25-fabrega-partitioning.pdf)) — gives the first formal security model for injection attacks and a framework that partitions application state by **adversarial views** (e.g. one compression stream per chat or per shared folder) so that similarity-sensitive functions never cross trust contexts. It proves that view non-interference implies length-independence (robustness reduces to encryption security) and measures the cost: a KeePassXC backup of 200 passwords grows from 29.7 KB to 36.5 KB instead of the 530 KB a no-compression fix would need — about 14× better.
- **C. Garman, M. Green, G. Kaptchuk, I. Miers, M. Rushanan, *Dancing on the Lip of the Volcano: Chosen Ciphertext Attacks on Apple iMessage*, USENIX Security 2016** ([usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/garman)) — cited by both Fábrega papers as the archetype of exploiting compression before encryption in a deployed E2EE protocol; the injection line of work generalizes that insight from chosen ciphertexts to chosen *plaintexts* injected through ordinary features.
- **M. Backendal, M. Haller, K. G. Paterson, *MEGA: Malleable Encryption Goes Awry*, IEEE S&P 2023** ([eprint 2022/959](https://eprint.iacr.org/2022/959)) — a benchmark for attacks where the *server* is adversarial and the client's cryptographic handling is the flaw; contrast with Fábrega et al., who need no server-side cryptographic break at all.

The authors' positioning is **systematic and reformist rather than revolutionary**: they do not claim the E2EE primitives are broken, and they explicitly credit prior work in searchable encryption (the binary-search technique) and compression attacks. Their claim is that the *application layer* — the features built on top of E2EE — is an under-studied attack surface, that it is best studied through reusable templates, and that the field needs general detection and mitigation tooling rather than per-bug patches. The 2025 partitioning paper reads as the authors' own answer: the same group moving from finding patterns to formalizing and closing them.

## 6. Summary and Callbacks

- **Threat model.** An adversary who controls only its own, unmodified client injects payloads via credential or folder sharing, then passively observes encrypted state. The victim accepts one shared item; all later updates propagate without approval. No client tampering, no cryptanalysis.
- **Observers.** An eavesdropper sees the E2EE data and plaintext metadata; a weaker network adversary sees only the HTTPS packets. Most attacks need one or the other; a couple need only the network view.
- **Corpus.** Ten sharing-capable managers, over 30% of users. Bitwarden was excluded because its collections share one key — "authorization level, not encryption level"; browser-integrated managers were excluded for lacking sharing.
- **Attack 1 (vault-health metrics).** Seven apps leak the duplicate-password count across personal and shared entries. Binary search costs $\lceil \log_2 n \rceil$ injections; a sequential variant costs $n/t + \lceil \log_2 t \rceil$. Zoho Vault leaks per-entry booleans, and one byte of payload-length difference even enables a network adversary.
- **Attack 2 (URL icons).** Six apps fetch each site's icon only once, so a missing fetch reveals that the URL is already in the vault. Network adversary suffices.
- **Attack 3 (KDBX 4).** Deduplication leaks attachment contents; compression leaks URLs and usernames (passwords are protected by a second encryption layer). Only KeePassXC among the ten qualifies, but the weakness is in the shared file format. Success probabilities are high and repeat-amplifiable, with confirmation steps removing false positives.
- **Mitigations and disclosure.** Fixes range from separating personal and shared data in the metric (LastPass 4.129.0), to a per-shared-folder dedup and random 64–512-byte padding in KDBX (KeePassXC 2.7), to making the icon channel removable and its endpoint noisy (Dashlane 6.2415). Detailed in Section 8 of the paper.
- **Takeaway and generalization.** The attacks are three reusable design patterns, not twelve bugs; the same patterns recur in E2EE messaging (S&P 2024) and multi-tenant search, and the authors' own 2025 framework shows how to close them by partitioning state along adversarial views at a modest, measured cost.
- **Contrast with chapters 8–9.** Li (2014) and Oesch (2020) attack the victim's own client-side environment; Fábrega (2024) keeps the client honest and lets another *user* attack it through ordinary features, leaking not the secret but information about it from ciphertext length and metadata.

**Callbacks.** Chapter 9 closed on a structural point: a password manager still holds a *shared secret* and still hands it into a web page, so its weakness is structural rather than incidental. This chapter runs that motif one turn further and finds the failure does not even need the hand-off — another *user* is enough. Where chapters 8 and 9 attack the victim's own client-side environment and leak the secret itself, Fábrega et al. keep the client honest, inject ordinary shared data, and read *information about* the secret out of ciphertext length and metadata; the attack surface is therefore opened by legitimate features rather than by bugs, and fixing the browser bugs of 2014 does not close it. The generalisation is stated in the paper and demonstrated in its companion: the same templates work against any multi-tenant E2EE application in which users share data with one another — E2EE messaging included, where WhatsApp's attachment deduplication, zlib compression and FTS4 search index, and Signal's backup serialisation, leak through encrypted backups. The hook left for later chapters is not a patch but the shape of the fix: partitioning state so that similarity-sensitive functions never span a trust boundary, which is precisely what the authors' own 2025 framework formalises. Chapters 11 and 12 then take up the neighbouring question — whether the cryptographic protocol underneath all of this holds when the *server* is the adversary.

## References

1. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. In: 33rd USENIX Security Symposium, 2024, pp. 4337–4354. https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf
2. A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks* (preprint). arXiv:2408.07054, 2024. https://arxiv.org/pdf/2408.07054
3. A. Fábrega, C. Ortega Pérez, A. Namavari, B. Nassi, R. Agarwal, T. Ristenpart. *Injection Attacks Against End-to-End Encrypted Applications*. IEEE S&P (Oakland), 2024, pp. 2648–2665. https://arxiv.org/abs/2411.09228
4. A. Fábrega, S. Breckenridge, A. Namavari, T. Ristenpart. *Mitigating Injection Attacks against E2EE Applications via View-Based Partitioning*. 34th USENIX Security Symposium, 2025. https://www.usenix.org/system/files/usenixsecurity25-fabrega-partitioning.pdf
5. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-based Password Managers*. USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li_zhiwei
6. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. USENIX Security 2020, pp. 2165–2182. https://www.usenix.org/conference/usenixsecurity20/presentation/oesch
7. C. Garman, M. Green, G. Kaptchuk, I. Miers, M. Rushanan. *Dancing on the Lip of the Volcano: Chosen Ciphertext Attacks on Apple iMessage*. USENIX Security 2016, pp. 271–288. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/garman
8. M. Backendal, M. Haller, K. G. Paterson. *MEGA: Malleable Encryption Goes Awry*. IEEE S&P, 2023. https://eprint.iacr.org/2022/959
9. D. Cash, P. Grubbs, J. Perry, T. Ristenpart. *Leakage-Abuse Attacks Against Searchable Encryption*. ACM CCS, 2015. https://eprint.iacr.org/2016/718
10. KeePassXC. *KDBX 4 database file format / KeePassXC* (project). https://github.com/keepassxreboot/keepassxc

## Fact-check checklist

All page-level references are to the USENIX Security 2024 proceedings version (pp. 4337–4354).

| Fact written into the chapter | Source in the paper |
|---|---|
| Threat model: adversary controls only its own unmodified client; injects via sharing; observes protected state; client tampering and backdoored clients out of scope | §4.1 "Threat Model", "Injections", "Out-of-scope attacks" |
| "assume strong cryptographic primitives … lengths of ciphertexts and plaintext metadata form the basis" | §4.1, "Injections"/"Observations" paragraph |
| Victim must accept one shared item; later updates need no approval; folders likewise | §3 "Credential sharing"; §4.1 |
| Two observers: eavesdropper (E2EE data + plaintext metadata) and network adversary (HTTPS packets); iterative interleaving | §4.1 "Observations"; Figure 2 |
| Quiet vs noisy device settings | §4.1, noise paragraph; §7 (Attack 3 quiet), §5/§7.1 |
| Server breaches common; average 212 days to identify (IBM 2022) | §4.1 |
| Corpus: 16 candidates screened; two inclusion criteria; browser managers and Bitwarden excluded; Bitwarden quote "authorization level, not at the encryption level" | §4.2 "A Corpus of Password Managers" + footnote 3 |
| Ten apps and versions (v4.123 … v2.7.6); over 30% of users | §4.2 |
| KeePassXC/Enpass do not run their own sync servers; KDBX introduced by open-source KeePass | §3 "Database file formats"; §4.2; §7 |
| Two example attacks (#1 metrics, #2 icons) summarized as three classes with #3 storage-saving | §4.3 "Overview of Attacks" |
| $dup(V)$ formula and its use as an oracle | §5 "Attack description" |
| Seven apps vulnerable to Attack 1: LastPass, Dashlane, Zoho Vault, Enpass, Roboform, Keeper, NordPass | §5.1; Figure 1 row (L, D, Z, E, R, K, N) |
| Binary search costs $\lceil \log_2 n \rceil$; sequential costs $n/t + \lceil \log_2 t \rceil$; both false-positive-free | §5 |
| PoC apps LastPass/Dashlane/Zoho; LastPass logs after every import and supports folders; Dashlane/Zoho log daily; Dashlane lacks folders | §5.1 |
| Attack 1 runs without victim interaction (logged-in background scripts), noisy device | §5.1 |
| Zoho Vault per-entry `reused` boolean; `false` is one char longer than `true`, giving a 1-byte network-adversary signal | §5.1 "Extension to a network adversary" |
| Attack 2: icons fetched once per URL; six apps (Dashlane, 1Password, Enpass, Roboform, NordPass, Proton Pass); network adversary only; PoC Dashlane; Majestic list | §6, §6.1 |
| Attack 3: KDBX 4 = $H_{out}$ + Enc(gzip($H_{in}\,\Vert\,I$)); dedup of attachments; passwords under a second encryption layer; only KeePassXC qualifies; format-level, so other KDBX apps affected | §7, §7 "Background on KDBX 4" |
| Dedup binary search noise correction $B_2/(B_1+z^{\prime}) < B_3/(B_1+z^{\prime\prime})$; naive attack false-positive-free; 100% for equal-size random files | §7.1 |
| Figure 4 numbers (Enron 92/81/52; 10 KB 74/53/29) | §7.1, Figure 4 |
| Compression two-injection (string + scramble) strategy; criterion $\max \lvert n^{\prime\prime}_i - n^{\prime}_i \rvert / \lvert w_i \rvert$; confirmation with 32 KB pad = zlib window | §7.2 |
| Figure 5 website-recovery numbers 99/97/92/89/84 for $\lvert W \rvert = 4, 10, 25, 50, 100$; averaging over $t=10$ | §7.2, Figure 5 |
| Mitigations: separate metrics, encrypt metrics, PIR for icons, re-fetch icons, disable storage-saving (5–6× size increase), per-trust-subset confinement, second encryption layer, padding/noise | §8 |
| Disclosure: LastPass 4.129.0 (folders first), Zoho 4.0 plan, Dashlane rate limits + icons toggle 6.2415, KeePassXC 2.7 (per-shared-folder dedup + random 64–512-byte padding) | §8 "Responsible disclosure" |
| Three guiding principles (trust separation; resource-specific communication; security/performance tension) | §9 "Conclusion" |
| S&P 2024 generalization: WhatsApp (dedup, zlib, FTS4), Signal (serialization); compromised Google/Apple account for backups | S&P 2024 abstract; §1; Figure 1 |
| Partitioning 2025: view-based partitioning, formal model, view non-interference ⇒ length independence, 29.7 KB → 36.5 KB vs 530 KB no-compression (~14×) | USENIX'25 abstract; §4; §6.3 (Thm 2, Cor 1); §7.2 (Figure 8) |

## Open questions / not obtained

- **Count discrepancy between versions.** The arXiv v1 preprint (2408.07054) says "Five out of the ten applications are vulnerable" for Attack 1 and its Figure 1 lists only `L, D, Z, K, N` — yet its own §5.1 text lists the same seven apps as the proceedings version. The USENIX 2024 proceedings version is internally consistent at **seven** (`L, D, Z, E, R, K, N`) and is the source used here. Flagged because the handoff and any reader of the arXiv version would otherwise see "five".
- **Open- vs closed-source breakdown.** The paper does not classify all ten applications by licence. The chapter says KeePassXC is the clearly open-source case and that the KDBX attacks target the shared format; it does not claim a licence for each of the other nine.
- **Appendices A/B/C** (testing methodology and the per-application case studies) are present in the USENIX PDF pages used for the Case Study #3 excerpt but the extended appendices with additional screenshots/payloads were not read in full; no chapter claim depends on them beyond what is cited above.
- **"27 attacks" style headline counts** appear in popular coverage of the surrounding literature (e.g. the 2026 zero-knowledge work) and are **not** used here; this chapter reports only the paper's own "three classes of attacks / four general attacks" framing (§4.3 "three main classes"; §9 "four general attacks").
- **Exact published page range for the S&P 2024 companion** is given as pp. 2648–2665 (DOI 10.1109/SP58266.2024.00174) from third-party indexes; the arXiv preprint is the copy actually read.

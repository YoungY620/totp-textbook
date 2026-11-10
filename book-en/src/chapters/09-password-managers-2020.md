# That Was Then, This Is Now (2020)

<div class="source-card">
<p><strong>Source:</strong> Sean Oesch, Scott Ruoti. <em>That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers</em>. In: Proceedings of the 29th USENIX Security Symposium, USENIX Association, August 2020, pp. 2165–2182. <a href="https://www.usenix.org/system/files/sec20-oesch_0.pdf">Open-access PDF</a> (<a href="https://www.usenix.org/conference/usenixsecurity20/presentation/oesch">presentation page</a>).</p>
<p><strong>In one line:</strong> Five years after the classic evaluations of browser password managers, thirteen popular managers are re-examined across all three stages of their lifecycle — generation, storage and autofill — showing real improvement, a set of old problems that never went away, and a first look at a problem nobody had measured before: the passwords the generators actually produce.</p>
</div>

<div class="hook">
Picture the autofill prompt that never appears: you open a page, the form fills itself, and you never notice. In 2014 several papers showed exactly how that convenience becomes a credential-theft channel, and the vendors went to work. Six years later a team reopens thirteen password managers to ask the same question of a whole new generation of software — what was actually fixed? The answer is not a clean yes, and the component nobody had thought to check is the very button that invents the password in the first place.
</div>

## 1. Background and the problem

Password managers promise to close the gap between the security advice users are given and what users can realistically do. A manager generates strong passwords, stores them in an encrypted vault, and fills them in on the right site, so the user can keep a unique password per account without memorising any of them. Herley's argument [18] — that rejecting security advice is rational when the effort is large and the risk is small — is exactly the burden a password manager is supposed to lift.

But the tool is itself software, and a manager that gets one of its three jobs wrong becomes a single point of failure for every account it holds. That is the concern the authors inherited. Li et al. [19] analysed five **extension-based** managers in 2014 and found logic and authorization errors, misunderstandings of the web security model, CSRF/XSS exposure, and badly sandboxed bookmarklets. Silver et al. [29] and Stock and Johns [31] showed in the same year that autofill is a credential-theft channel: if a manager fills without asking the user, any page the attacker can inject script into hands over the password, and if autofill is allowed inside an iframe, clickjacking can manufacture the "user interaction" the user never knowingly gave. Gasti and Rasmussen [17] had analysed vault formats and found unencrypted metadata plus side-channel leakage from encrypted data.

The authors' motivation is that the field had moved underneath those results. Between 2014 and 2020 the product landscape changed: managers moved from browser extensions to standalone apps and to password vaults synced through the cloud, and browsers began shipping their own built-in managers. A 2014 finding about a bookmarklet-based deployment may say nothing about a 2020 cloud-synced extension. The paper's framing is therefore explicitly comparative — *that was then, this is now* — and it asks two questions at once: **have the specific vulnerabilities found five years earlier been fixed, and are the tools now ready for broad adoption?** Its second, more novel motivation is a gap in the literature: no one had evaluated **password generation** at all. Prior work looked at how vaults are stored or how credentials are filled, but nobody had asked whether the passwords the generators emit are actually random.

## 2. What was evaluated, and how

**The subjects.** Thirteen password managers, grouped by how tightly they integrate with the browser (Table 1):

| Category | Managers |
|---|---|
| App (desktop client, not browser-integrated) | KeePassX, KeePassXC |
| Extension | 1Password X, Bitwarden, Dashlane, LastPass, RoboForm |
| Built into the browser | Chrome, Edge, Firefox, Internet Explorer, Opera, Safari |

That is two desktop clients, five browser extensions and six browser-native managers. The authors note that by the time of writing several had changed: KeePassXC had switched its default key derivation function to Argon2D, LastPass and RoboForm had reworked their generation interfaces, Firefox was moving to Firefox Lockbox, and Edge was moving onto Chromium (Section 3.4). For comparison, the generation study also includes two baselines: a Python script reading `/dev/random`, and the online Secure Password Generator (SPG), the first Google result for "password generator".

**Generation.** This is the paper's original contribution. Nine of the thirteen managers can generate passwords — seven fully (KeePassX, KeePassXC, 1Password X, Bitwarden, Dashlane, LastPass, RoboForm) and two partially (Chrome, Safari). For each generator the authors varied the character classes (letters `l`; letters and digits `ld`; letters and symbols `ls`; symbols and digits `sd`; all four `all`) and the length (8, 12, 20), collecting **one million passwords per configuration**. Together with the two baselines this yields a corpus of **147 million passwords** — the arithmetic the paper gives is $10 \times 5 \times 3 - 3$, the subtraction covering the one generator (1Password X) that cannot produce symbols-and-digits-only passwords. Safari has no scripting hook for password generation, so only 100 of its passwords were generated by hand and checked for obvious defects, none found.

Because no test can prove a pseudorandom generator is indistinguishable from random, the authors attack the corpus with four independent detectors, each looking for *evidence of non-randomness*: Shannon entropy over character frequencies; the $\chi^{2}$ test for randomness; the zxcvbn strength estimator; and the LSTM recurrent neural network password guesser of Melicher et al. [22], trained on 80% of each corpus and tested on the remaining 20%. Because many tests run on the same family of data, all $p$-values are Bonferroni-corrected by multiplying by 147 (capped at 1.00).

**Storage.** The cloud back-ends were not available to the authors, so storage was evaluated by **manually inspecting each manager's local database**, asking what is encrypted, what the ciphertext format is, and how changing the master password affects the ciphertext. The authors stress that "how encryption takes place" was inferred from a combination of maintainer claims, the options exposed in the client, and the format of the ciphertext — it is not a cryptographic audit of the cloud service.

**Autofill.** The authors built test websites that reproduce the attacks of Li et al. [19], Silver et al. [29] and Stock and Johns [31], updated for the browser and manager defences added since those attacks were described. The instruments are graded rather than pass/fail: whether interaction is required, what happens inside same-origin and cross-origin iframes, whether the manager fills a form that differs from the one where the password was saved, and whether it fills non-standard login fields.

## 3. Evaluation and findings

### 3.1 Generation

**Weakness, not obvious non-randomness, is the main problem.** The character-distribution tests found several statistically non-random distributions (Table 4), but almost all of them have a single innocent explanation: the option requiring at least one character from every selected class. With $|characters_{all}|$ the size of the union of enabled sets and $|sets|$ the number of enabled sets, a character's probability of appearing is

$$
\frac{1}{length \cdot |characters_{all}|}
$$

without that option, and

$$
\left( (length - |sets|) \cdot \frac{1}{|characters_{all}|} \right) + \frac{1}{|characters_{set}|}
$$

with it — so characters drawn from *smaller* sets (digits, symbols) appear more often. Two apparent exceptions also fit: Bitwarden's `sd` set has equal numbers of digits and symbols so they are selected equally often, and Dashlane's `l` set uses unequal numbers of upper- and lowercase letters. The one distribution that the authors could not explain this way is RoboForm's `l`: uppercase letters (except `Z`) are selected more often than lowercase, and `Z`, `z` and `9` are consistently the rarest characters. They hypothesise a bias from modular arithmetic character selection (`rand()%(max - min) + min`), but flag it as a hypothesis.

The serious finding is not the distribution skew but the **tail**. Using the standard thresholds — more than $10^{6}$ guesses to resist an online attack, more than $10^{14}$ to resist offline guessing [16] — the analysis shows that generators, being truly random, occasionally emit passwords that are trivially guessable: a dictionary word with substitutions (`d@rKn3s5`), or a repeated-character pattern (`'+'+'+_+`). Such passwords occur rarely — **fewer than 1 in 200** — but they occur. The consequences scale with length: at length 8 the weakest generated passwords are vulnerable to *both* online and offline guessing; at length 12 they fall to offline guessing only; at length 20 even the weakest survive an offline attack. The paper's conclusion is a rule of thumb: **length 10 for online resistance, length 18 for offline resistance**.

Two further generation issues are interface-level rather than statistical. First, symbol sets differ wildly — KeePassXC supports all standard ASCII symbols except space plus extended ASCII; KeePassX and Dashlane support standard ASCII except space; 1Password supports 19 symbols; the rest offer 8 or fewer — and every restriction directly reduces password strength. Second, most managers **save the last-used settings as the new defaults**, so a user who once dropped to weaker settings to satisfy a site's policy may find the weaker settings have silently become their default (Dashlane avoids this; KeePassX saves them only until the app is restarted).

### 3.2 Storage

App- and extension-based managers all encrypt their vaults with **AES-256**, and all derive the key from the master password with a key derivation function. KeePassX and KeePassXC use AES-KDF with 100,000 rounds; 1Password X, Bitwarden and LastPass use PBKDF2 at roughly 100,000 rounds (the table lists 100,000, 100,001 and 100,100 respectively); RoboForm uses PBKDF2 with only **4,096 rounds** — the only one of this group below 100,000; and Dashlane is the sole manager using a memory-hard KDF, **Argon2D with 3 rounds**.

Among the browser-native managers only Firefox encrypts its own vault, and it does so worst: **3DES** for the data, with a **single round of SHA-1** to derive the key, and no policy whatsoever on the master password. The authors call it "by far the weakest". The others delegate to the operating system — Edge, Internet Explorer and Safari use the Windows Vault or the macOS keychain; Chrome and Opera use `CryptProtectData` on Windows and the GNOME keyring or KWallet on Linux, **falling back to storing passwords in plaintext** if neither keyring is present, and on macOS derive keys from the keychain while keeping the passwords themselves outside it. Because these managers have no master password of their own, their vaults cannot be locked separately from the OS account.

On metadata, the picture is genuinely better than in 2014. KeePassX and KeePassXC encrypt all metadata; extension-based managers encrypt most of it but each leaves at least one item exposed — 1Password X stores **extension settings in plaintext**, including security-relevant settings such as whether auto-lock is on; Dashlane encrypts the website URLs but not the **icons** associated with them, which leaks which sites the user has accounts on; and all extension-based managers leak the email address used to log in to the manager. The remaining browser managers (Chrome and Opera on Windows/macOS, Firefox everywhere) store the **URL in cleartext** and, except Firefox, the username as well, and reveal account creation time, last use, and fill count.

### 3.3 Autofill

The autofill findings are where the "that was then" thread runs. Only KeePassX has no browser autofill at all, and only Bitwarden marks its autofill experimental; of the rest, **only 1Password X and Safari always require user interaction before filling**. Everyone else either defaults to autofill without asking (Dashlane, LastPass, Firefox — an option to require interaction exists but defaults matter) or always autofills (Chrome, Edge, Internet Explorer, Opera). KeePassXC, Bitwarden and RoboForm require interaction by default but let the user switch the requirement off, which puts them one setting away from the same exposure. Unsurprisingly, managers do react to a bad HTTPS certificate — Edge and IE escalate to requiring interaction, Chrome and Opera disable autofill entirely — but on plain HTTP the responses are uneven.

The iframe results are the sharpest. Autofilling inside an iframe is dangerous regardless of interaction, because clickjacking can supply the "interaction" invisibly; if autofill is allowed in a **cross-domain** iframe and interaction is not required, an attacker can harvest credentials for every site they can reach with an injection or XSS attack. KeePassXC, 1Password X, Dashlane and LastPass autofill inside same-origin iframes and are therefore clickjacking-exposed; Bitwarden and RoboForm do too, but keep the interaction prompt outside the page (in the extension drop-down), which largely defuses clickjacking. KeePassXC further permits cross-domain iframe autofill and, since the interaction requirement can be disabled, is vulnerable to harvesting. FireFox's default — no interaction required for cross-domain iframes — leaves it **vulnerable to the domain harvesting attack out of the box**, which is why the authors single it out as a manager to avoid. Chrome, Edge, IE, Opera and Safari require interaction in cross-domain iframes, which still leaves the clickjacking route open.

Two remediation experiments show where the ecosystem blocks fixes. Stock et al. [31] proposed a **nonce-based autofill**: fill a nonce, let the manager swap in the real password only when the request is actually transmitted to the matching domain, so page JavaScript never sees the secret. **None of the thirteen managers supported it**, and the authors' own attempt failed because browsers do not let extensions modify the request body. And the `autocomplete="off"` attribute, which the W3C specification says should stop a user agent filling a field, is **obeyed by no password manager** — consistent with Mozilla's own note that modern browsers deliberately ignore it for login fields in order to keep managers working.

### 3.4 Web vaults

Of the five extension-based managers, 1Password X, Bitwarden, Dashlane and LastPass use CSRF tokens; **RoboForm does not**, and the authors launched a CSRF attack against its web vault that changed the session timeout parameter. On content security policy, 1Password X and Dashlane were clean; Bitwarden had two small holes (`script-src 'self'`, `object-src 'self'` and `blob:`); **LastPass allowed `unsafe-inline` in `script-src`**, a significant XSS opening; and **RoboForm had no CSP at all**. Attempts to actually exploit LastPass and RoboForm failed because both sites sanitise input aggressively — the authors note the vaults would still benefit from stricter policies. On bookmarklets, only LastPass still ships one, and it sandboxes correctly and filters dangerous messages, addressing the 2014 finding.

### 3.5 That was then, this is now

- **Fixed or improved (the "then" that is no longer):** metadata protection in app- and extension-based vaults; the removal of insecure bookmarklet deployments; restricting iframe autofill enough to shut down the password-harvesting attacks; and CSRF/XSS hardening of the online web vaults.
- **Replicated, i.e. still broken (the "then" that persists):** autofill without user interaction remains a live credential-theft channel on XSS- or injection-compromised pages; clickjacking through same-origin iframes still bypasses interaction requirements; managers still fail to warn about discrepancies between the form being filled and the form where the password was saved; no manager implements the nonce-based secure autofill of Stock et al.; and `autocomplete="off"` is still universally ignored.
- **New (the "this is now"):** the first measurement of password generation, yielding non-random character distributions and, more importantly, occasionally trivially guessable generated passwords; plaintext extension settings in 1Password X; unsafe generation *defaults*; LastPass's `unsafe-inline` CSP and RoboForm's absent CSP and CSRF token; and a structural obstacle — browsers' refusal to let extensions rewrite a request body — that blocks the one proposed mitigation for XSS-safe autofill.

<div class="aside">
<p><span class="aside-label">Aside · One parameter that decides everything</span></p>
<p>Under a vault's AES-256 encryption sits a key derived from the master password, and the parameter that decides how expensive a stolen vault is to crack is the derivation's cost — for the PBKDF2 and AES-KDF constructions of this 2019 generation, the iteration count. In the versions Oesch and Ruoti examined, LastPass's PBKDF2 ran 100,100 iterations, while RoboForm's ran 4,096 — the only count in that group below 100,000. The number sits quietly in a table and is easy to skip past; it is, in effect, the whole answer to how long a stolen vault holds out offline.</p>
<p class="aside-source">Source: Oesch &amp; Ruoti, USENIX Security 2020, Table 6 (the same table the paper's prose summarises as "roughly 100,000" rounds).</p>
</div>

## 4. Applicability and boundaries

**Which product shapes the results cover.** The study is about **browser-centric password managers on desktop**: desktop clients, browser extensions, and the native managers shipped inside six browsers. Not covered: dedicated mobile managers and native mobile autofill frameworks (the authors name this explicitly as necessary future work, Section 7.2), so any conclusion about "password managers" in general should be read as "desktop, browser-based password managers of 2019" — the versions are pinned in the paper. Storage results are further limited to the **local vault**; the cloud back-end was not available for direct evaluation, and the encryption assessment rests on observable ciphertext format and maintainer claims rather than an audit.

**Premises the results rest on.** Generation findings assume the default configuration of each generator and the corpus construction described above; results for length 20 in the neural-network analysis are missing because the analyser ran out of memory, so the strongest-length claims rest on the other three detectors. Autofill findings assume the attacker can reach the page — a network injection (e.g. control of a hostile Wi-Fi access point) or an XSS bug — and, for clickjacking, that the user can be induced to visit the malicious page; the authors argue this is a low bar precisely because an attacker on the same access point can inject into the captive-portal page every user sees.

**What has aged, and how.** Some findings were already changing as the paper was written: KeePassXC moved to Argon2D as its default KDF (retiring the 100,000-round AES-KDF number), LastPass and RoboForm reworked their generation interfaces, Firefox was to replace its built-in manager with Firefox Lockbox, and Edge was to be rebuilt on Chromium. The paper itself credits disclosure: results were given to the maintainers of every manager studied, and RoboForm had already adopted several recommendations. Read today, the durable parts are the *method and the shape of the failure*, not the version numbers — the checklist of questions (what is encrypted, what defaults are set, who triggers autofill, what happens in iframes, does the vault honour `autocomplete`) is what transfers to a new manager or to a new platform.

**Methodological transferability.** The generation methodology — a million-passwords-per-configuration corpus plus four independent non-randomness detectors with Bonferroni correction — is a reusable instrument for any product that emits secrets from an RNG, and the paper is candid about its limits: no test *proves* randomness, so the method can only surface counterexamples, and the negative results on the baselines (`/dev/random`, and several managers) matter as much as the positives because they show the tests were sensitive enough to fire when there was something to find. The same instrument is what the sequel work reuses: Oesch, Gautam and Ruoti applied the autofill threat model to **iOS and Android autofill frameworks** in 2021 [a], and Oesch, Ruoti, Simmons and Gautam followed with an observational user study of how managers are actually used in 2022 [b] — exactly the two boundary conditions this paper flagged (mobile, and real users rather than configured defaults).

**What it means for practice.** The paper's own advice is blunt: among the browser-native managers, avoid Firefox's built-in vault (insecure autofill, harvesting-vulnerable); prefer app- and extension-based managers, which are more capable, store passwords more securely and refuse to fill in cross-origin iframes — with Safari as the exception, since it stores well and avoids autofill mistakes but has a poor generator. Even then, the user must configure the tool correctly, which the authors note is exactly the kind of responsibility users rarely discharge well. The larger lesson for the book's thesis: a password manager still holds a *shared secret* and still releases it into a web page on the user's behalf, so the weakness is structural rather than incidental — which is why the direction of travel in this field is toward secrets that are never handed to the page at all.

## 5. Related literature

- **Z. Li, W. He, D. Akhawe, D. Song, *The Emperor's New Password Manager: Security Analysis of Web-Based Password Managers*, USENIX Security 2014** ([usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li)) — the direct predecessor and the "then" of this paper's title, covering five extension-based managers; chapter 8 of this book. Oesch and Ruoti replicate and update it.
- **D. Silver, S. Jana, D. Boneh, E. Y. Chen, C. Jackson, *Password Managers: Attacks and Defenses*, USENIX Security 2014** ([usenix.org](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver)) — establishes the autofill threat model (network injection, XSS, clickjacking) and proposes the nonce-based defence that Oesch and Ruoti test and find unimplemented.
- **B. Stock, M. Johns, *Protecting Users Against XSS-based Password Manager Abuse*, ASIACCS 2014** ([ACM DL](https://dl.acm.org/doi/10.1145/2590296.2590332)) — the second half of the 2014 autofill pair; source of the "more secure autofill" recommendation this paper checks against all thirteen managers.
- **P. Gasti, K. B. Rasmussen, *On the Security of Password Manager Database Formats*, ESORICS 2012** ([Springer](https://link.springer.com/chapter/10.1007/978-3-642-33167-1_44)) — the storage-side predecessor, which found unencrypted metadata and side-channel leakage; Oesch and Ruoti repeat the exercise on local vaults and find the metadata situation much improved.
- **W. Melicher, B. Ur, S. M. Segreti, S. Komanduri, L. Bauer, N. Christin, L. F. Cranor, *Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks*, USENIX Security 2016** ([usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher)) — the LSTM password guesser re-used here as one of the four generation detectors.
- **D. L. Wheeler, *zxcvbn: Low-Budget Password Strength Estimation*, USENIX Security 2016** ([usenix.org](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler)) — the pattern/guessability estimator used both as a detector and, in the recommendations, as the filter that would let generators reject their own weak output.

**Where the authors place themselves.** They are systematisers and incrementalists, not iconoclasts: the paper's own framing is that managers "have improved" and that the right response is careful selection, correct configuration, better defaults and browser-level support for authentication — notably making password authentication a first-class browser concern and letting managers generate a nonce the browser substitutes on the wire. The field's later trajectory runs straight out of this paper's closing observation that pushing the burden onto users rarely works: the follow-on work moves first to mobile autofill frameworks [a], then to understanding real usage [b], and finally, in chapters 10–12 of this book, to attacking the zero-knowledge guarantees themselves — Fábrega et al.'s injection attacks [c] and the malicious-server analyses that treat the cloud vault, which Oesch and Ruoti could not evaluate, as adversary-controlled.

## 6. Summary and Callbacks

- The paper re-evaluates password-manager security five years after the classic 2014 studies, framing the question as **"that was then, this is now"**: which old findings were fixed, and are managers ready for wide adoption?
- It studies **13 managers** — 2 desktop clients, 5 browser extensions, 6 built into browsers — across **all three stages** of the lifecycle: generation, storage and autofill. It is the first evaluation of password generation, and the first to consider all three stages at once.
- Generation was measured on a corpus of **147 million passwords** ($10 \times 5 \times 3 - 3$: ten generators, five character classes, three lengths, one million each), using Shannon entropy, $\chi^{2}$, zxcvbn and an LSTM password guesser, with Bonferroni correction by 147.
- Most non-random character distributions trace to one feature — requiring at least one character from every class — but the **tail** matters: fewer than 1 in 200 generated passwords is trivially guessable, so length 8 can fall to online guessing, length 12 to offline. Length **10** resists online attacks, **18** resists offline.
- Storage has genuinely improved (KeePassX/KeePassXC encrypt all metadata), but AES-256 vaults still leak: **1Password X's extension settings are plaintext**, Dashlane leaks website icons, every extension leaks the login email, and Firefox's own vault is the weakest of all (3DES, one round of SHA-1).
- Autofill remains the largest attack surface: **only 1Password X and Safari always require user interaction**; several managers autofill compromised pages without asking, and **Firefox's default is vulnerable to domain harvesting through cross-domain iframes**.
- Two proposed fixes are blocked by the ecosystem: the **nonce-based secure autofill** is supported by no manager (browsers forbid extensions from modifying request bodies), and `autocomplete="off"` is **obeyed by no manager**.
- The durable contribution is **methodological**: a corpus-plus-multiple-detectors instrument for auditing any secret generator, and a checklist of storage/autofill questions that transfers to new products and new platforms — which is exactly what the authors' 2021 mobile-autofill [a] and 2022 usage [b] follow-ups do.

**Callbacks.** Chapter 8 asked *that was then*; this chapter is the *now* — the same class of product re-examined, with real fixes and a set of stubborn survivors, and the verdict that the concept is sound while the implementation is where it breaks. Two threads run forward. First, the dull parameter from the aside above: the iteration count that decides how long a stolen vault resists offline guessing stops being a footnote in the next two chapters. Chapter 11 (Duan, Wang and Fu, S&P 2025) finds 35 of 43 managers relying on PBKDF2 or Argon2 to slow guessing, and shows that slowing is not enough — every manager that survives an offline guess adds a second high-entropy secret, because a single master password cannot supply the entropy on its own. Chapter 12 (Scarlata et al., 2026) attacks the parameter itself: a malicious server can suppress a vault's stored KDF settings and drive Bitwarden's cost from $N = 600{,}000$ down to $N = 1$, a roughly 300,000-fold speed-up for the attacker. The iteration count was never a secret the client could trust the server to keep. Second, this chapter's structural point — that a manager still hands a *shared secret* into a web page — is what chapter 10 dismantles: there the attacker needs neither a compromised client nor a broken cipher, because the encrypted state itself leaks.

## References

1. S. Oesch, S. Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. In: Proceedings of the 29th USENIX Security Symposium, USENIX Association, 2020, pp. 2165–2182. https://www.usenix.org/system/files/sec20-oesch_0.pdf
2. Z. Li, W. He, D. Akhawe, D. Song. *The Emperor's New Password Manager: Security Analysis of Web-Based Password Managers*. USENIX Security 2014, pp. 465–479. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/li
3. D. Silver, S. Jana, D. Boneh, E. Y. Chen, C. Jackson. *Password Managers: Attacks and Defenses*. USENIX Security 2014, pp. 449–464. https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver
4. B. Stock, M. Johns. *Protecting Users Against XSS-based Password Manager Abuse*. In: Proceedings of the 9th ACM Symposium on Information, Computer and Communications Security (ASIACCS), 2014, pp. 183–194. https://dl.acm.org/doi/10.1145/2590296.2590332
5. P. Gasti, K. B. Rasmussen. *On the Security of Password Manager Database Formats*. In: European Symposium on Research in Computer Security (ESORICS), Springer, 2012, pp. 770–787. https://link.springer.com/chapter/10.1007/978-3-642-33167-1_44
6. W. Melicher, B. Ur, S. M. Segreti, S. Komanduri, L. Bauer, N. Christin, L. F. Cranor. *Fast, Lean, and Accurate: Modeling Password Guessability Using Neural Networks*. USENIX Security 2016, pp. 175–191. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/melicher
7. D. L. Wheeler. *zxcvbn: Low-Budget Password Strength Estimation*. USENIX Security 2016, pp. 157–173. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler
8. D. Florêncio, C. Herley, P. C. van Oorschot. *An Administrator's Guide to Internet Password Research*. LISA 2014, pp. 44–61. (Source of the $10^{6}$ online / $10^{14}$ offline guess thresholds used by the paper.)
9. C. Herley. *So Long, and No Thanks for the Externalities: The Rational Rejection of Security Advice by Users*. NSPW 2009, pp. 133–144. ACM. https://dl.acm.org/doi/10.1145/1719030.1719050
10. F. Stajano, M. Spencer, G. Jenkinson, Q. Stafford-Fraser. *Password-Manager Friendly (PMF): Semantic Annotations to Improve the Effectiveness of Password Managers*. In: International Conference on Passwords, Springer, 2014, pp. 61–73.
11. Y.-Y. Choong. *A Cognitive-Behavioral Framework of User Password Management Lifecycle*. In: Human Aspects of Information Security, Privacy, and Trust (HAS), Springer, 2014, pp. 127–137. (Source of the three-stage lifecycle model used throughout the paper.)
12. S. Oesch, S. Ruoti. *Research artifacts for "That Was Then, This Is Now"*. https://userlab.utk.edu/papers/oesch2020that

**Follow-on work cited in Section 4–5 of this chapter:**

- [a] S. Oesch, A. Gautam, S. Ruoti. *The Emperor's New Autofill Framework: A Security Analysis of Autofill on iOS and Android*. ACSAC 2021, pp. 996–1010. https://arxiv.org/abs/2104.10017 · https://doi.org/10.1145/3485832.3485884
- [b] S. Oesch, S. Ruoti, J. Simmons, A. Gautam. *"It Basically Started Using Me:" An Observational Study of Password Manager Usage*. CHI 2022. https://doi.org/10.1145/3491102.3517534
- [c] A. Fábrega, A. Namavari, R. Agarwal, B. Nassi, T. Ristenpart. *Exploiting Leakage in Password Managers via Injection Attacks*. USENIX Security 2024, pp. 4337–4354. https://www.usenix.org/conference/usenixsecurity24/presentation/fabrega

## Fact-check checklist

| Claim in this chapter | Source in the paper |
|---|---|
| Authors Sean Oesch and Scott Ruoti, University of Tennessee, Knoxville | Title page (p. 2165–2166) |
| USENIX Security 2020, pp. 2165–2182, 29th symposium, 12–14 August 2020 | Proceedings cover page |
| 13 managers; 2 desktop clients, 5 extensions, 6 browser-native | Abstract; §1 Introduction ("thirteen popular password managers"; "five browser extensions and six password managers integrated directly into the browser… two desktop clients"); Table 1 |
| Manager list per category | Table 1 rows: KeePassX, KeePassXC / 1Password X, Bitwarden, Dashlane, LastPass, RoboForm / Chrome, Edge, Firefox, IE, Opera, Safari |
| Version numbers quoted in §2 of the chapter | §3.1–3.3 (v2.0.3, v2.3.4, v1.14.1, v1.38.0, v6.1908.3, v4.24.0, v8.5.6.6, v71.0, v42.17134, v64.0, v11.523, v58.0.3135, v12.0) |
| 147 million passwords; $10 \times 5 \times 3 - 3$; 1 million per config | §4.2 Password Collection and Analysis, "+This resulted in a corpus of 147 million passwords (10 × 5 × 3 − 3)" |
| Character classes `l`, `ld`, `ls`, `sd`, `all`; lengths 8, 12, 20 | §4.2 |
| Three-stage lifecycle (generation, storage, autofill) | §1; §7 Discussion; reference [8] (Choong) |
| First evaluation of password generation | §1 contribution 2; §2.2 "our work is the first to study the strength of password generators" |
| Four detectors: Shannon entropy, $\chi^{2}$, zxcvbn, LSTM RNN | §4.2; Appendix A Listing 1 |
| Bonferroni correction ×147, capped at 1.00 | §4.2 footnote 5 |
| Shorter passwords vulnerable to online (<10 chars) and offline (<18 chars) attacks | §1 Introduction ("shorter than 10 characters and 18 characters, respectively") |
| Thresholds $10^{6}$ online, $10^{14}$ offline | §4.2, citing reference [16] |
| Weak generated passwords occur fewer than 1 in 200 | §4.3 "Random but Weak Passwords" ("less than 1 in 200") |
| Length 10 online / length 18 offline guidance | §4.3; §7.1 ("10 characters for online resistance, 18 for offline resistance") |
| Non-random distributions explained by "at least one character from each set"; Equations 1 and 2 | §4.3 "Randomness"; Equations (1) and (2) |
| RoboForm (`l`) unexplained; hypothesis of modular-arithmetic bias | §4.3 "Randomness" |
| Bitwarden `sd` and Dashlane `l` explained by equal/unequal set composition | §4.3 "Randomness"; Table 3 |
| Symbol-set sizes: KeePassXC all standard ASCII except space + extended ASCII; KeePassX and Dashlane standard ASCII except space; 1Password X ≥ half of ASCII (19); others ≤ 8 | §4.1 Settings and Features; Table 2 |
| Last-used settings become new defaults (Dashlane exception; KeePassX until restart) | §4.1 |
| Safari: form "xxx-xxx-xxx-xxx"; 100 passwords generated by hand, no obvious problems | §3.3; §4.2 |
| 7 full-support and 2 partial-support generators | §4 opening sentence |
| Storage inspected manually on local databases; cloud not available | §5 opening paragraph |
| AES-256 for app- and extension-based vaults | §5.1 |
| Key derivation rounds: KeePassX/KeePassXC AES-KDF 100,000; 1Password X PBKDF2 100,000; Bitwarden 100,001; LastPass 100,100; RoboForm PBKDF2 4,096; Dashlane Argon2D 3 rounds | §5.1; Table 6 |
| Firefox: 3DES, single round of SHA-1, no master-password policy, "by far the weakest" | §5.1 |
| Chrome/Opera fall back to plaintext on Linux without GNOME keyring/KWallet; CryptProtectData on Windows; macOS keychain-derived keys with passwords stored locally | §5.1; Table 6 footnote 1 |
| KeePassX/KeePassXC encrypt all metadata | §5.2 |
| 1Password X stores extension settings in plaintext (incl. auto-lock, generation defaults, notifications) | §5.2 |
| Dashlane encrypts URLs but not website icons; all extensions leak login email | §5.2 |
| Chrome/Opera (Win/macOS) and Firefox: URL in cleartext; only Firefox encrypts username; reveal creation time, last use, fill count | §5.2 |
| Only KeePassX lacks browser autofill; Bitwarden autofill experimental | §6 opening; footnote 6 |
| Only 1Password X and Safari always require user interaction | §6.1 |
| HTTPS valid cert: KeePassXC/Bitwarden/RoboForm require interaction by default but can be disabled; Dashlane/LastPass/Firefox default to autofill (option exists); Chrome/Edge/IE/Opera always autofill | §6.1 |
| Bad cert: Edge and IE always require interaction; Chrome and Opera disable autofill | §6.1 |
| HTTP: KeePassXC/Bitwarden/RoboForm keep requiring interaction; Dashlane/LastPass/Edge/IE switch to always requiring interaction | §6.1 |
| Same-origin iframe autofill: KeePassXC, 1Password X, Dashlane, LastPass, Bitwarden, RoboForm, all browsers | §6.2 |
| Cross-domain: KeePassXC permits it and the requirement can be disabled; 1Password X/LastPass/RoboForm do not; Bitwarden/Dashlane use top-most window domain; Chrome/Edge/IE/Opera/Safari require interaction (clickjacking remains); Firefox defaults to not requiring it → harvesting | §6.2 |
| `type="text"` filled only by Dashlane | §6.4 |
| Minimal non-login form filled by Bitwarden, Chrome, Edge, Firefox, IE, Opera | §6.4 |
| Form-disparity behaviour (URL, protocol, action, method, renamed fields) | §6.3 |
| Nonce-based autofill unsupported by all; browsers forbid extensions modifying request bodies | §6.5; §7.2 |
| No manager obeys `autocomplete="off"`; W3C spec ambiguity; Mozilla's note | §6.5; references [32], [23] |
| CSRF tokens in 1Password X, Bitwarden, Dashlane, LastPass; RoboForm CSRF changed session timeout | §6.6 |
| CSP: 1Password X/Dashlane clean; Bitwarden two issues; LastPass `unsafe-inline`; RoboForm none; XSS attempts unsuccessful | §6.6 |
| Bookmarklets: only LastPass remains, correctly sandboxed | §6.6 |
| Disclosure to maintainers; RoboForm adopted several recommendations | §Disclosure |
| §3.4 updates: KeePassXC → Argon2D default; LastPass/RoboForm generation UI changes (digit option removed; RoboForm default length 16); Firefox → Lockbox; Edge → Chromium | §3.4 |
| Practical advice: avoid Firefox's built-in manager; prefer app/extension managers; Safari exception | §7 Discussion |
| Research artifacts URL | §Research Artifacts |

## Uncertainties / not obtained

- **Cloud vault encryption not verified.** The paper itself states the cloud databases "are not available to us for direct evaluation"; §5 concerns local vaults only. The encryption descriptions here therefore repeat the paper's own inference from maintainer claims, client options and ciphertext format — not an independent cryptographic audit. The same limitation transfers to this chapter.
- **The `100,000`-round figures are as printed.** Table 6 lists Bitwarden as `100,001` and LastPass as `100,100` rounds while the prose rounds them to "roughly 100,000"; the chapter follows the table for the exact numbers and the prose for the summary.
- **The corpus arithmetic is quoted, not derived.** The paper states $10 \times 5 \times 3 - 3 = 147$ million without enumerating the three missing configurations. This chapter reproduces the paper's figure rather than reconstructing the exclusions, noting only the one exclusion the paper does state (1Password X cannot generate symbols-and-digits-only passwords).
- **RoboForm's bias is a hypothesis.** The paper explicitly says "it is not entirely clear what causes this issue" and offers modular arithmetic as a hypothesis; the chapter labels it as such.
- **Length-20 neural-network results are absent.** The paper reports that the analyser crashed on length-20 passwords (out-of-memory) regardless of settings, so those claims rest on the other three detectors. Stated in §2 and §4 of this chapter.
- **Versions are those of the study period (2019).** Some changed during writing (§3.4) and all have moved on since; the chapter flags this rather than asserting current behaviour.
- **Page range.** The task brief cites pp. 2165–2182, which matches the printed page numbers of the PDF; the USENIX proceedings index is the authority for the official range.

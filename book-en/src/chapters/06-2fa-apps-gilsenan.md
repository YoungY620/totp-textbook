# Security and Privacy Failures in Popular 2FA Apps

<div class="source-card">
<p><strong>Source:</strong> Conor Gilsenan, Fuzail Shakir, Noura Alomar, Serge Egelman. <em>Security and Privacy Failures in Popular 2FA Apps</em>. 32nd USENIX Security Symposium, 2023, pp. 2079–2096. <a href="https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf">Paper PDF</a> · <a href="https://www.usenix.org/system/files/usenixsecurity23-appendix-gilsenan.pdf">Artifact appendix</a> · <a href="https://www.usenix.org/conference/usenixsecurity23/presentation/gilsenan">Presentation page</a></p>
<p><strong>In one sentence:</strong> A systematic analysis of the backup and recovery mechanisms in 22 popular Android TOTP apps finds that most of them quietly re-anchor 2FA on the very factors TOTP was meant to replace — passwords, SMS, and email — and that their encryption is often weak enough to be attacked offline.</p>
</div>

<div class="hook">
You turn on TOTP because SMS codes can be intercepted, and you tell yourself a stolen password is no longer enough to get in. Then the authenticator offers to back your codes up, and in several apps that backup carries the secrets in plaintext — so the keys you just moved off the account now sit in a cloud folder, guarded by the same kind of password login you were trying to leave behind. The extra layer you added for safety is copied, in a weaker form, to whoever holds the backup.
</div>

## 1. Background and the problem

TOTP was sold as an upgrade over SMS 2FA: codes are generated locally from a shared secret, so no network and no phone number is involved. But that design creates a usability tax. The secret lives only on the user's device, and if the device is lost or replaced, or the app uninstalled, the user cannot produce codes and faces lockout across every service protected by TOTP.

Because lockout is the main reason people refuse to adopt 2FA at all, most authenticator apps add some form of **backup**: a manual export, a QR-code transfer, cloud sync, or the platform's own Android Auto Backup. Each choice moves the secret somewhere else. This paper asks what that costs.

- **RQ1** — what personal information leaks to the app's developer or to third parties as a result of using the backup mechanism?
- **RQ2** — what is the risk that an attacker obtains a backup?
- **RQ3** — what is the risk that an attacker who holds a backup recovers the TOTP secrets inside it?

## 2. What they studied

Between November and December 2021 the authors enumerated the Google Play Store for general-purpose TOTP apps. Their queries returned 546 candidates; they removed 193 with fewer than 100,000 installs and 263 whose description contained none of the search terms, leaving 90 reviewed by hand. Apps tied to a single service (e.g. Blizzard Authenticator) and multi-purpose apps that merely embed TOTP — password managers in particular, whose cryptography is far more extensive — were excluded. The final sample is **22 apps** with over **180 million** installs (Table 1 totals 181.5 M+).

The threat model is deliberately narrow. Malware, root access, and on-device compromise are **out of scope**; the phone is assumed unrooted and patched. What the authors analyse is the data in a backup — secret, label, and issuer — **once it leaves the device**. Two words do double duty throughout: *plaintext* means data not end-to-end encrypted before leaving the app, and *encrypted* means the app applied end-to-end encryption before transmission, regardless of TLS. Every app used TLS; TLS alone does not make a backup "encrypted" here.

Provisioning matters for reading the results. Enabling TOTP hands the app three values: the **issuer** (the service's name), the **label** (the user's account name there), and the **secret**. RFC 6238 defines how client and server use the secret but leaves its transfer out of scope; the de facto standard filling the gap is Google's Key URI Format, which encodes those fields in a QR code. Label and issuer are therefore not incidental metadata: together they map every account the user holds.

## 3. Analysis: methodology, mechanisms, and attacks

### 3.1 Methodology

Each APK was pulled from Google Play with ADB and analysed in three phases. **Dynamic analysis** installed each app on a Pixel 3a running a custom Android 9 build (maintained by AppCensus) that records plaintext network traffic to file, with the screen mirrored via `scrcpy` so every transmission could be traced to the tap that caused it. Platform-level capture attributes traffic to a specific app and defeats TLS certificate pinning — problems that defeat ordinary proxies such as mitmproxy or Charles. Because the researchers controlled provisioning, they could plant **known values**: two QR codes carrying chosen issuer, label, and secret, which they then searched for in the captured traffic, so a match proves the field left the device in the clear.

**Cryptanalysis** decompiled each APK with `jadx`, found crypto code via static strings and by comparing signatures to Bouncy Castle and libsodium, and reconstructed two things: how the key was obtained (which KDF, with what salt and iteration count) and which cipher and mode produced the ciphertext, with any integrity mechanism. To prove the reading correct they re-implemented each app's decryption in a standalone Go script and checked it recovered the QR-code secret. Everything is released as a reproducible artifact.

### 3.2 The backup mechanisms, counted

| Mechanism | Apps | Installs |
|---|---|---|
| QR-code transfer (offline) | 7 | 101 M+ |
| Cloud sync, plaintext | 3 | 6.1 M+ |
| Cloud sync, encrypted | 9 | 73.7 M+ |
| File export, plaintext | 5 | 1.8 M+ |
| File export, encrypted | 6 | 1.5 M+ |
| Sharing, plaintext | 7 | 2 M+ |
| Sharing, encrypted | 4 | 1.7 M+ |
| Android Auto Backup | 9 | 2.2 M+ |

The offline option — the one that never touches a network — is rare. Seven apps offer QR-code transfer, and Google Authenticator, the most-installed app by a factor of two or more, supports *only* this. Google noted the feature requires "physical access to [the] phone and the ability to unlock it". But it fails on availability: it is manual, needs a second device, and must be repeated for every account added.

**Plaintext.** Over half the apps — **12**, nearly 8 million installs — can produce plaintext backups. Ten do so through the Android sharing menu, the clipboard, or file export; only **3** sync plaintext to the cloud. Latch sent every field to Latch servers automatically, with no opt-out, and that was its only backup; SAASPASS backed up plaintext over XMPP, optional but repeatedly prompted; 2FAS defaulted to plaintext Google Drive backups. Warnings are the quiet scandal: Section 5.2 counts **4 of the 12** plaintext-capable apps as issuing a real warning — 2FAS, Authenticator Pro, andOTP, and Aegis Authenticator. (The paper's own abstract says "only two"; the section is the more specific account and names the four.) Authenticator Pro warned on file export while offering a clipboard copy with no warning at all.

**Encrypted, and how.** **15** apps, over 74 million installs, support encrypted backups — and encryption is where the failures concentrate. All but one derive the key from a user-chosen password, so an attacker holding a ciphertext can attack it like a password hash. Feasibility depends first on the password, second on the KDF.

*Password policy.* Several apps accept a **single character**; minimum lengths range from 1 (Auth0 Guardian, 2FAS, Authenticator Pro) to 12 (LastPass Authenticator). Duo Mobile rejected known-weak passwords and Latch consulted Have I Been Pwned, but only Aegis shipped a strength meter. Authenticator and App Authenticator could suggest four words from a 6,566-word list, but both then used a static salt, largely cancelling the benefit.

*KDF.* PBKDF2 was the most common choice (**n = 7**; 4 with SHA-1, 3 with SHA-256), but its cost was token: the highest iteration count in the sample was only about **100,000** (andOTP, LastPass Authenticator), against OWASP's guidance of 720,000 for PBKDF2-HMAC-SHA1 and 310,000 for PBKDF2-HMAC-SHA256. Zoho OneAuth and TOTP Authenticator used a **single round of SHA-256** — a fast hash, not a KDF at all — and Authenticator and App Authenticator used the PKCS#12 KDF. Only **3** apps used memory-hard KDFs: Yandex.Key and Aegis Authenticator used scrypt, Duo Mobile used Argon2i.

$$\text{Duo (Argon2i)}: m = 128\ \text{Mb},\ t = 6,\ p = 1; \qquad \text{Aegis (scrypt)}: N = 2^{15},\ r = 8,\ p = 1$$

Random salts were the norm, but Authenticator and App Authenticator hard-coded the salt `ROYALEWITHCHEESEROYALEWITHCHEESE`, enabling rainbow tables; the authors suspect App Authenticator is an unauthorised repackaged clone, sharing the salt and "littered with ads".

*Key management.* Several apps can be decrypted by the service storing the backup, because ciphertext and key (or the password it came from) go to the same entity: **Microsoft Authenticator**, despite using random AES-256 keys from a Microsoft key service, stores the ciphertext on a Microsoft-controlled service (Microsoft confirmed the design as intentional; the iOS version keeps ciphertext in iCloud and does not give Microsoft that capability); **Yandex.Key**, **Zoho OneAuth**, and **Salesforce Authenticator** all sent the backup password to their own servers alongside the ciphertext — Zoho's documentation claims the passphrase is not stored, yet nothing lets a user verify that. **TOTP Authenticator** derives its Google Drive key from a static, hard-coded password, so anyone who decompiles the APK has it.

*Ciphers and integrity.* Of the 15 encrypted-backup apps, **5** used a modern AEAD (Xsalsa20-Poly1305 twice via libsodium's `secret_box`, AES-GCM three times), **5** used AES-CBC, and **3** used AES-ECB, which is deterministic and not IND-CPA. Microsoft Authenticator was the only non-AEAD app to authenticate its ciphertext (HMAC-SHA256); the rest had no MAC and instead guessed whether decryption succeeded by heuristics — is the plaintext valid JSON, a valid URI, or valid Base32? An offline attacker uses the same heuristics, so the missing MAC buys nothing. TOTP Authenticator compounded this with an all-zero IV, and 2FAS uploaded existing TOTP data to Google Drive in plaintext before a backup password was set. andOTP was the only app offering asymmetric encryption, handing the plaintext to a separate PGP app.

**Android Auto Backup.** AAB uploads app data to the user's Google Drive by default, end-to-end encrypted on Android 9+ using the device PIN, pattern, or password. Twelve apps opt out; 10 support it, though three could not be made to run without error. Of the seven that could be observed, six backed up *all* TOTP fields, making the Google account a single point of failure; Google Authenticator backed up only settings. Auth0 Guardian added a password-protected encrypted Realm database.

### 3.3 Privacy: what leaks

Only **2** apps demanded personal data merely to open the app: Twilio Authy (email plus proof of a phone number) and Latch (an account with email). But enabling cloud sync almost always does. Of the **11** cloud-sync apps, **8** required an email address and **5** a phone number; Microsoft Authenticator required phone number, email, name, and date of birth, and Zoho OneAuth collected email, country, and state. The 3 apps uploading directly to Google Drive obtained the user's primary email, name, and account photo through OAuth/OpenID, none of which the backup function needs.

A second leak is invisible to users: several apps encrypt only the secret and ship the issuer and label in the clear. Zoho OneAuth and Twilio Authy send service names and account usernames to their own servers in plaintext, so anyone in the plumbing learns which accounts a user holds. Duo Mobile conditionally includes the issuer or the label in plaintext depending on whether the service is on an internal list of popular sites; Duo's rationale is that showing accounts in a non-restored state helps users set them up again.

### 3.4 Recovery: the circle closes

Of the **19** apps that automatically upload backups to the cloud, **15** required authenticating to the cloud service and **4** relied *solely* on SMS OTP to recover. SAASPASS combined plaintext cloud backups with SMS-only recovery, so anyone who takes over the phone number gets the full backup immediately; an optional 20-hour delay on the recovery OTP gives the user a head start but is off the beaten path. The cloud accounts are themselves ordinary passworded accounts — Latch required only a username and password, with no 2FA supported. Even Google's push to enable 2FA on hundreds of millions of accounts funnels most users into SMS or push, and push recovery can require approving a notification on the very device the user lost.

The conclusion is the paper's sharpest sentence: cloud backup "inevitably reduces the security of the TOTP 2FA scheme to just another layer of the same authentication mechanisms that TOTP 2FA is meant to supersede: username/password, SMS, and/or email."

<div class="aside">
<p><span class="aside-label">Aside · Encrypted, with the key right beside it</span></p>
<p>The key-management findings read like a locked box with the key taped to the lid. Four apps send the backup password, or the key derived from it, to the same party that stores the ciphertext — Microsoft Authenticator, Yandex.Key, Zoho OneAuth, and Salesforce Authenticator — so whoever holds the ciphertext can also decrypt it. Two apps send plaintext secrets to the developer outright, and two hard-code the same salt, handing an attacker a rainbow table for free.</p>
<p class="aside-source">Source: Gilsenan, Shakir, Alomar, Egelman, USENIX Security 2023 — key management (ciphertext and key to the same entity), plaintext secrets to the developer, hard-coded salt.</p>
</div>

## 4. Impact and limitations

**Recommendations.** Apps should not support plaintext backups, and where they do, warn clearly. They must encrypt *all* fields, not just the secret, and apps using remote key servers should split key and ciphertext across different entities. Apps deriving keys from passwords should enforce strong policies, never let the backup password leave the app (wipe it from memory, keep the key in the Android Key Store), and configure the KDF to run *far* slower than password-storage guidance allows — key derivation happens only twice, at setup and at recovery, so the authors propose reusing the familiar 30-second countdown and tuning the KDF to take 30 seconds. They recommend Argon2 for its independently tuneable memory and CPU parameters. andOTP already tuned PBKDF2 rounds to a 1-second budget, but only for the AAB path, not for Google Drive.

**Disclosure.** Six apps had nothing to disclose; andOTP was deprecated; TOTP Authenticator had no security contact. The other 14 developers were contacted with at least 90 days' notice, and 6 never replied. The responses are themselves findings: Twilio let the 2020 Authy issues persist for over two years (v24.3.1 to v24.8.5) before committing to longer backup passwords and more PBKDF2 iterations, and defended sending the issuer and label in plaintext; Latch called plaintext backup "by design", and so did Microsoft; Salesforce pointed to support articles that never address its ability to decrypt. The developer of Authenticator was the outlier — version 1.2.4 switched to random salts and AES-CBC, set a minimum password length of 20, and warned about plaintext export.

**Limitations.** The study is Android-only, and the platforms differ — Microsoft Authenticator is the named counterexample. AAB could not be run without error on three apps that support it. The cryptography of LastPass Authenticator and Auth0 Guardian could not be verified directly; those cells come from documentation and observation and are marked as such in the tables.

## 5. Related work

- **RFC 6238 — TOTP: Time-Based One-Time Password Algorithm** (M'Raihi et al., 2011). <https://www.rfc-editor.org/rfc/rfc6238> The algorithm these apps implement; it leaves secret transfer out of scope — exactly the gap the backup mechanisms fill badly.
- **Google Key URI Format**. <https://github.com/google/google-authenticator/wiki/Key-Uri-Format> The de facto provisioning standard: the `otpauth://` URI and the issuer/label/secret fields that Gilsenan et al. plant to detect leaks.
- **Sean Oesch, Scott Ruoti. "That Was Then, This Is Now" (USENIX Security 2020).** <https://www.usenix.org/system/files/sec20-oesch_0.pdf> A security evaluation of password generation, storage, and autofill in browser-based password managers — the same methodology family applied to a different class of vault; see chapter 9.
- **Giuseppe Bianchi, Lorenzo Valeriani. "Time Is on My Side: Forward-Replay Attacks to TOTP Authentication" (SocialSec 2023).** <https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7> Attacks the TOTP protocol rather than its implementation, replaying codes in the window a server still accepts — what an observed code is worth, where Gilsenan et al. show the secret leaking out of storage; see chapter 7.
- **Sabrina Amft et al. "'We've Disabled MFA for You'" (CCS 2023).** <https://arxiv.org/abs/2306.09708> Studies MFA recovery on 1,303 websites and finds many recovery flows let an attacker with access to the account's email disable MFA entirely — the server-side mirror of this chapter's client-side problem.
- **Sanchari Das, Bingxing Wang, Andrew Kim, L. Jean Camp. "MFA is a Necessary Chore!" (HICSS 2020).** <https://aisel.aisnet.org/hicss-53/os/design/3/> Explores users' mental models of MFA, establishing the lockout fear and the demand for recovery that motivates every backup mechanism analysed here.

## 6. Summary and Callbacks

- The sample is **22** general-purpose Android TOTP apps from Google Play with at least 100,000 installs and a backup mechanism, together over **180 million** installs, selected from 546 candidates in late 2021.
- Methods were dynamic (platform-level network capture on a Pixel 3a, with known QR-code values planted to detect plaintext leaks) plus cryptanalysis (decompile with `jadx`, reconstruct KDF and cipher, re-implement decryption in Go).
- **12** apps could produce plaintext backups, and only **4** of them warned the user (Section 5.2; the abstract says two).
- **15** apps supported encrypted backups, but all but one derived the key from a user password; **5** used an AEAD, **5** AES-CBC, **3** AES-ECB, and Microsoft Authenticator was the only non-AEAD app to authenticate its ciphertext.
- KDFs were routinely too weak: 2 apps used a single round of SHA-256, 2 used a hard-coded salt, and the highest PBKDF2 iteration count was about 100,000.
- **4** apps sent the key or password to the same service that stored the ciphertext, and **2** sent plaintext secrets to the developer outright.
- Recovery routes 2FA back to passwords, SMS, and email: of 19 cloud-backup apps, **4** relied solely on SMS OTP.
- Recommendations: no plaintext backups, encrypt every field, split key from ciphertext, keep the password on-device, and tune the KDF to a 30-second budget (Argon2 preferred).

**Callbacks.** This is where the setup planted when the protocols were standardised first detonates. HOTP and TOTP (chapters 3 and 4) put a shared secret back on both ends so that login would be convenient; chapter 5 proved a scheme could take it off the server, but the market kept the convenience. Now the bill arrives: a secret that has to be stored somewhere ends up in a cloud folder, a plaintext export, or a developer's server — and because backup exists only to survive lockout, it pulls recovery back to passwords, SMS, and email, the very factors TOTP was sold to replace. The same pattern replays from chapter 8 onward, where password managers promise "zero-knowledge" encryption while keeping a copy of the vault, and the detail that decides how long a stolen vault resists cracking — the KDF and its parameters — is as unglamorous as the iteration counts seen here. Chapter 7 goes after the one assumption this chapter leaves untouched: the clock.

## References

1. Conor Gilsenan, Fuzail Shakir, Noura Alomar, Serge Egelman. *Security and Privacy Failures in Popular 2FA Apps*. 32nd USENIX Security Symposium, 2023, pp. 2079–2096. <https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf>
2. Conor Gilsenan, Fuzail Shakir, Noura Alomar, Serge Egelman. *Artifact Appendix* to the same paper. USENIX Security 2023. <https://www.usenix.org/system/files/usenixsecurity23-appendix-gilsenan.pdf> (artifact: <https://github.com/blues-lab/totp-app-analysis-public>)
3. D. M'Raihi, S. Machani, M. Pei, J. Rydell. *TOTP: Time-Based One-Time Password Algorithm*. RFC 6238, IETF, 2011. <https://www.rfc-editor.org/rfc/rfc6238>
4. Google. *Key URI Format* (de facto provisioning standard for TOTP). <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
5. Sean Oesch, Scott Ruoti. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage, and Autofill in Browser-Based Password Managers*. 29th USENIX Security Symposium, 2020, pp. 2165–2182. <https://www.usenix.org/system/files/sec20-oesch_0.pdf>
6. Giuseppe Bianchi, Lorenzo Valeriani. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication*. SocialSec 2023 (Springer), pp. 109–126. <https://link.springer.com/chapter/10.1007/978-981-99-5177-2_7>
7. Sabrina Amft, Sandra Höltervennhoff, Nicolas Huaman, Alexander Krause, Lucy Simko, Yasemin Acar, Sascha Fahl. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor Authentication Recovery Deployments*. ACM CCS 2023, pp. 3138–3152. <https://arxiv.org/abs/2306.09708>
8. Sanchari Das, Bingxing Wang, Andrew Kim, L. Jean Camp. *MFA is a Necessary Chore! Exploring User Mental Models of Multi-Factor Authentication Technologies*. HICSS 2020. <https://aisel.aisnet.org/hicss-53/os/design/3/>

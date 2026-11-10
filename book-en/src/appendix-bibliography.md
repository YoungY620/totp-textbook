# Bibliography

Each chapter carries its own reference list. This page collects the **core primary sources** and the key
works that recur across chapters' "related literature" sections. "Paywalled" means no open-access full text
was obtained, and the chapter states only what could be verified.

## 1. Core sources (one per chapter)

1. Lamport, L. *Password Authentication with Insecure Communication.* Communications of the ACM, 24(11), 1981.
   (**Paywalled**; chapters rely on its published abstract, RFC 1760's description, and public lecture notes.)
2. Haller, N. *The S/KEY One-Time Password System.* RFC 1760, IETF, February 1995.
   <https://www.rfc-editor.org/rfc/rfc1760.txt>
3. M'Raihi, D., Bellare, M., Hoornaert, F., Naccache, D., Ranen, O. *HOTP: An HMAC-Based One-Time
   Password Algorithm.* RFC 4226, IETF, December 2005. <https://www.rfc-editor.org/rfc/rfc4226.txt>
4. M'Raihi, D., Machani, S., Pei, M., Rydell, J. *TOTP: Time-Based One-Time Password Algorithm.*
   RFC 6238, IETF, May 2011. <https://www.rfc-editor.org/rfc/rfc6238.txt>
5. Kogan, D., Manohar, N., Boneh, D. *T/Key: Second-Factor Authentication From Secure Hash Chains.*
   ACM CCS 2017, pp. 983–999. <https://arxiv.org/abs/1708.08424>
6. Gilsenan, C., Shakir, F., Alomar, N., Egelman, S. *Security and Privacy Failures in Popular 2FA Apps.*
   USENIX Security 2023, pp. 2079–2096. <https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf>
7. Bianchi, G., Valeriani, L. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication.*
   SocialSec 2023 (LNCS), pp. 109–126. (**Paywalled**; the chapter relies on the authors' public conference
   slides and the abstract.)
8. Li, Z., He, W., Akhawe, D., Song, D. *The Emperor's New Password Manager: Security Analysis of
   Web-based Password Managers.* USENIX Security 2014.
   <https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-li-zhiwei.pdf>
9. Oesch, S., Ruoti, S. *That Was Then, This Is Now: A Security Evaluation of Password Generation, Storage,
   and Autofill in Browser-Based Password Managers.* USENIX Security 2020, pp. 2165–2182.
   <https://www.usenix.org/system/files/sec20-oesch_0.pdf>
10. Fábrega, A., Namavari, A., Agarwal, R., Nassi, B., Ristenpart, T. *Exploiting Leakage in Password Managers
    via Injection Attacks.* USENIX Security 2024, pp. 4337–4354.
    <https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf>
11. Duan, Y., Wang, D., Fu, Y. *Security Analysis of Master-Password-Protected Password Management
    Protocols.* IEEE S&P 2025, pp. 701–719. DOI 10.1109/SP61157.2025.00050
12. Scarlata, M., Torrisi, G., Backendal, M., Paterson, K. G. *Zero Knowledge (About) Encryption: A
    Comparative Security Analysis of Three Cloud-based Password Managers.* USENIX Security 2026
    (prepublication). See also IACR ePrint 2026/058 for the four-vendor version including 1Password.
    <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>
13. W3C. *Web Authentication: An API for accessing Public Key Credentials, Level 3.*
    <https://www.w3.org/TR/webauthn-3/>; FIDO2 / CTAP specifications from the FIDO Alliance:
    <https://fidoalliance.org/specifications/>

## 2. Standards and specifications

- RFC 2104 *HMAC: Keyed-Hashing for Message Authentication* (Krawczyk, Bellare, Canetti, 1997).
- RFC 2289 *A One-Time Password System* (Haller et al., 1998) — the standardized successor to S/KEY, with the
  race attack and the checksum in the word encoding.
- RFC 6287 *OCRA: OATH Challenge-Response Algorithm* (M'Raihi et al., 2011).
- RFC 2898 *PKCS #5: Password-Based Cryptography Specification* (the origin of PBKDF2).
- Google, *Key URI Format* (`otpauth://`) — the de facto interoperability standard of the TOTP ecosystem, and
  **not** an IETF RFC.

## 3. Password managers: related and follow-on work

- Gasti, P., Rasmussen, K. B. *On the Security of Password Manager Database Formats.* ESORICS 2012.
- Bojinov, H., Bursztein, E., Boyen, X., Boneh, D. *Kamouflage: Loss-Resistant Password Management.*
  ESORICS 2010.
- Chatterjee, R., Bonneau, J., Juels, A., Ristenpart, T. *Cracking-Resistant Password Vaults using Natural
  Language Encoders (NoCrack).* IEEE S&P 2015.
- Oesch, S., Gautam, A., Ruoti, S. *The Emperor's New Autofill Framework: A Security Analysis of Autofill on
  iOS and Android.* ACSAC 2021. <https://arxiv.org/abs/2104.10017>
- Carr, M., Shahandashti, S. F. *Revisiting Security Vulnerabilities in Commercial Password Managers.*
  SEC 2020. <https://arxiv.org/abs/2003.01985>
- Fábrega, A., Ortega Pérez, C., Namavari, A., Nassi, B., Agarwal, R., Ristenpart, T. *Injection Attacks
  Against End-to-End Encrypted Applications.* IEEE S&P 2024.
- Fábrega, A., Breckenridge, S., Namavari, A., Ristenpart, T. *Mitigating Injection Attacks against E2EE
  Applications via View-Based Partitioning.* USENIX Security 2025.
- Davies, G. T. et al. *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol.* CRYPTO 2023 /
  IACR ePrint 2023/843.

## 4. MFA, recovery and passkeys

- Amft, S. et al. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of Multi-Factor
  Authentication Recovery Deployments.* ACM CCS 2023, pp. 3138–3152. <https://arxiv.org/abs/2306.09708>
- Daffalla, A. et al. *A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal Threat
  Models.* USENIX Security 2025.
- Lassak, A. et al. An interview study of passkey adoption barriers. USENIX Security 2024.

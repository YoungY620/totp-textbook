# 参考文献总表

本书每一章各有一份自己的参考文献；这里是**核心一手材料**的汇总，以及各章"相关文献"里反复出现的
关键工作。标注「付费墙」的表示未取得开放获取全文，教材只写可核实的内容。

## 一、核心一手材料（每章一篇）

1. Lamport, L. *Password Authentication with Insecure Communication.* Communications of the ACM,
   24(11), 1981.（**付费墙**；书中依据其公开摘要、RFC 1760 的描述与公开讲义撰写）
2. Haller, N. *The S/KEY One-Time Password System.* RFC 1760, IETF, 1995 年 2 月。
   <https://www.rfc-editor.org/rfc/rfc1760.txt>
3. M'Raihi, D., Bellare, M., Hoornaert, F., Naccache, D., Ranen, O. *HOTP: An HMAC-Based One-Time
   Password Algorithm.* RFC 4226, IETF, 2005 年 12 月。 <https://www.rfc-editor.org/rfc/rfc4226.txt>
4. M'Raihi, D., Machani, S., Pei, M., Rydell, J. *TOTP: Time-Based One-Time Password Algorithm.*
   RFC 6238, IETF, 2011 年 5 月。 <https://www.rfc-editor.org/rfc/rfc6238.txt>
5. Kogan, D., Manohar, N., Boneh, D. *T/Key: Second-Factor Authentication From Secure Hash Chains.*
   ACM CCS 2017, pp. 983–999。 <https://arxiv.org/abs/1708.08424>
6. Gilsenan, C., Shakir, F., Alomar, N., Egelman, S. *Security and Privacy Failures in Popular 2FA Apps.*
   USENIX Security 2023, pp. 2079–2096。 <https://www.usenix.org/system/files/usenixsecurity23-gilsenan.pdf>
7. Bianchi, G., Valeriani, L. *Time Is on My Side: Forward-Replay Attacks to TOTP Authentication.*
   SocialSec 2023 (LNCS), pp. 109–126.（**付费墙**；书中依据作者公开的会议 slides 与摘要撰写）
8. Li, Z., He, W., Akhawe, D., Song, D. *The Emperor's New Password Manager: Security Analysis of
   Web-based Password Managers.* USENIX Security 2014。
   <https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-li-zhiwei.pdf>
9. Oesch, S., Ruoti, S. *That Was Then, This Is Now: A Security Evaluation of Password Generation,
   Storage, and Autofill in Browser-Based Password Managers.* USENIX Security 2020, pp. 2165–2182。
   <https://www.usenix.org/system/files/sec20-oesch_0.pdf>
10. Fábrega, A., Namavari, A., Agarwal, R., Nassi, B., Ristenpart, T. *Exploiting Leakage in Password
    Managers via Injection Attacks.* USENIX Security 2024, pp. 4337–4354。
    <https://www.usenix.org/system/files/usenixsecurity24-fabrega.pdf>
11. Duan, Y., Wang, D., Fu, Y. *Security Analysis of Master-Password-Protected Password Management
    Protocols.* IEEE S&P 2025, pp. 701–719。 DOI 10.1109/SP61157.2025.00050
12. Scarlata, M., Torrisi, G., Backendal, M., Paterson, K. G. *Zero Knowledge (About) Encryption:
    A Comparative Security Analysis of Three Cloud-based Password Managers.* USENIX Security 2026（预出版）。
    另见 IACR ePrint 2026/058（含 1Password 的四厂商全版）。
    <https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf>
13. W3C. *Web Authentication: An API for accessing Public Key Credentials, Level 3.*
    <https://www.w3.org/TR/webauthn-3/>；FIDO Alliance 的 FIDO2 / CTAP 规范见
    <https://fidoalliance.org/specifications/>

## 二、标准与规范

- RFC 2104 *HMAC: Keyed-Hashing for Message Authentication*（Krawczyk, Bellare, Canetti, 1997）。
- RFC 2289 *A One-Time Password System*（Haller 等, 1998）——S/KEY 的标准化续作，含 race attack 与校验和。
- RFC 6287 *OCRA: OATH Challenge-Response Algorithm*（M'Raihi 等, 2011）。
- RFC 2898 *PKCS #5: Password-Based Cryptography Specification*（PBKDF2 的出处）。
- Google, *Key URI Format*（`otpauth://`）——TOTP 生态互操作的事实标准，**不是** IETF RFC。

## 三、密码管理器：相关与后续工作

- Gasti, P., Rasmussen, K. B. *On the Security of Password Manager Database Formats.* ESORICS 2012。
- Bojinov, H., Bursztein, E., Boyen, X., Boneh, D. *Kamouflage: Loss-Resistant Password Management.*
  ESORICS 2010。
- Chatterjee, R., Bonneau, J., Juels, A., Ristenpart, T. *Cracking-Resistant Password Vaults using
  Natural Language Encoders (NoCrack).* IEEE S&P 2015。
- Oesch, S., Gautam, A., Ruoti, S. *The Emperor's New Autofill Framework: A Security Analysis of
  Autofill on iOS and Android.* ACSAC 2021。 <https://arxiv.org/abs/2104.10017>
- Carr, M., Shahandashti, S. F. *Revisiting Security Vulnerabilities in Commercial Password Managers.*
  SEC 2020。 <https://arxiv.org/abs/2003.01985>
- Fábrega, A., Ortega Pérez, C., Namavari, A., Nassi, B., Agarwal, R., Ristenpart, T. *Injection Attacks
  Against End-to-End Encrypted Applications.* IEEE S&P 2024。
- Fábrega, A., Breckenridge, S., Namavari, A., Ristenpart, T. *Mitigating Injection Attacks against E2EE
  Applications via View-Based Partitioning.* USENIX Security 2025。
- Davies, G. T. 等. *Security Analysis of the WhatsApp End-to-End Encrypted Backup Protocol.*
  CRYPTO 2023 / IACR ePrint 2023/843。

## 四、MFA、恢复流程与 Passkeys

- Amft, S. 等. *"We've Disabled MFA for You": An Evaluation of the Security and Usability of
  Multi-Factor Authentication Recovery Deployments.* ACM CCS 2023, pp. 3138–3152。
  <https://arxiv.org/abs/2306.09708>
- Daffalla, A. 等. *A Framework for Abusability Analysis: The Case of Passkeys in Interpersonal
  Threat Models.* USENIX Security 2025。
- Lassak, A. 等. 关于 passkey 采用障碍的访谈研究，USENIX Security 2024。

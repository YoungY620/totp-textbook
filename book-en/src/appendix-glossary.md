# Glossary

Alphabetical. Hovering (or tapping) a term in the text shows a one-line definition; clicking jumps here.
The chapter where a term first appears is in parentheses.

## A

- **Argon2** — A memory-hard password-hashing function, designed to resist hardware-accelerated guessing.
- **autofill** — A password manager inserting credentials into a web form; a frequent source of
  origin-check bugs. (Chapter 9)

## C

- **confidentiality / integrity** — "Can't read it" vs "can't change it". Attacks on password
  managers are usually sorted along these two axes. (Chapter 12)
- **counter resynchronization** — The server trying forward counters to tolerate client drift;
  in TOTP this becomes tolerating a few time steps of clock skew. (Chapters 3, 4)

## D

- **Dynamic Truncation (DT)** — How HOTP/TOTP reduces an HMAC output to digits: take the low 4 bits
  of the last byte as an offset, extract 4 bytes, mask the top bit for a 31-bit integer, then reduce
  modulo $10^{\text{Digit}}$. (Chapter 3)

## E

- **end-to-end encryption (E2EE)** — Only the endpoints can decrypt; a server holding ciphertext
  learns nothing. The "zero-knowledge" promise of password managers belongs to this family.
  (Chapters 5, 10, 12)

## F

- **forward-replay attack** — Setting a device clock *forward* to harvest "future" TOTP codes in bulk,
  then replaying them when their time comes. No cryptography is broken. (Chapter 7)

## H

- **hash chain** — A sequence with $w_{i} = H(w_{i+1})$, revealed in reverse order so each value is
  verified with one hash. Lamport's original 1981 construction. (Chapters 1, 2, 5)
- **HMAC** — The keyed message authentication code of RFC 2104; the primitive behind HOTP and TOTP.
- **honey vault** — Decrypting with a wrong master password yields plausible fake credentials, so an
  offline guesser cannot tell whether it guessed right. It does not close the protocol-level gap. (Chapter 11)
- **HOTP** — RFC 4226: $\mathrm{HOTP} = \mathrm{DT}(\mathrm{HMAC\text{-}SHA1}(K, C)) \bmod 10^{\text{Digit}}$,
  with an **event counter** $C$ as the moving factor. (Chapter 3)

## K

- **KDBX** — The vault file format of the KeePass family; products sharing a format share a class of flaws. (Chapter 10)
- **KDF (key derivation function)** — Turns a master password into encryption keys, deliberately slowly
  and salted. Its **iteration count** decides the offline cracking cost of a stolen vault. (Chapters 9, 11, 12)
- **key hierarchy** — Master password derives intermediate keys, which encrypt data keys. Standard in
  cloud password managers, and a focus for attackers. (Chapter 12)

## M

- **master password** — The single password from which all vault keys are derived. The server never stores
  it — but it often stores enough to verify guesses. (Chapter 11)
- **M3PM protocol** — The cryptographic protocol by which a client authenticates with a master password
  and retrieves credentials while the vault stays oblivious to the server. Secure vault *encryption* does
  not imply a secure *protocol*. (Chapter 11)

## N

- **non-malleability** — An attacker cannot transform one credential into another and still validate;
  with indistinguishability, one of the two classic goals for vault storage formats. (Chapters 9, 11)
- **nonce** — A single-use random value used to stop replay. Proposed for tagging form origins in
  autofill, but not adopted by mainstream products. (Chapter 9)

## O

- **OCRA** — RFC 6287, OATH's challenge-response OTP algorithm; the branch of the OTP family that relies
  on neither a counter nor a clock.
- **one-time password (OTP)** — A password valid for a single session and then discarded.

## P

- **passkey** — A WebAuthn credential that can sync across devices. The spec describes device binding and
  backup with the BE/BS flags: `00` single-device, `10` multi-device not backed up, `11` multi-device backed
  up, `01` invalid. (Chapter 13)
- **password manager** — A tool that generates, stores and autofills credentials.
- **PBKDF2** — A password-based KDF (RFC 2898) still used by several managers; iteration count is the
  decisive parameter. (Chapter 9)
- **phishing** — Tricking a user into handing credentials — including live codes — to an attacker. TOTP is a
  shared secret and **inherently not phishing-resistant**; this is WebAuthn's starting point. (Chapter 13)

## S

- **S/KEY** — The one-time password system of RFC 1760/2289, which engineered Lamport's hash chain into
  early Unix logins and encoded passwords as six short English words. (Chapter 2)
- **shared secret** — A secret held by both client and server. All of TOTP's security rests on it not
  leaking; if the server is breached, every user's second factor is exposed at once. (Chapters 3, 4, 5)
- **side channel** — Inferring secrets from "non-content" signals: ciphertext length, network timing,
  error messages. Many password-manager attacks beyond forward-replay rely on it. (Chapters 10, 12)
- **symmetric key** — One key for both encryption and decryption; the shared secret of HOTP/TOTP.

## T

- **threat model** — The explicitly assumed adversary capabilities. The recurring dividing line in this book
  is "server trusted" vs "server may be malicious". (Chapters 5, 10, 11, 12)
- **throttling** — Server-side rate limiting of verification attempts. RFC 4226's security analysis shows the
  optimal attack is brute force under an ideal HMAC, so **rate limiting, not longer codes, is the key defence**.
  (Chapter 3)
- **time as a trust input** — One of the book's motifs: TOTP treats the local clock as given, yet the clock
  can be manipulated. (Chapters 4, 7)
- **time step** — TOTP's unit of time: $T = \lfloor (\text{current Unix time} - T_0)/X \rfloor$, with defaults
  $T_0 = 0$ and $X = 30$ seconds. (Chapter 4)
- **T/Key** — A CCS 2017 scheme that keeps TOTP-like usability while leaving **no secret on the server**;
  the price is a much longer chain, periodic reinitialisation and growing verification cost. (Chapter 5)
- **TOTP** — RFC 6238: HOTP with the event counter replaced by a time step; the standard behind nearly
  every authenticator app today. (Chapter 4)
- **two-factor authentication (2FA)** — Requiring something you have or are, beyond something you know. (Chapter 6)

## U

- **unlinkability** — A server should not be able to correlate a single user's separate actions. (Chapter 8)

## W

- **WebAuthn** — The W3C specification that replaces shared secrets with public-key credentials bound to an
  origin; the server stores only the public key. (Chapter 13)

## Z

- **zero-knowledge encryption** — A marketing term widely used by cloud password managers, claiming the
  server cannot read the vault even when it misbehaves. It has **no strict technical definition** — which is
  exactly where the trouble starts. (Chapter 12)

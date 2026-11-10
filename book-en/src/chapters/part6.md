# Part VI · The Way Out

By now the pattern is hard to miss: as long as authentication rests on a **shared secret**, someone
must answer where that secret lives, who can see it, where its backup goes, and whose clock decides.
Every generation answered those questions imperfectly.

So the last answer changes the premise: **stop sharing a secret.**

WebAuthn and passkeys replace it with public keys. The private key never leaves the device and is
bound to a specific web origin; the server holds only the public half. A phishing site does not get a
password — it gets **a signature that is useless to it**. And a breached server no longer means
"everyone's second factor is exposed".

This is, at last, what Lamport wanted in Act I: **a server that does not need to be trusted.** It also
brings its own new problems — key sync, account recovery, and a fresh trust assumption about the
platform holding your key.

Six acts later the question is back where it started, except that now we know exactly how hard it is.

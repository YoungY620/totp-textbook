# Part V · The Other Front

Now turn the camera to password managers. On the surface this is a different front: what they guard
is not a one-time code but all your passwords. But the question they raise is **the same one asked by
the same character** — *when the server cannot be trusted, where does the secret go?*

The cloud password manager's answer is called "zero-knowledge encryption": encrypt locally, upload
ciphertext, and the server never sees plaintext. That promise is the modern restatement of Lamport's
1981 move — **take the secret off the server**.

So this act becomes a twelve-year acceptance test. From the first analysis of web-based managers in
2014, through the 2020 re-check, the injection attacks of 2024, the formal protocol analysis of 2025,
and the 2026 systematic attacks on three vendors under a **fully malicious server** — researchers keep
asking one question:

> **What does "zero-knowledge encryption" actually protect, and where does it quietly leak?**

This is the longest and most detective-like act in the book.

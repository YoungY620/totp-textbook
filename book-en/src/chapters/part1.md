# Part I · Origins

The story starts with a small, unglamorous observation.

In 1981 a Unix system kept every user's password in a table that could be read or cracked offline.
Anyone who got that table got **every** account at once. Password authentication had a second,
awkward premise too: it assumed nobody was watching the wire — and nobody ever isn't.

Leslie Lamport's answer was unexpectedly elegant: **let the server hold nothing that can log anyone in.**
The user carries a hash chain and steps it forward on each login; the server keeps only the tail and
verifies with a single hash. A password an eavesdropper captured is worthless a minute later.

This act has two scenes: Lamport's scalpel that **takes the secret off the server** (Chapter 1), and
S/KEY, which fitted that idea into early Unix logins — down to encoding passwords as six memorable
English words (Chapter 2).

Remember that move — *taking the secret away*. In the next act it gets put back.

# Part III · Counterattack

By 2017 TOTP was everywhere, and so was its flaw: **break the server and you get everyone's second
factor at once.** The attacker never has to defeat you — only the database holding everyone's shared
secrets.

It is the opening crisis of Act I all over again. So someone went back and asked Lamport's old
question: **can we keep everything that makes TOTP convenient, and still leave no secret on the
server?**

T/Key is that counterattack. It brings the hash chain back on stage, fixes the old S/KEY complaint
that chains are too short to last, and comes with a proof. It also pays a price — and that price is
the most honest and most memorable part of the story.

This act is a single chapter, but it is the hinge of the book: **what does it cost to take the
secret away again?**

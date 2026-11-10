# Part II · Standardization

The hash chain was a good idea and a clumsy product. The chain is finite and must be reinitialised;
client and server have to stay in step by counting how far along they are. In 2005 a group of
standards authors decided to trade it for something else: **HMAC**.

The gains were large — long keys, fast and stable codes, and a formal security analysis written
right into the document. The price was quiet but real: **client and server now share one secret.**
The very thing Lamport had taken off the server in Act I was put back on.

HOTP (2005) and TOTP (2011), which swaps the counter for a time step, became the foundation of every
authenticator app today: your phone and the server each hold the same key, never speak to each other,
and still produce the same six digits.

This act is the book's biggest setup. That decision — *put the secret back on the server* — comes
back to bite in Act IV (backups and key leakage) and Act V (the "zero-knowledge" claims of password
managers), in forms nobody in 2005 saw coming.

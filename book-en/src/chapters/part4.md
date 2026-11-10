# Part IV · Reality Bites Back

By now a cryptographer could call it a day: HOTP/TOTP is provably secure, and T/Key goes further.
Yet the breach reports never stopped.

The reason is plain: **the algorithm did not lose — everything around it did.** Where the key lives,
where backups get uploaded, who does the encrypting, and whose clock you trust are the real
battlefield.

Two scenes. First, a 2023 check-up on 22 Android authenticator apps (Chapter 6): plaintext uploads,
weak key derivation, secrets handed to the developer, encrypted backups that crack offline — in many
apps the word "encrypted" means almost nothing. The second is more theatrical (Chapter 7): the
attacker breaks nothing at all. They simply **set the phone's clock forward**, harvest "future" codes
in bulk, and replay them when the time comes.

The setup from Act II detonates here for the first time: **whoever you hand the secret to, you hand
the future to.**

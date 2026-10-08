-- Protocol v7 (docs/protocol.md, "v7: a new phone types the computer's code"): the computer shows
-- the 6-digit code and the phone types it, through a password-authenticated key exchange the
-- server only relays. Additive only. Same columns as miblo.ai's 0033_phone_pake.
-- phone_requests: pake, this computer's public share of the current attempt (JSON {n, rs, ya,
-- wrong}; never the code); pake_answer, the phone's answer to that attempt (JSON {n, ya, yb, tag,
-- wa?}), set once per attempt and cleared by a new one.
ALTER TABLE phone_requests ADD COLUMN pake TEXT;
ALTER TABLE phone_requests ADD COLUMN pake_answer TEXT;
-- account_phones: one passkey per phone (v7). A new identity that re-uses the phone's passkey
-- lists its public key (pk: JSON {id, x, y}) and an assertion over the identity (pkwa) instead of
-- a registration (att, cdj).
ALTER TABLE account_phones ADD COLUMN pk TEXT;
ALTER TABLE account_phones ADD COLUMN pkwa TEXT;

-- v6 push (docs/protocol.md, "Push: phones changed"): a counter per phone, bumped by
-- every write that changes what the phone reads (its computers' requests and grants, its
-- revocation, a computer unlinked). The phone's long poll reads this one value every 500 ms and
-- reads its grants and requests again only when it moved. Additive only.
ALTER TABLE account_phones ADD COLUMN rev INTEGER NOT NULL DEFAULT 0;

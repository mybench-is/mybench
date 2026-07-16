# anchor

**Single responsibility:** anchor ledger commitments and Merkle roots to public
timestamp authorities (OpenTimestamps plus a public anchors repo) so that timing
and volume become independently provable. It publishes only salted commitments,
Merkle roots, and timestamps — never content, prompt text, code, or filenames
(privacy invariant #1).

`anchor cut` also appends one private `anchor_receipt` ledger observation after
the date-only event and pending proof stage successfully. Its `receipt_ts` is
sampled immediately after the first OTS calendar response successfully merges;
it never enters the public event or proof. See
[`docs/private-anchor-receipts.md`](../../../docs/private-anchor-receipts.md).

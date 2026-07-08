# verify

**Single responsibility:** independently verify published attestations — recompute
Merkle roots, check OpenTimestamps proofs, and confirm commitments match a
disclosed `(nonce, length, content)` triple — without trusting the scorer or
daemon. Powers the "verification instructions" shipped with every report.

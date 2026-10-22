# Public incident snapshot

Source: <https://github.com/galadran/we-have-a-problem.com>, commit
`2086d67fb486982ab58aab2c965855aadf4c4a24`, retrieved over verified HTTPS Git
on 2026-10-22. Public incident identifier: CVE-2026-111943.

Upstream presentation and downloadable equivalents:

- <https://emudhra.we-have-a-problem.com/>
- <https://emudhra.we-have-a-problem.com/chains.zip>
- <https://emudhra.we-have-a-problem.com/impacted-intermediates.json>
- <https://emudhra.we-have-a-problem.com/roots.json>

`data/` retains the upstream JSON and all fourteen PEM chains verbatim. Twelve
regular endpoints cover six TLS keys, each under eMudhra and Sectigo signatures.
The upstream snapshot also includes two additional DV G3B endpoints without
Certificate Transparency SCTs. Four code-signing certificate identities cover
two keys, each with two issuers. Four root identities include the ECC cross-signer.
The eMudhra TLS chain's advertised issuer is the cross-signed emSign Root TLS
CA G3; the ultimate offline trust anchor may be emSign ECC Root CA G3 instead.

`SHA256SUMS` pins the bytes of each bundled file. Load verifies these hashes,
checks each JSON certificate's DER SHA-256 and SPKI SHA-256 against its published
metadata, matches the actual intermediate certificate in every chain, verifies
adjacent signatures, and verifies the published leaf hostname. Unit tests check
six TLS keys/two code-signing keys and the expected cross-sign counts.

These are public certificates, not private keys. No upstream executable scripts,
private keys or compromise proof artifacts are distributed. The upstream
repository does not specify a software license in this snapshot; these public
certificate/incident facts are retained with attribution. Project source is MIT.

Integrity hashes detect changes; they are not an independent attestation of the
incident, a CVE authority confirmation, or an upstream cryptographic signature.
We used the linked Git source, rather than disabling TLS verification or
requiring access to the separately hosted ZIP. Refreshes must be reviewed against
a pinned upstream commit and repeat all identity/signature/hostname checks;
never update fixtures silently during a scan.

# WebAuthnAssertionReview

Offline WebAuthn get assertion verification from a saved ceremony plus explicit trusted registration record; PEM Ed25519/ES256 key profile.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `webauthn-assertion-review request.json` or pipe JSON to `webauthn-assertion-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Authentication assertion only, no registration or login service. AT/ED extensions, cross-origin, tokenBinding and other algorithms rejected. Caller must authenticate the saved context; this CLI does not persist replay state or prove a login occurred.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `credential` is a saved `public-key` get assertion with canonical base64url id/rawId, clientDataJSON, 37-byte extension-free authenticatorData and signature. Required `trusted_record` supplies authenticated credential_id, public PEM key, Ed25519 or ES256 algorithm and previous sign_count, optionally user_handle. Required `expected_challenge` (at least 16 bytes), exact HTTPS `expected_origin`, `expected_rp_id` and boolean `require_user_verification` come from the authorized saved ceremony. Counter replay, ID, RP hash, challenge, origin, user handle if returned, flags and actual signature are checked. Public-suffix registration policy and authentication-context provenance are caller responsibilities. No replay state is stored and no login is performed.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
webauthn-assertion-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.

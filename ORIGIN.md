# Origin and implementation scope

WebAuthnAssertionReview independently implements this selected scope: Offline WebAuthn get assertion verification from a saved ceremony plus explicit trusted registration record; PEM Ed25519/ES256 key profile.

The research source is [duo-labs/py_webauthn](https://github.com/duo-labs/py_webauthn) at fixed commit `d72e0f53cb6684fdd2f178bae83aeab8bda64665`. Source archive SHA-256: `f2517388b0b99020c8682d9932a80fb79b1a213c637e40ebe5cda17a57fa5c82`. Its license is BSD-3-Clause; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [webauthn/authentication/verify_authentication_response.py](https://github.com/duo-labs/py_webauthn/blob/d72e0f53cb6684fdd2f178bae83aeab8bda64665/webauthn/authentication/verify_authentication_response.py) — SHA-256 `b087274473e97db241fee2d0b2f65098899cb526cc5ce7c7257f4d4930e304fe`.
- [webauthn/helpers/parse_authenticator_data.py](https://github.com/duo-labs/py_webauthn/blob/d72e0f53cb6684fdd2f178bae83aeab8bda64665/webauthn/helpers/parse_authenticator_data.py) — SHA-256 `a8c3f0c218c3a5546eb841db1fe25c9360813acd98c58f27161abd607ff7cf74`.
- [webauthn/helpers/parse_client_data_json.py](https://github.com/duo-labs/py_webauthn/blob/d72e0f53cb6684fdd2f178bae83aeab8bda64665/webauthn/helpers/parse_client_data_json.py) — SHA-256 `f2284aed185100c44fd3587668377a3137e72ba9880f8eea25c54f1dff8940ed`.
- [webauthn/helpers/parse_backup_flags.py](https://github.com/duo-labs/py_webauthn/blob/d72e0f53cb6684fdd2f178bae83aeab8bda64665/webauthn/helpers/parse_backup_flags.py) — SHA-256 `ad9356d061b038d62525310d5e73847b3eda42c617fbbc998861a8bcb71633b7`.
- [webauthn/helpers/verify_signature.py](https://github.com/duo-labs/py_webauthn/blob/d72e0f53cb6684fdd2f178bae83aeab8bda64665/webauthn/helpers/verify_signature.py) — SHA-256 `86e734a985495b53fcc573d0515f74f7dcfbb25669993f030e951d9d3536fb84`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on assertion challenge/origin/RP and credential binding, UP/UV/backup flags and monotonic sign counter, authenticatorData plus clientDataJSON hash signature input. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `credential` is a saved `public-key` get assertion with canonical base64url id/rawId, clientDataJSON, 37-byte extension-free authenticatorData and signature. Required `trusted_record` supplies authenticated credential_id, public PEM key, Ed25519 or ES256 algorithm and previous sign_count, optionally user_handle. Required `expected_challenge` (at least 16 bytes), exact HTTPS `expected_origin`, `expected_rp_id` and boolean `require_user_verification` come from the authorized saved ceremony. Counter replay, ID, RP hash, challenge, origin, user handle if returned, flags and actual signature are checked. Public-suffix registration policy and authentication-context provenance are caller responsibilities. No replay state is stored and no login is performed.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.

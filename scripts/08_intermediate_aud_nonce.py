"""aud and nonce are not checked on intermediate delegation hops.

A KB-JWT's aud and nonce bind a presentation to one verifier and one challenge.
verify_chain enforces expected_aud/expected_nonce only on the terminal hop, and
kb_sd_jwt.verify skips the check for intermediate hop types, so an intermediate
hop is accepted under the wrong aud and nonce.

Same code area as issue #319. The Delegate SD-JWT draft also places replay
protection at the final presentation rather than every hop, so this is the gap
between an intuitive expectation and what the chain verifier actually checks.

Refs:
  https://github.com/google-agentic-commerce/AP2/issues/319
  https://github.com/GarethCOliver/gco-delegate-sd-jwt
"""

import json

from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.sdjwt import kb_sd_jwt, parse_token, sd_jwt
from jwcrypto.jwk import JWK


def cnf_of(key: JWK) -> dict:
    return {"jwk": json.loads(key.export_public())}


def main() -> None:
    issuer = JWK.generate(kty="EC", crv="P-256")
    holder = JWK.generate(kty="EC", crv="P-256")
    nxt = JWK.generate(kty="EC", crv="P-256")

    parent = sd_jwt.create(
        payload=OpenPaymentMandate(constraints=[], cnf=cnf_of(holder)), issuer_key=issuer
    ).sd_jwt_issuance

    hop = kb_sd_jwt.create(
        prev_token=parse_token(parent),
        holder_key=holder,
        payload=OpenPaymentMandate(constraints=[], cnf=cnf_of(nxt)),
        aud="verifier-a",
        nonce="challenge-a",
    ).sd_jwt_issuance

    parsed = parse_token(parent)
    payload = sd_jwt.verify(parsed.canonical, JWK.from_json(issuer.export_public()))
    verified_parent = parsed.with_verified_payload(payload, [])

    try:
        kb_sd_jwt.verify(parse_token(hop), verified_parent, expected_aud="wrong", expected_nonce="wrong")
        accepted = True
    except Exception:
        accepted = False

    print(f"intermediate hop built with aud=verifier-a nonce=challenge-a")
    print(f"{'ACCEPTED' if accepted else 'rejected':8} verifying it with aud=wrong nonce=wrong")

    assert accepted, "intermediate hop should accept the wrong aud/nonce (checked only at terminal)"


if __name__ == "__main__":
    main()

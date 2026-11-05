"""Chain binding and signature type-safety hold against classic JWT attacks.

Two attacks that often work on hand-rolled JWT stacks:
  - splicing a delegation hop onto a different parent token
  - algorithm confusion (alg=none, or an EC public key used as an HMAC secret)

AP2 builds on jwcrypto with typed keys, so both are rejected. This is the part
of the stack you can rely on.

Refs:
  https://datatracker.ietf.org/doc/rfc9901/
  https://github.com/GarethCOliver/gco-delegate-sd-jwt
"""

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.sdjwt import kb_sd_jwt, parse_token, sd_jwt


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def cnf_of(key: JWK) -> dict:
    return {"jwk": json.loads(key.export_public())}


def root_open(issuer: JWK, holder: JWK) -> str:
    payload = OpenPaymentMandate(constraints=[], cnf=cnf_of(holder))
    return sd_jwt.create(payload=payload, issuer_key=issuer).sd_jwt_issuance


def rejects(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


def splice_rejected() -> bool:
    issuer = JWK.generate(kty="EC", crv="P-256")
    holder = JWK.generate(kty="EC", crv="P-256")
    nxt = JWK.generate(kty="EC", crv="P-256")

    parent = root_open(issuer, holder)
    hop = kb_sd_jwt.create(
        prev_token=parse_token(parent),
        holder_key=holder,
        payload=OpenPaymentMandate(constraints=[], cnf=cnf_of(nxt)),
        aud="verifier",
        nonce="challenge",
    ).sd_jwt_issuance

    other = root_open(issuer, JWK.generate(kty="EC", crv="P-256"))
    parsed = parse_token(other)
    payload = sd_jwt.verify(parsed.canonical, JWK.from_json(issuer.export_public()))
    other_verified = parsed.with_verified_payload(payload, [])
    return rejects(lambda: kb_sd_jwt.verify(parse_token(hop), other_verified))


def alg_none_rejected(token: str, pub: JWK) -> bool:
    jwt_part, _, disclosures = token.partition("~")
    _, body, _ = jwt_part.split(".")
    header = b64url(json.dumps({"alg": "none", "typ": "example+sd-jwt"}).encode())
    forged = f"{header}.{body}.~{disclosures}"
    return rejects(lambda: sd_jwt.verify(forged, pub))


def hmac_confusion_rejected(token: str, pub: JWK) -> bool:
    jwt_part, _, disclosures = token.partition("~")
    _, body, _ = jwt_part.split(".")
    pem = serialization.load_pem_public_key(pub.export_to_pem()).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = b64url(json.dumps({"alg": "HS256", "typ": "example+sd-jwt"}).encode())
    signature = b64url(hmac.new(pem, f"{header}.{body}".encode(), hashlib.sha256).digest())
    forged = f"{header}.{body}.{signature}~{disclosures}"
    return rejects(lambda: sd_jwt.verify(forged, pub))


def main() -> None:
    issuer = JWK.generate(kty="EC", crv="P-256")
    pub = JWK.from_json(issuer.export_public())
    token = sd_jwt.create(
        payload=PaymentMandate(
            transaction_id="tx",
            payee=Merchant(name="Shop", id="s"),
            payment_amount=Amount(amount=1000, currency="USD"),
            payment_instrument=PaymentInstrument(id="pi", type="credit"),
        ),
        issuer_key=issuer,
    ).sd_jwt_issuance

    results = {
        "chain splice onto a different parent": splice_rejected(),
        "alg=none forgery": alg_none_rejected(token, pub),
        "EC-key-as-HMAC confusion": hmac_confusion_rejected(token, pub),
    }
    for label, rejected in results.items():
        print(f"{'rejected' if rejected else 'ACCEPTED':8} {label}")

    assert all(results.values()), "every forgery must be rejected"


if __name__ == "__main__":
    main()

"""The issuer signature makes a mandate tamper-evident.

Three attempts against a signed Payment Mandate:
  - editing the signed body            -> signature fails
  - re-signing with an attacker key    -> rejected under the honest key
  - injecting a forged disclosure      -> dropped, since its digest is not in _sd

This is the integrity guarantee the rest of the system builds on.

Ref: https://datatracker.ietf.org/doc/rfc9901/
"""

import base64
import json

from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.sdjwt import sd_jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def signed_mandate(key: JWK) -> str:
    mandate = PaymentMandate(
        transaction_id="tx-123",
        payee=Merchant(name="Honest Shop", id="shop-1"),
        payment_amount=Amount(amount=1000, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi-1", type="credit"),
    )
    return sd_jwt.create(payload=mandate, issuer_key=key).sd_jwt_issuance


def rejects(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


def main() -> None:
    key = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    pub = JWK.from_json(key.export_public())
    token = signed_mandate(key)
    jwt_part, _, disclosures = token.partition("~")
    header, body, signature = jwt_part.split(".")

    claims = json.loads(b64d(body))
    claims["injected"] = True
    edited = f"{header}.{b64url(json.dumps(claims).encode())}.{signature}~{disclosures}"
    body_tamper_rejected = rejects(lambda: sd_jwt.verify(edited, pub))

    attacker = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    wrong_key_rejected = rejects(lambda: sd_jwt.verify(signed_mandate(attacker), pub))

    forged = b64url(json.dumps(["salt", "payment_amount", {"amount": 999999, "currency": "USD"}]).encode())
    resolved = sd_jwt.verify(f"{jwt_part}~{forged}~", pub)
    disclosed = [part for part in resolved["delegate_payload"] if isinstance(part, dict)]
    forged_disclosure_dropped = not disclosed

    print(f"{'rejected' if body_tamper_rejected else 'ACCEPTED':8} editing the signed body")
    print(f"{'rejected' if wrong_key_rejected else 'ACCEPTED':8} re-signing with an attacker key")
    print(f"{'dropped' if forged_disclosure_dropped else 'KEPT':8} forged disclosure not in _sd")

    assert body_tamper_rejected
    assert wrong_key_rejected
    assert forged_disclosure_dropped


if __name__ == "__main__":
    main()

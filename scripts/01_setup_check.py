"""Sign and verify a mandate to confirm the lab environment works.

If this prints a verified payload, the SDK is installed correctly and the rest
of the scripts will run.
"""

from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.sdjwt import sd_jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK


def main() -> None:
    signing_key = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    public_key = JWK.from_json(signing_key.export_public())

    mandate = PaymentMandate(
        transaction_id="tx-123",
        payee=Merchant(name="Honest Shop", id="shop-1"),
        payment_amount=Amount(amount=1000, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi-1", type="credit"),
    )

    token = sd_jwt.create(payload=mandate, issuer_key=signing_key).sd_jwt_issuance
    resolved = sd_jwt.verify(token, public_key)
    disclosed = next(part for part in resolved["delegate_payload"] if isinstance(part, dict))

    print(f"signed and verified {len(token)}-char SD-JWT")
    print(f"payee  {disclosed['payee']['name']}")
    print(f"amount {disclosed['payment_amount']['amount']} {disclosed['payment_amount']['currency']}")

    assert disclosed["payment_amount"]["amount"] == 1000


if __name__ == "__main__":
    main()

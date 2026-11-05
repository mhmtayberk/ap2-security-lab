"""Unknown constraints are coerced to a no-op instead of failing.

Spec requires unknown constraints to fail evaluation [1], but
OpenPaymentMandate.constraints is a non-discriminated Pydantic union and
ExecutionDate has only optional fields. A constraint object with no known
fields is parsed as an empty ExecutionDate, which enforces nothing.

Not a new vulnerability: same class as issue #339, closed by Google's OSS VRP
as intended behavior.

[1] https://ap2-protocol.org/ap2/agent_authorization/#verification-and-processing-rules
"""

from ap2.sdk.constraints import check_payment_constraints
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.utils import ec_key_to_jwk
from cryptography.hazmat.primitives.asymmetric import ec

CNF = {"jwk": ec_key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key()).model_dump(exclude_none=True)}


def main() -> None:
    mandate = OpenPaymentMandate(vct="mandate.payment.open.1", cnf=CNF, constraints=[{"foo": "bar"}])
    coerced = mandate.constraints[0]
    print(f"{{'foo':'bar'}} parsed as {type(coerced).__name__}: {coerced.model_dump(exclude_none=True)}")

    payment = PaymentMandate(
        transaction_id="tx",
        payee=Merchant(name="EvilShop", id="evil"),
        payment_amount=Amount(amount=99_999_999, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi", type="credit"),
    )
    violations = check_payment_constraints(mandate, payment)
    print(f"{'BLOCKED' if violations else 'ALLOWED':8} $999,999.99 against that constraint")

    try:
        OpenPaymentMandate(vct="mandate.payment.open.1", cnf=CNF, constraints=[{"type": "nope", "x": 1}])
        raise AssertionError("explicit unknown type should not parse")
    except ValueError:
        print("rejected explicit unknown 'type' at parse time")

    assert not violations


if __name__ == "__main__":
    main()

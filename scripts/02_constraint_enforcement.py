"""Constraint evaluation blocks a compromised agent that exceeds the signed limits.

The user signs an open mandate with a per-transaction cap of $50 (an AmountRange,
not a cumulative Budget) and an allowed-payee list. A compromised shopping agent
then tries to settle outside those bounds. The deterministic constraint check
rejects every attempt.

This is the baseline that holds; later scripts show where it does not.
"""

from ap2.sdk.constraints import check_payment_constraints
from ap2.sdk.generated.open_payment_mandate import AllowedPayees, AmountRange, OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.utils import ec_key_to_jwk
from cryptography.hazmat.primitives.asymmetric import ec

CNF = {"jwk": ec_key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key()).model_dump(exclude_none=True)}
TRUSTED = Merchant(name="TrustedShop", id="trusted-1")
EVIL = Merchant(name="EvilShop", id="evil-1")


def payment(payee: Merchant, amount: int, currency: str = "USD") -> PaymentMandate:
    return PaymentMandate(
        transaction_id="tx-1",
        payee=payee,
        payment_amount=Amount(amount=amount, currency=currency),
        payment_instrument=PaymentInstrument(id="pi-1", type="credit"),
    )


def main() -> None:
    authorized = OpenPaymentMandate(
        cnf=CNF,
        constraints=[AmountRange(min=0, max=5000, currency="USD"), AllowedPayees(allowed=[TRUSTED])],
    )

    cases = {
        "$600 at the allowed payee": payment(TRUSTED, 60000),
        "$10 at an unauthorized payee": payment(EVIL, 1000),
        "4000 EUR against a USD cap": payment(TRUSTED, 4000, "EUR"),
        "$40 at the allowed payee": payment(TRUSTED, 4000),
    }
    for label, candidate in cases.items():
        violations = check_payment_constraints(authorized, candidate)
        print(f"{'BLOCKED' if violations else 'ALLOWED':8} {label}")
        for v in violations:
            print(f"         {v}")

    assert check_payment_constraints(authorized, payment(TRUSTED, 60000))
    assert check_payment_constraints(authorized, payment(EVIL, 1000))
    assert check_payment_constraints(authorized, payment(TRUSTED, 4000, "EUR"))
    assert not check_payment_constraints(authorized, payment(TRUSTED, 4000))


if __name__ == "__main__":
    main()

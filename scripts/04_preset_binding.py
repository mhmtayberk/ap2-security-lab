"""Preset fields in an open mandate cannot be changed by the agent.

An open mandate can fix a field outright (a preset) rather than constrain a
range. A preset payee or amount must appear unchanged in the closed mandate, so
the agent cannot swap the merchant or raise the amount.

This also backstops the withheld-disclosure problem: a preset is part of the
mandate content, not a droppable constraint.
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
TRUSTED = Merchant(name="TrustedShop", id="trusted-1")
EVIL = Merchant(name="EvilShop", id="evil-1")


def payment(payee: Merchant, amount: int) -> PaymentMandate:
    return PaymentMandate(
        transaction_id="tx",
        payee=payee,
        payment_amount=Amount(amount=amount, currency="USD"),
        payment_instrument=PaymentInstrument(id="pi", type="credit"),
    )


def main() -> None:
    authorized = OpenPaymentMandate(
        cnf=CNF,
        constraints=[],
        payee=TRUSTED,
        payment_amount=Amount(amount=2500, currency="USD"),
    )

    cases = {
        "different payee": payment(EVIL, 2500),
        "higher amount": payment(TRUSTED, 50000),
        "exact preset": payment(TRUSTED, 2500),
    }
    for label, candidate in cases.items():
        violations = check_payment_constraints(authorized, candidate)
        print(f"{'BLOCKED' if violations else 'ALLOWED':8} {label}")
        for v in violations:
            print(f"         {v}")

    assert check_payment_constraints(authorized, payment(EVIL, 2500))
    assert check_payment_constraints(authorized, payment(TRUSTED, 50000))
    assert not check_payment_constraints(authorized, payment(TRUSTED, 2500))


if __name__ == "__main__":
    main()

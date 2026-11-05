"""Budget constraints assume every currency has 100 minor units.

BudgetEvaluator computes the cap as int(max * 100). For zero-decimal currencies
like JPY, where the amount is already in major units, the cap is inflated 100x
and the limit effectively disappears.

Not a new vulnerability: see issues #362 and #389.

Refs:
  https://github.com/google-agentic-commerce/AP2/issues/362
  https://github.com/google-agentic-commerce/AP2/issues/389
"""

from ap2.sdk.constraints import MandateContext, check_payment_constraints
from ap2.sdk.generated.open_payment_mandate import Budget, OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.utils import ec_key_to_jwk
from cryptography.hazmat.primitives.asymmetric import ec

CNF = {"jwk": ec_key_to_jwk(ec.generate_private_key(ec.SECP256R1()).public_key()).model_dump(exclude_none=True)}


def payment(amount: int, currency: str) -> PaymentMandate:
    return PaymentMandate(
        transaction_id="tx",
        payee=Merchant(name="Shop", id="s"),
        payment_amount=Amount(amount=amount, currency=currency),
        payment_instrument=PaymentInstrument(id="pi", type="credit"),
    )


def check(budget: Budget, candidate: PaymentMandate) -> list[str]:
    mandate = OpenPaymentMandate(cnf=CNF, constraints=[budget])
    return check_payment_constraints(mandate, candidate, mandate_context=MandateContext())


def main() -> None:
    usd_over = check(Budget(max=50, currency="USD"), payment(6000, "USD"))
    print(f"{'BLOCKED' if usd_over else 'ALLOWED':8} USD cap $50, charge $60")

    jpy_over = check(Budget(max=5000, currency="JPY"), payment(400000, "JPY"))
    print(f"{'BLOCKED' if jpy_over else 'ALLOWED':8} JPY cap 5000, charge 400000 (80x)")

    assert usd_over, "USD over-cap should be blocked"
    assert not jpy_over, "JPY cap is inflated 100x, so the over-cap charge passes"


if __name__ == "__main__":
    main()

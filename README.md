# AP2 mandate security lab

A set of small, self-contained scripts that exercise the cryptographic mandate
layer of Google's [Agent Payments Protocol (AP2)](https://ap2-protocol.org/)
against its reference Python SDK. Each script runs an attack or a check against a
signed mandate and asserts the outcome, so the behavior is reproducible rather
than described.

This accompanies the blogpost [Where the AP2 SDK Leaves Security to You](https://ayberk.ninja/where-the-ap2-sdk-leaves-security-to-you).

## What this is, and what it is not

These scripts are a teaching lab, not a vulnerability disclosure. The behaviors
on the "what leaks" side are not new findings: most are tracked in AP2's own
issue tracker, and some were reviewed by Google's OSS VRP and classified as
intended behavior. The value here is seeing the whole picture run in one place,
from an integrator's point of view: which checks the SDK performs for you, and
which ones you have to perform yourself.

Tested against AP2 **v0.2** (released 2026-04-28). Behavior may change in later
versions, so each script links the relevant issue or spec section.

## Setup

Requires Python 3.11+.

The scripts import `ap2`, which is the reference SDK from Google's repository.
You install it by cloning that repo and running `pip install -e .`, which also
pulls in every dependency. Installing `requirements.txt` on its own is **not**
enough: it provides the SDK's dependencies but not the `ap2` package itself, so
the scripts will fail with `ModuleNotFoundError: No module named 'ap2'`.

```sh
# Recommended: a virtual environment so this stays isolated.
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install the AP2 reference SDK (this installs ap2 and all its dependencies).
git clone https://github.com/google-agentic-commerce/AP2.git
cd AP2
git checkout e1ea56d    # the exact commit this lab was written against
pip install -e .
cd ..

# Run any script against that SDK.
python scripts/01_setup_check.py
```

`01_setup_check.py` signs and verifies a mandate. If it prints a verified
payload, the environment is ready.

## Running

Run a single script:

```sh
python scripts/05_signature_integrity.py
```

Or run the whole set; each script asserts its own claim, so a non-zero exit
means a behavior changed against the installed SDK:

```sh
python scripts/run_all.py
```

## The scripts

What holds (the parts you can rely on):

| Script | Shows |
| --- | --- |
| `01_setup_check.py` | Signs and verifies a mandate; confirms the environment. |
| `02_constraint_enforcement.py` | Amount, payee and currency limits block an over-reaching agent. |
| `03_crypto_core.py` | Chain splicing and algorithm confusion are rejected. |
| `04_preset_binding.py` | Preset payee and amount cannot be changed by the agent. |
| `05_signature_integrity.py` | Body tampering and wrong-key signing are rejected. |

What leaks (what you have to handle yourself):

| Script | Shows | Reference |
| --- | --- | --- |
| `06_unknown_constraint.py` | An unknown constraint is coerced to a no-op instead of failing. | [#395](https://github.com/google-agentic-commerce/AP2/issues/395) |
| `07_withheld_disclosure.py` | Withholding a constraint's disclosure silently disables it. | [#339](https://github.com/google-agentic-commerce/AP2/issues/339) |
| `08_intermediate_aud_nonce.py` | aud/nonce are not checked on intermediate delegation hops. | [#319](https://github.com/google-agentic-commerce/AP2/issues/319) |
| `09_checkout_binding.py` | checkout_jwt signature and hash binding are left to the caller. | [#331](https://github.com/google-agentic-commerce/AP2/issues/331) |
| `10_budget_currency.py` | Budget caps assume 100 minor units, so zero-decimal currencies overflow. | [#362](https://github.com/google-agentic-commerce/AP2/issues/362), [#389](https://github.com/google-agentic-commerce/AP2/issues/389) |

## References

- AP2 specification: https://ap2-protocol.org/
- AP2 reference implementation: https://github.com/google-agentic-commerce/AP2
- SD-JWT (RFC 9901): https://datatracker.ietf.org/doc/rfc9901/

## License

MIT. See [LICENSE](LICENSE).

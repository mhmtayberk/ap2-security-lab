"""Run every lab script and report pass/fail.

Each script asserts its own claim, so a non-zero exit means a script's expected
behavior no longer holds against the installed SDK version.
"""

import pathlib
import runpy
import sys

SCRIPTS = sorted(
    p for p in pathlib.Path(__file__).parent.glob("*.py")
    if p.name not in {"run_all.py"}
)


def main() -> int:
    failures = []
    for script in SCRIPTS:
        print(f"\n=== {script.name} ===")
        try:
            runpy.run_path(str(script), run_name="__main__")
        except Exception as exc:
            failures.append((script.name, exc))
            print(f"FAILED: {type(exc).__name__}: {exc}")

    print(f"\n{len(SCRIPTS) - len(failures)}/{len(SCRIPTS)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

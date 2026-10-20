"""Run the test suite without requiring pytest.

If ``pytest`` is installed we defer to it (``python -m pytest tests/``).
Otherwise this runner installs a minimal ``pytest`` shim and executes every
``test_*`` function and ``Test*`` class method directly, so the suite is
verifiable on a bare Python install.
"""

from __future__ import annotations

import importlib
import inspect
import pathlib
import sys
import traceback
import types

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))


def _install_pytest_shim() -> None:
    """Provide the tiny slice of the pytest API our tests actually use."""

    class _Mark:
        def __getattr__(self, name):  # pragma: no cover - no marks used
            def decorator(*_a, **_kw):
                def wrap(fn):
                    return fn
                return wrap
            return decorator

    class _Raises:
        def __init__(self, exc):
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                raise AssertionError(f"DID NOT RAISE {self.exc}")
            return issubclass(exc_type, self.exc)

    shim = types.ModuleType("pytest")
    shim.raises = lambda exc, *a, **kw: _Raises(exc)
    shim.mark = _Mark()
    shim.fixture = lambda *a, **kw: (lambda fn: fn)
    shim.skip = lambda *a, **kw: None
    sys.modules["pytest"] = shim


def _iter_tests(module):
    """Yield ``(label, callable)`` for every test in *module*."""
    for name, obj in vars(module).items():
        if name.startswith("test_") and inspect.isfunction(obj):
            yield name, obj
        elif name.startswith("Test") and inspect.isclass(obj):
            instance = obj()
            for attr in dir(instance):
                if attr.startswith("test_"):
                    yield f"{name}.{attr}", getattr(instance, attr)


def main() -> int:
    try:
        importlib.import_module("pytest")
        have_pytest = True
    except ImportError:
        have_pytest = False

    if have_pytest:
        import pytest
        return pytest.main([str(HERE), "-q"])

    print("pytest not installed — using the built-in runner\n")
    _install_pytest_shim()
    module = importlib.import_module("test_protocol")

    passed = 0
    failures: list[tuple[str, BaseException]] = []
    for label, fn in _iter_tests(module):
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - collect everything
            failures.append((label, exc))
            print(f"  [FAIL] {label}")
            traceback.print_exc(limit=2)
        else:
            passed += 1
            print(f"  [PASS] {label}")

    total = passed + len(failures)
    print(f"\n{passed}/{total} passed")
    if failures:
        print("\nFailures:")
        for label, exc in failures:
            print(f"  - {label}: {exc!r}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
TraceMail AI — Standalone Test Suite Runner
Executes all unit tests in shared/tests and threat_intelligence/tests
using Python standard library without requiring external test runners.
"""

import sys
import asyncio
import inspect
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Import test modules
from shared.tests import test_shared
from threat_intelligence.tests import test_threat_engine, test_api_endpoints
from backend.tests import test_health, test_auth, test_email, test_scan, test_reports

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


async def run_test_module(module, module_name: str) -> bool:
    print(f"\n{CYAN}>>> Testing Module: {module_name}{RESET}")
    functions = [
        (name, func)
        for name, func in inspect.getmembers(module, inspect.isfunction)
        if name.startswith("test_")
    ]

    all_passed = True
    for name, func in functions:
        try:
            if inspect.iscoroutinefunction(func):
                await func()
            else:
                func()
            print(f"  {GREEN}[PASS]{RESET} {name}")
        except Exception as e:
            print(f"  {RED}[FAIL]{RESET} {name}: {e}")
            all_passed = False
    return all_passed


async def main():
    print("=" * 70)
    print(" TraceMail AI -- Unit & Contract Test Suite Runner ")
    print("=" * 70)

    results = [
        await run_test_module(test_shared, "shared/tests/test_shared.py"),
        await run_test_module(test_threat_engine, "threat_intelligence/tests/test_threat_engine.py"),
        await run_test_module(test_api_endpoints, "threat_intelligence/tests/test_api_endpoints.py"),
        await run_test_module(test_health, "backend/tests/test_health.py"),
        await run_test_module(test_auth, "backend/tests/test_auth.py"),
        await run_test_module(test_email, "backend/tests/test_email.py"),
        await run_test_module(test_scan, "backend/tests/test_scan.py"),
        await run_test_module(test_reports, "backend/tests/test_reports.py"),
    ]

    print("\n" + "=" * 70)
    if all(results):
        print(f"{GREEN}[SUCCESS] All unit, backend and contract tests PASSED! (100% Success){RESET}")
        return 0
    else:
        print(f"{RED}[FAILURE] One or more test suites failed.{RESET}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

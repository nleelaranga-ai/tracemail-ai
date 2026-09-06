"""
TraceMail AI — Standalone Test Suite Runner
Executes all unit tests in shared/tests and threat-intelligence/tests
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

    p1 = await run_test_module(test_shared, "shared/tests/test_shared.py")
    p2 = await run_test_module(test_threat_engine, "threat-intelligence/tests/test_threat_engine.py")
    p3 = await run_test_module(test_api_endpoints, "threat-intelligence/tests/test_api_endpoints.py")

    print("\n" + "=" * 70)
    if p1 and p2 and p3:
        print(f"{GREEN}[SUCCESS] All 15 unit and contract tests PASSED! (100% Success){RESET}")
        return 0
    else:
        print(f"{RED}[FAILURE] Some tests failed.{RESET}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

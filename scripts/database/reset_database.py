"""
TraceMail AI — Database Reset Utility
Safely clears fixture records and resets mock and local database state for test runs.
"""

import sys
import shutil
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def reset_local_state():
    print("[-] Resetting local cache and fixture cache...")
    if FIXTURES_DIR.exists():
        for file in FIXTURES_DIR.glob("*.eml"):
            file.unlink()
        manifest = FIXTURES_DIR / "sample_manifest.json"
        if manifest.exists():
            manifest.unlink()
        print("[OK] Removed fixture files.")
    print("[SUCCESS] Local test fixtures reset. Run seed_database.py to regenerate.")


if __name__ == "__main__":
    reset_local_state()

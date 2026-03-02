#!/usr/bin/env python3
"""
Test runner that works around the ``py/`` namespace conflict.

pytest internally does ``import py`` which collides with the
workspace ``py/`` package.  This script:
  1. Removes the workspace from sys.path
  2. Imports pytest (resolves to pylib from site-packages)
  3. Saves pylib's ``py`` module reference
  4. Restores workspace to sys.path and lets our ``py/`` take over
  5. Patches sys.modules so both pylib and our package coexist

Usage:
    cd anchor-dex
    python run_tests.py [-v] [--tb=short] [py/tests/test_production.py]
"""
import os
import sys

project_root = os.path.dirname(os.path.abspath(__file__))
cwd_norm = os.path.normcase(os.path.abspath(os.getcwd()))
root_norm = os.path.normcase(project_root)

# Step 1: Temporarily remove workspace root from sys.path
original_path = list(sys.path)
sys.path = [p for p in sys.path
            if os.path.normcase(os.path.abspath(p)) not in (root_norm, cwd_norm)]

# Step 2: Import pytest (uses site-packages pylib)
import pytest  # noqa: E402

# Step 3: Save pylib's py module
import py as _pylib  # noqa: E402
_pylib_ref = _pylib

# Step 4: Restore sys.path
sys.path = original_path

# Step 5: Force-reimport our workspace py package
del sys.modules["py"]
# Also clear any py.* submodules from pylib
for key in list(sys.modules):
    if key.startswith("py.") and not key.startswith("py.tests"):
        # Keep only if it's from our workspace, not pylib
        pass  # will be re-imported on demand

import py  # noqa: E402, F811  -- this now resolves to our workspace package

# Step 6: Ensure pylib is still accessible for pytest internals
# pytest uses py.path.local via _pytest.compat.LEGACY_PATH
sys.modules["py.path"] = _pylib_ref.path

if __name__ == "__main__":
    args = sys.argv[1:] or ["-v", "--tb=short", "py/tests/"]
    sys.exit(pytest.main(args))

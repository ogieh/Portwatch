"""
Backend test entry point for PortWatch Pro.

The suite lives in backend/tests/ (pytest). This wrapper keeps the documented
command working and prints a coverage summary when the `coverage` package is
available.

Run:  cd backend && python test_backend.py
  or: cd backend && python -m pytest tests -q
"""

import os
import subprocess
import sys

HERE = os.path.abspath(os.path.dirname(__file__))


def main():
    env = dict(os.environ, PORTWATCH_SIMULATE="1", PORTWATCH_SCHEDULER="0",
               PORTWATCH_NO_DEFAULT_APP="1")
    args = sys.argv[1:] or ["-q"]
    try:
        import coverage  # noqa: F401
        cmd = [sys.executable, "-m", "coverage", "run", "--source=.",
               "--omit=tests/*,migrations/*,seed.py,test_backend.py",
               "-m", "pytest", "tests", "-p", "no:cacheprovider", *args]
        rc = subprocess.call(cmd, cwd=HERE, env=env)
        if rc == 0:
            subprocess.call([sys.executable, "-m", "coverage", "report", "-m",
                             "--skip-covered"], cwd=HERE, env=env)
    except ImportError:
        cmd = [sys.executable, "-m", "pytest", "tests", "-p", "no:cacheprovider", *args]
        rc = subprocess.call(cmd, cwd=HERE, env=env)
    sys.exit(rc)


if __name__ == "__main__":
    main()

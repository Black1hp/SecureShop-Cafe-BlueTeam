SecureShop Cafe - Partial Typing Enrollment Login Fix

Problem: A user with 1-4 typing samples received "Five samples required" during login.
Cause: Login tried to construct a completed typing profile whenever any row existed.
Fix: Compare timing and produce anomaly events only when at least 5 trusted samples are saved.
Existing samples are preserved; no database reset is needed.

Installation:
1. Stop the server.
2. Back up your current app.py and tests/test_app.py.
3. Copy app.py into the project folder and tests/test_app.py into tests/.
4. Do not replace secureshop.db or .venv.
5. Run: python -m unittest discover -s tests -v
6. Run: python app.py

Tested: 33 tests passed using a separate temporary testing database.

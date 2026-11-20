# SecureShop Cafe - review of uploaded ZIP (20 Nov 2026)

## Verdict
The uploaded `SecureShop_Cafe_v2(1).zip` is **not ready for Blue Team submission**. The main code is older than the test suite and documentation.

## Reproducible results
- Uploaded ZIP tested in an isolated directory with `python -m unittest discover -s tests -v`: **23 tests, 4 failures, 5 errors, 14 successes**.
- This reviewed clean build (based on the complete Blue Team build) tested in an isolated directory with the same command: **32 tests, OK**.
- Passing automated tests do not mean the complete real-device/passkey flow or Red Team penetration test has been completed.

## Critical findings in uploaded ZIP
1. `app.py` (~57 KB) does not implement `/security`, `/admin/audit`, passkey endpoints, or the new audit/behavior/passkey schema expected by the included tests. Routes return HTTP 404 or queries fail.
2. `passkey_security.py` and `security.js` were placed under `docs/`, although the application/tests expect them at project root and `/static/security.js`.
3. `requirements.txt` was placed under `docs/` rather than project root, so documented installation command fails.
4. Uploaded ZIP contains `secureshop.db` with 2 user records, 2 order records, 5 session rows, 2 users with MFA enabled, and a pending MFA enrollment. Keep this database private: it contains authentication material and personal data. It also contains `.venv` and backups. Never distribute these with submission code.
5. `docs/BLUE_TEAM_REVIEW_AR.md` and the test plan claim 32 tests and completed features, but they do not match the uploaded application's actual implementation. The claim is only verified for the separate complete build.

## What is included in this clean build
- Source code, root-level dependencies, browser script, tests and docs. No database, sessions, secrets, backups or `.venv`.
- Existing local `secureshop.db` should be retained separately and backed up before updating code; `init_db()` migrates/creates new tables in the existing database.
- Update by replacing code files from this folder into the existing local application after a full backup. Do not replace the user's database or virtual environment.

## Remaining manual/academic work
- Run `python -m pip install -r requirements.txt` and `python -m unittest discover -s tests -v` on the Mac after installing code.
- Test passkey enrollment and assertion on a real device; test required protections with local browser flows.
- Collect naive-vs-secure evidence, SAST/DAST outputs, Red Team findings/retests, Git commit history and final report.
- Browser geolocation and timing signals are not trustworthy authentication factors. Location/time risk policy is a demonstration, not production geofencing.

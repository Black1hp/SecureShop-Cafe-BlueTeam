# Attack evidence tracker — FILL FROM ACTUAL TESTS ONLY

Do not mark entries PASS based on the existence of code or based only on unit tests. Capture an authorized request/reproduction and its actual response. Redact secrets.

| Test ID | Topic | Vulnerable isolated demo: observed? | SecureShop action | Actual HTTP / UI result | Evidence screenshot / command | Pass/Fail | Reviewer |
|---|---|---|---|---|---|---|---|
| SEC-01 | Price integrity price tampering | NOT TESTED | Alter client-submitted price during checkout | NOT TESTED | | NOT TESTED | |
| SEC-02 | Coupon reuse protection coupon reuse | NOT TESTED | Reuse one-time coupon | NOT TESTED | | NOT TESTED | |
| SEC-03 | Input validation exceptional inputs | NOT TESTED | Oversize/invalid fields | NOT TESTED | | NOT TESTED | |
| SEC-04 | Checkout workflow validation checkout workflow | NOT TESTED | Empty cart / low credit | NOT TESTED | | NOT TESTED | |
| SEC-05 | MFA verification broken 2FA | NOT TESTED | Attempt cross-user OTP | NOT TESTED | | NOT TESTED | |
| SEC-06 | Typing behavior anomaly detection | NOT TESTED | Enroll + unusual typing | NOT TESTED | | NOT TESTED | |
| SEC-07 | Location risk & hour | NOT TESTED | Test boundary cases | NOT TESTED | | NOT TESTED | |
| SEC-08 | Location and time policy WebAuthn | NOT TESTED | Valid passkey then invalid challenge | NOT TESTED | | NOT TESTED | |
| SEC-09 | SQL injection | NOT TESTED | Query with unexpected search input | NOT TESTED | | NOT TESTED | |
| SEC-10 | Stored/reflected XSS | NOT TESTED | Escaped text / CSP | NOT TESTED | | NOT TESTED | |
| SEC-11 | CSRF | NOT TESTED | Missing token POST | NOT TESTED | | NOT TESTED | |
| SEC-12 | IDOR / role bypass | NOT TESTED | User asks for another order/admin | NOT TESTED | | NOT TESTED | |

Attach: timestamp, isolated target (localhost), method/path (no secrets), sanitized evidence, expected/actual, fix/commit reference if failing.

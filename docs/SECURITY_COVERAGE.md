# SecureShop Café — Security Coverage Matrix, final build snapshot

**Status definition:** Tested = automated regression exists and passed locally. Manual pending = browser/device step needs final one-pass test. No row is proof of Red Team testing or an insecure comparison.

| Topic | Threat / root cause | Code defense | Local automated evidence | Remaining work |
|---|---|---|---|---|
| Server-authoritative pricing | Client tampers price | app.py checkout DB authoritative price | `test_price_is_always_from_database` | Manual screenshot + naive comparison |
| Coupon reuse protection | Coupon reused | DB unique coupon_uses + server transaction | `test_coupon_single_use_and_no_negative_quantity` | concurrent coupon test |
| Exceptional input handling | giant or ambiguous fields | strict lengths, reject duplicates | `test_exceptional_email_rejected_not_truncated` | fuzz more forms |
| Checkout workflow protection | skip cart/credit | atomic checkout and validation | `test_checkout_bypass_blocked_and_no_side_effect` | concurrency test |
| Cross-account MFA | change verify user | pending server-side MFA user id | `test_mfa_binds_second_factor_to_authenticated_user` | manual wrong OTP screenshot |
| Password protection | weak/plaintext hashes | Argon2id | `test_argon2id_password_storage` | secrets management review |
| TOTP replay | reuse accepted OTP | persistent last-step + rate limit | MFA tests | recovery procedure missing |
| Typing behavior anomaly | abnormal typing | 5 samples, z-score > 3, audit flag | `BehavioralTests`, `test_security_page_protected_and_behaviour_five_enrollments` | manual live capture; spoofable browser signals |
| Location and time policy distance | >50km travel | Haversine check of supplied location | `GeoTimeTests` | only browser-reported coordinates; manual |
| Time risk | 22:00–07:59 | Cairo server time gate | `test_hour_window_boundaries` | optional enforcement; manual |
| Passkey validation | fake/challenge replay | ES256 signature, RP/origin/challenge/flags/counter | `WebAuthnTests` and HTTP passkey tests | real hardware test; broader authenticator support |
| User/admin authz | role escalation | admin checks and owned orders | `test_idor_and_admin_denied` | mutation fuzz |
| CSRF | forged mutating POST | per-session CSRF | `test_csrf_missing_blocks_writes` | browser test |
| XSS | HTML injection | output escaping + CSP | `test_xss_escaped_and_no_html_injection` | expanded suite |
| SQL injection | SQL in search | bound SQL placeholders | `test_sql_query_input_does_not_expand_search` | static analysis pending |
| Audit | no trace | event allowlist and admin audit page | audit tests | retention / tamper-proof design |
| Threat model | unmodeled threats | `SECURITY_DESIGN_BLUE_TEAM.md` | reviewed document | instructor/team review |
| DAST/SAST / Red Team | missing independent testing | isolated test suite + evidence templates | 35 tests local | external tools and Red Team evidence NOT DONE |


## Evidence revision
- The 35-test isolated suite now covers explicit HTTP passkey accept/deny for signature and location/time, plus 49/51 km approximate boundary cases.
- `localhost` is the only browser WebAuthn RP/Origin for the packaged build. `127.0.0.1` remains a loopback bind address only.
- Manual Mac evidence (user-reported) is summarized in `TEST_RESULTS.md`; Red Team, naive comparison, SAST/DAST remain Pending.

# SecureShop Café — Security Coverage Matrix

**Status definition:** Tested = automated regression exists and passed locally. HTTP-evidence = exercised against running servers by `scripts/security_compare.py` (transcripts in `evidence/`). Manual pending = browser/device step still needs a human pass. No row is proof of independent Red Team testing.

Updated for the `feature/secure-shop-hardening` build (41 tests + 10/10 HTTP comparisons).

| Topic | Threat / root cause | Code defense | Local automated evidence | Remaining work |
|---|---|---|---|---|
| Server-authoritative pricing | Client tampers price | `app.py /checkout` reads `products.price_cents`; client totals ignored | `test_price_is_always_from_database`; HTTP `price-tampering` | — |
| Checkout replay | Double-submit debits twice | `orders.idempotency_key` UNIQUE(user_id,key); replay returns same receipt | `test_checkout_replay_returns_same_order_no_second_debit`; HTTP `checkout-replay` | true parallel race test |
| Coupon reuse | Coupon reused | `coupon_uses` PK inside checkout transaction | `test_coupon_single_use_and_no_negative_quantity`; HTTP `coupon-reuse` | concurrent coupon test |
| Newsletter harvesting | Anyone mints coupons for any email | Code never in HTTP response; delivered to mailbox (dev console); uniform reply | `test_newsletter_never_displays_coupon_to_submitter`; HTTP `newsletter-harvest` | — |
| Account enumeration (register) | 409 reveals taken email | Identical page + status for new and taken emails | `test_registration_response_does_not_reveal_existing_email` | — |
| Account enumeration (login timing) | Unknown email skips Argon2 | `DUMMY_PASSWORD_HASH` verified for unknown users | `test_unknown_email_login_still_runs_argon2` | — |
| Exceptional input | Giant/ambiguous fields | Strict lengths, duplicate fields rejected, 16 KB body cap | `test_exceptional_email_rejected_not_truncated` | more fuzz forms |
| Checkout workflow | Skip cart/credit checks | Atomic `BEGIN IMMEDIATE` checkout; stock/credit/active re-checked | `test_checkout_bypass_blocked_and_no_side_effect` | — |
| Negative quantity | Negative qty in cart | `positive_int` + CHECK(qty>0) | `test_coupon_single_use_and_no_negative_quantity`; HTTP `negative-qty` | — |
| Cross-account MFA | Attacker picks MFA user | `pending_user_id` bound to session row | `test_mfa_binds_second_factor_to_authenticated_user` | — |
| TOTP replay | OTP reuse | Persistent `totp_last_step` + 5/10min budget | MFA tests | — |
| MFA recovery | Lost authenticator lockout | 8 hashed single-use recovery codes; password-gated regeneration | `test_recovery_code_single_use_login`, `test_recovery_regeneration_replaces_old_set` | — |
| Password storage | Weak/plaintext hashes | Argon2id (t=3, m=64 MiB, p=2) | `test_argon2id_password_storage`; HTTP `admin-no-role` contrast | — |
| Session fixation/quality | Predictable/stealable sid | 256-bit token, SHA-256 stored, rotation on login/logout, HttpOnly+SameSite | session tests; HTTP `session-token` | — |
| Brute force | Password spraying | `login_attempts` 5/10min per IP+email; MFA 5/10min per user | login tests | per-email distributed limit untested |
| Typing behavior anomaly | Abnormal typing | 5 samples, z-score>3 → `behavior_anomaly` audit (signal only) | `BehavioralTests`, `test_security_page_protected_and_behaviour_five_enrollments` | spoofable browser signal — documented |
| Location/time policy | Impossible travel / off-hours | Haversine ≤50 km + Cairo 08:00–22:00 gate (optional enforcement) | `GeoTimeTests`, HTTP passkey policy tests | browser coords forgeable — documented |
| Passkey validation | Forged/replayed credential | ES256 verify: origin, RP hash, UP+UV flags, signature, sign count, one-time challenge | `WebAuthnTests`, HTTP passkey tests | real hardware pass pending |
| Authorization/IDOR | Other user's order, /admin | Owner-scoped queries + `must_admin` on every admin route | `test_idor_and_admin_denied`; HTTP `idor-order`, `admin-no-role` | — |
| CSRF | Forged mutating POST | Per-session CSRF token, `hmac.compare_digest`, POSTs require session cookie | `test_csrf_missing_blocks_writes`; HTTP `csrf-profile` | — |
| XSS | HTML/JS injection | `html.escape` on all user output + CSP `script-src 'self'` | `test_xss_escaped_and_no_html_injection` | — |
| SQL injection | Search/query injection | Bound parameters; LIKE wildcards escaped | `test_sql_query_input_does_not_expand_search`; HTTP `sqli-search` | — |
| Security headers | Clickjacking/sniffing | nosniff, XFO DENY, no-referrer, no-store, CSP; HSTS under HTTPS | header assertions in tests | — |
| Audit | Repudiation, silent failures | Allowlisted events, actor+target, no secrets column | audit tests | admin can edit local SQLite — documented |
| Error handling | Stack/secret leakage | Generic error pages, no debug output, `sys_version=''` | error-path tests | — |

## Evidence revision
- 41-test suite green on the hardening branch (`python -m unittest discover -s tests`).
- `scripts/security_compare.py` → **10/10 scenarios: naive vulnerable, secure defended**; transcripts in `evidence/compare_summary.txt` + `evidence/compare_transcripts.json`.
- `localhost` is the only WebAuthn RP/Origin. `127.0.0.1` is the loopback bind.
- Independent Red Team findings still require the student team to run and document their own authorized pass (`docs/RED_TEAM_FINDINGS_TEMPLATE.md`).

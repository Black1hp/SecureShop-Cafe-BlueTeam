# CET431 — SecureShop Café: Naive vs Secure Evidence

**Prepared:** 21 November 2026  
**Scope:** Blue Team self-testing and isolated educational comparisons; **not** Red Team penetration testing.

## How to interpret the evidence

This package contains **two distinct kinds of proof**:

1. **NAIVE-CONCEPT DEMO** (`test_naive_concepts.py`, `naive_demo.log`): a deliberately insecure *in-memory teaching model* built specifically for this evidence. It is **not** an earlier version of the SecureShop Café website and exposes **no web service**. Each passing test demonstrates a conceptual unsafe behavior (e.g., trusting a client-supplied price). A passing test here **means the toy model exhibits the vulnerability**; it does not mean the model is secure.
2. **SECURE APP TEST** (`secure_app_tests.log`): 35 tests run against the actual SecureShop Café source supplied in `SecureShop_Cafe_BlueTeam_Documentation_Ready.zip`. The HTTP integration tests launch a loopback-only server on an ephemeral port and use a **temporary SQLite database**. The user's Mac database, credentials, and passkeys were not used or modified.

**Actual runs in this environment:** 12/12 naive-concept demonstrations passed; 35/35 secure application tests passed. See the raw logs.

## Attack scenario and outcome matrix

| ID | Topic / threat | Naive conceptual model — observed | Actual SecureShop Café test(s) — observed | Evidence strength |
|---|---|---|---|---|
| N01 | Price tampering | Client-supplied one-cent price accepted despite catalog 2499 cents. | `test_price_is_always_from_database`: HTTP request submits `price_cents=1`; order total stays 2499 cents. | **HTTP secure; toy naive** |
| N02 | Coupon replay | Same coupon yields discount twice because no usage record. | `test_coupon_single_use_and_no_negative_quantity`: second checkout with same coupon returns 400. | **HTTP secure; toy naive** |
| N03 | Negative quantity | Negative qty produces negative cart total. | `test_coupon_single_use_and_no_negative_quantity`: `qty=-1` returns 400. | **HTTP secure; toy naive** |
| N04 | CSRF | POST accepted based only on authentication, no CSRF. | `test_csrf_missing_blocks_writes`: POST `/newsletter` without token returns 403. | **HTTP secure; toy naive** |
| N05 | Admin authorization | Any logged-in user accepted as administrator. | `test_idor_and_admin_denied`: ordinary user GET `/admin` returns 403; `test_audit_log_only_visible_to_admin` checks audit route. | **HTTP secure; toy naive** |
| N06 | IDOR | Order retrieved by numeric ID alone, ignoring owner. | `test_idor_and_admin_denied`: second user GET `/order/<id>` returns 404. | **HTTP secure; toy naive** |
| N07 | Reflected/stored HTML injection | User-controlled HTML embedded raw. | `test_xss_escaped_and_no_html_injection`: injected `<script>` is escaped and CSP is set. | **HTTP secure; toy naive** |
| N08 | SQL injection root cause | User search concatenated into SQL string; no query is executed by toy. | `test_sql_query_input_does_not_expand_search`: request with SQL-like input does not expand product results. | **HTTP secure (behavioral); toy construction** |
| N09 | Cross-account MFA | Client-supplied account chooses which TOTP secret to verify. | `test_mfa_binds_second_factor_to_authenticated_user`: wrong TOTP rejected; account remains server-session bound, replay rejected. | **HTTP secure; toy naive** |
| N10 | WebAuthn challenge replay | Stateless comparison accepts the same challenge twice. | `test_passkey_register_and_assertion_over_http`: first valid ES256 assertion approved, replay returns 403; `test_challenge_replay_and_wrong_operation` covers primitives. | **HTTP secure; toy naive** |
| N11 | Location & time risk | Any password-authenticated session accepted regardless of location/hour. | `test_passkey_signature_and_location_time_policy_denials_over_http`: location and time each return 403; valid policy returns 200. Also `GeoTimeTests`. | **HTTP secure; toy naive** |
| N12 | Behavioral anomaly monitoring | No baseline/anomaly detection exists. | `test_security_page_protected_and_behaviour_five_enrollments`: five enrollment samples enforced, extra sample 409, anomaly event logged. | **HTTP secure; toy naive** |

### Additional secure-app-only coverage

The 35-test suite also checks: registration confirmation, successful cart checkout with balance debit/order history, password hashing with Argon2id, forced workflow bypass, oversized email rejection, MFA enrollment/re-authentication, audit event allowlisting, Passkey enrollment requiring authenticated password, WebAuthn RP ID and user verification, invalid CBOR, signed assertions and wrong signatures, optional enforced Passkey login, distance boundary at around 50 km, and Cairo time-window boundaries. These tests strengthen security coverage but **do not add independent naive-site attack reproductions**.

### Browser evidence from the Mac

The earlier Blue Team documentation ZIP includes existing screenshots: `evidence/E01_passkey_count_4.png`, `E02_passkey_location_denial.png`, `E03_admin_audit_log.png`, `E04_passkey_saved.png`. They document a live browser experience, including `passkey_verified` followed by `risk_location_denied` in the admin audit log. They should **not** be relabeled as screenshots of the isolated naive toy implementation.

## Reproduce offline (macOS)

Run these commands from the **evidence folder**:

```bash
python3 -m unittest -v test_naive_concepts
```

For the secure app (from the existing SecureShop Café project folder with `.venv` activated):

```bash
cd "$HOME/Desktop/SecureShop_Cafe_v2 2"
source .venv/bin/activate
python -m unittest discover -s tests -v
```

Expected when using the same app version: `Ran 12 tests ... OK` for the conceptual demo and `Ran 35 tests ... OK` for the secure app. Results depend on code version and dependencies; re-run after any changes.

## Remaining evidence / caveats (must be disclosed at submission)

- **Full naive WEBSITE comparison pending:** This teaching file is a *model of insecure patterns*, not a running naive SecureShop implementation. If the instructor requires HTTP requests/screenshots against an actual naive web version for each topic, that evidence still has to be produced on a strictly isolated local teaching site.
- **SQLi**: the insecure example only constructs a dangerous SQL string. It deliberately does **not** run arbitrary injected SQL. The secure side tests observable search behavior; it is not an exhaustive database injection assessment.
- **Concurrency**: simultaneous coupon redemption, checkout stock/balance races, and broad mutation fuzzing are not separately proven in this comparison.
- **Device trust**: browser-reported geolocation and timing are untrusted risk signals, not cryptographic identity proof. Behavioral monitoring logs anomaly; logging alone does not prove login is blocked.
- **Enforcement policy**: Passkey location/time gate may be optional by default; passing isolated policy tests does not mean it is always enforced for login.
- **Email confirmation**: the developer-mode email confirmation link printed in terminal does not prove possession of a real inbox.
- **Git history**: only authentic Git commits count; screenshots/test runs are not substitutes for contributions from all required members.
- **Red Team results**: excluded from this package; any future valid findings must be fixed and re-tested by the Blue Team.

## Safe evidence handling

No real credentials, passkey private keys, secret OTP seeds, session cookies, or personal database files are included. Run any further tests only on team-owned, authorized local systems. Keep the final GitHub repository private until the instructor authorizes publication.

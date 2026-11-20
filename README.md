# SecureShop Café — CET431 Blue Team build

Local educational site with customer/admin e-commerce flows, TOTP QR-based MFA, server-side security protections, audit logging, typing anomaly model, and limited real ES256 WebAuthn registration/verification.

## Install (Mac)
```sh
cd ~/Desktop/SecureShop_Cafe_v2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python app.py
```
Visit `http://localhost:8000` for all browser tests. Passkeys use RP ID `localhost` and verify origin `http://localhost:8000`; opening the site at `127.0.0.1` instead will not work for passkeys. The server still binds to loopback.

Existing Mac users: DO NOT replace `secureshop.db` or `.venv`. Back them up first. `init_db` migrates tables non-destructively. Avoid restoring from old ZIP without checking account DB contents.

Admin creation on an **empty database only** (do not share passwords in reports):
```sh
export SECURESHOP_ADMIN_EMAIL='admin@example.test'
read -s 'SECURESHOP_ADMIN_PASSWORD?Admin password: '; echo
export SECURESHOP_ADMIN_PASSWORD
python app.py
```
Existing Admin password is NOT overwritten by the environment variable. To create a normal user, use `/register` and the terminal-only development confirmation link. TOTP requires Google/Microsoft Authenticator.

## Routes / architecture
- `/` catalogue, `/product/<id>` detail, `/cart`, `/checkout`, `/orders`, `/order/<id>` purchase flow.
- `/register`, `/confirm`, `/login`, `/mfa`, `/mfa/setup`, `/account` customer auth.
- `/admin` products/users/coupons; `/admin/audit` allowlisted events.
- `/security` security dashboard, `/security/behavior` five samples, passkey register and risk check.
- `app.py` HTTP routes, SQLite schema/business rules/CSRF/session control; `auth_security.py` Argon2id/TOTP; `blue_security.py` behavior and place/time math; `passkey_security.py` limited ES256 WebAuthn verification; `security.js` client-only browser APIs; `tests/` integration and unit tests.
- `SECURESHOP_DB` points to custom SQLite path. Defaults to adjacent `secureshop.db`. Auto-new DB when none exists.

## Optional risk policy login enforcement
`SECURESHOP_RISK_GATE_ENFORCE=1 python app.py` makes enrolled-passkey users pass additional WebAuthn+location/time gate before login completes. WARNING: blocks outside Cairo 08:00–22:00 or outside demo 50km radius, when geolocation unavailable, or device unsupported. Leave OFF for standard demo until the dedicated test. Browser geolocation is forgeable and not proof of identity.

## Safety and limits
- Localhost only. No real payment gateway or trusted email sending.
- WebAuthn supports ES256/P-256, fmt none, user presence/verification flags and one-time challenge; not all passkeys/platforms supported. Production deployments should use maintained WebAuthn library with full protocol verification, HTTPS, key/recovery policy and a trusted external security review.
- Behavioral timings are provided by client and spoofable; used for audit flag, not independent authentication. No raw keystrokes retained.
- SAST/DAST, Red Team findings, naïve comparison and manual evidence are unfinished until run and documented by team.
- Read `docs/FINAL_ONE_PASS_TEST_AR.md` for one-shot Mac user/admin/security test. Read `docs/SECURITY_DESIGN_BLUE_TEAM.md` for threat model/matrix and documented limitations.

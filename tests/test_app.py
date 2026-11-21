import contextlib
import io
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path

TEMP = tempfile.TemporaryDirectory()
os.environ['SECURESHOP_DB'] = str(Path(TEMP.name) / 'testing.sqlite')
import app
from auth_security import new_totp_secret, totp_at, verify_password
import time


class WebTestHelpers:
    @classmethod
    def setUpClass(cls):
        app.init_db()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), app.App)
        cls.base = 'http://127.0.0.1:' + str(cls.server.server_address[1])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        TEMP.cleanup()

    def setUp(self):
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
        self.get('/')

    def request(self, method, path, data=None, opener=None):
        req = urllib.request.Request(self.base + path, method=method,
               data=urllib.parse.urlencode(data).encode() if data is not None else None)
        if data is not None:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        try:
            r = (opener or self.client).open(req)
            return r.status, r.read().decode('utf-8'),r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8'),e.headers

    def get(self, path, opener=None):
        return self.request('GET',path,opener=opener)

    def csrf(self, path='/login'):
        text = self.get(path)[1]
        return re.search(r'name="csrf" value="([^"]+)"',text).group(1)

    def post(self, path, data, csrf=True):
        if csrf: data = dict(data,csrf=self.csrf('/register' if path == '/register' else '/login'))
        return self.request('POST',path,data)

    def create_user(self, email='alice@example.test', pw='a good password 123'):
        # Create unconfirmed account directly for deterministic test fixture,
        # then verify user-facing auth / authorization via HTTP.
        with app.db() as c:
            c.execute('INSERT INTO users(email,display_name,password_hash,confirmed) VALUES(?,?,?,1)',
                      (email,'Alice',app.hash_password(pw)))
        return email,pw

    def login(self,email,pw):
        return self.post('/login',{'email':email,'password':pw})

class SecureShopTests(WebTestHelpers, unittest.TestCase):
    def test_csrf_missing_blocks_writes(self):
        status,_,_ = self.request('POST','/newsletter',{'email':'a@example.test'})
        self.assertEqual(status,403)

    def test_registration_and_confirmation_required(self):
        email='registration@example.test'
        status,body,_=self.post('/register',{'name':'Registration','email':email,'password':'a long test password'})
        self.assertEqual(status,200)
        self.assertIn('confirmation link',body)
        status,_,_=self.login(email,'a long test password')
        self.assertEqual(status,401)
        with app.db() as c:
            self.assertEqual(c.execute('SELECT confirmed FROM users WHERE email=?',(email,)).fetchone()['confirmed'],0)

    def test_login_cart_and_checkout(self):
        email,pw=self.create_user('checkout@example.test')
        status,_,_=self.login(email,pw)
        self.assertEqual(status,200)
        status,_,_=self.post('/cart/add',{'product_id':'1','qty':'2'})
        self.assertEqual(status,200)
        status,body,_=self.post('/checkout',{'coupon':''})
        self.assertEqual(status,200)
        self.assertIn('Order confirmed',body)
        with app.db() as c:
            u=c.execute('SELECT credit_cents FROM users WHERE email=?',(email,)).fetchone()
            self.assertEqual(u['credit_cents'],10000-4998)
            self.assertEqual(c.execute('SELECT count(*) AS n FROM orders WHERE user_id=(SELECT id FROM users WHERE email=?)',(email,)).fetchone()['n'],1)
        self.assertIn('Order #',self.get('/orders')[1])

    def test_idor_and_admin_denied(self):
        first,pw=self.create_user('first@example.test')
        self.login(first,pw)
        self.post('/cart/add',{'product_id':'2','qty':'1'})
        self.post('/checkout',{'coupon':''})
        with app.db() as c:
            oid=c.execute('SELECT id FROM orders WHERE user_id=(SELECT id FROM users WHERE email=?)',(first,)).fetchone()['id']
        status,_,_=self.get('/admin')
        self.assertEqual(status,403)
        self.post('/logout',{})
        second,pw2=self.create_user('second@example.test')
        self.login(second,pw2)
        status,_,_=self.get('/order/'+str(oid))
        self.assertEqual(status,404)

    def test_xss_escaped_and_no_html_injection(self):
        email,pw=self.create_user('xss@example.test')
        self.login(email,pw)
        payload='<script>alert(1)</script>'
        self.post('/account',{'name':payload})
        status,body,headers=self.get('/account')
        self.assertEqual(status,200)
        self.assertNotIn(payload,body)
        self.assertIn('&lt;script&gt;',body)
        self.assertIn('Content-Security-Policy',headers)

    def test_coupon_single_use_and_no_negative_quantity(self):
        email,pw=self.create_user('coupon@example.test')
        self.login(email,pw)
        with app.db() as c:
            c.execute("INSERT INTO coupons(code,percent_off) VALUES('TEST10',10)")
        status,_,_=self.post('/cart/add',{'product_id':'1','qty':'-1'})
        self.assertEqual(status,400)
        self.post('/cart/add',{'product_id':'1','qty':'1'})
        status,body,_=self.post('/checkout',{'coupon':'TEST10'})
        self.assertEqual(status,200)
        self.assertIn('$22.50',body)
        self.post('/cart/add',{'product_id':'1','qty':'1'})
        status,body,_=self.post('/checkout',{'coupon':'TEST10'})
        self.assertEqual(status,400)
        self.assertIn('already used',body)


    def test_argon2id_password_storage(self):
        email,pw=self.create_user('argon2@example.test')
        with app.db() as c:
            user=c.execute('SELECT password_hash FROM users WHERE email=?',(email,)).fetchone()
        self.assertTrue(user['password_hash'].startswith('$argon2id$'))
        self.assertTrue(verify_password(pw,user['password_hash']))
        self.assertFalse(verify_password('incorrect',user['password_hash']))

    def test_price_is_always_from_database(self):
        email,pw=self.create_user('price@example.test')
        self.login(email,pw)
        status,_,_=self.post('/cart/add',{'product_id':'1','qty':'1','price_cents':'1'})
        self.assertEqual(status,200)
        status,_,_=self.post('/checkout',{'coupon':'','total_cents':'1','price_cents':'1'})
        self.assertEqual(status,200)
        with app.db() as c:
            total=c.execute('SELECT total_cents FROM orders WHERE user_id=(SELECT id FROM users WHERE email=?)',(email,)).fetchone()['total_cents']
        self.assertEqual(total,2499)

    def test_checkout_bypass_blocked_and_no_side_effect(self):
        email,pw=self.create_user('workflow@example.test')
        self.login(email,pw)
        status,_,_=self.post('/checkout',{'coupon':'','paid':'1','order_status':'confirmed'})
        self.assertEqual(status,400)
        with app.db() as c:
            user=c.execute('SELECT id,credit_cents FROM users WHERE email=?',(email,)).fetchone()
            self.assertEqual(c.execute('SELECT COUNT(*) AS n FROM orders WHERE user_id=?',(user['id'],)).fetchone()['n'],0)
            self.assertEqual(user['credit_cents'],10000)

    def test_registration_response_does_not_reveal_existing_email(self):
        email,pw=self.create_user('taken@example.test')
        status,body,_=self.post('/register',{'name':'Someone Else','email':email,'password':'another long password'})
        self.assertEqual(status,200)
        self.assertIn('If the email can be registered',body)
        self.assertNotIn('cannot be registered',body)
        with app.db() as c:
            uid=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()['id']
            self.assertEqual(c.execute('SELECT COUNT(*) AS n FROM confirmations WHERE user_id=?',(uid,)).fetchone()['n'],0)

    def test_unknown_email_login_still_runs_argon2(self):
        from unittest.mock import patch
        with patch.object(app,'verify_password',return_value=False) as check:
            status,_,_=self.login('no.such.user@example.test','whatever password')
        self.assertEqual(status,401)
        check.assert_called_once_with('whatever password',app.DUMMY_PASSWORD_HASH)

    def test_exceptional_email_rejected_not_truncated(self):
        huge='a'*255+'@example.test'
        status,_,_=self.post('/register',{'name':'Too Long','email':huge,'password':'long enough password'})
        self.assertEqual(status,400)
        with app.db() as c:
            self.assertEqual(c.execute('SELECT count(*) AS n FROM users WHERE display_name=?',('Too Long',)).fetchone()['n'],0)

    def test_mfa_binds_second_factor_to_authenticated_user(self):
        email,pw=self.create_user('mfa@example.test')
        secret=new_totp_secret()
        with app.db() as c:
            c.execute('UPDATE users SET totp_secret=? WHERE email=?',(secret,email))
        status,body,_=self.login(email,pw)
        self.assertEqual(status,200)  # follows redirect to MFA page, not account
        self.assertIn('Two-factor verification',body)
        status,_,_=self.get('/account')
        self.assertEqual(status,401)
        status,_,_=self.post('/mfa',{'code':'not-a-code','verify':'other-account'})
        self.assertEqual(status,401)
        code=totp_at(secret,int(time.time()))
        status,body,_=self.post('/mfa',{'code':code,'verify':'other-account'})
        self.assertEqual(status,200)
        self.assertIn('My account',body)
        self.assertIn(email,body)
        self.post('/logout',{})
        self.login(email,pw)
        status,_,_=self.post('/mfa',{'code':code})
        self.assertEqual(status,401)

    def test_mfa_enrollment_and_wrong_password(self):
        email,pw=self.create_user('enroll@example.test')
        self.login(email,pw)
        status,body,_=self.get('/mfa/setup')
        self.assertEqual(status,200)
        self.assertIn('data:image/png;base64,',body)
        self.assertIn('Scan with your authenticator app',body)
        with app.db() as c:
            u=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
            sid=c.execute('SELECT id_hash FROM sessions WHERE user_id=?',(u['id'],)).fetchone()['id_hash']
            secret=c.execute('SELECT secret FROM mfa_enrollments WHERE session_hash=?',(sid,)).fetchone()['secret']
        code=totp_at(secret,int(time.time()))
        status,_,_=self.post('/mfa/setup',{'password':'wrong password','code':code})
        self.assertEqual(status,403)
        status,body,_=self.post('/mfa/setup',{'password':pw,'code':code})
        self.assertEqual(status,200)
        self.assertIn('MFA: Enabled',body)

    def test_cafe_catalog_and_category_filters(self):
        status, body, _ = self.get('/')
        self.assertEqual(status, 200)
        self.assertIn('SecureShop Café', body)
        self.assertIn('Spanish Latte', body)
        self.assertIn('Chocolate Chip Cookie', body)
        self.assertNotIn('Wireless Mouse', body)
        status, filtered, _ = self.get('/?category=bakery')
        self.assertEqual(status, 200)
        self.assertIn('Chocolate Chip Cookie', filtered)
        self.assertNotIn('Classic Cappuccino', filtered)
        status, filtered, _ = self.get('/?category=iced')
        self.assertEqual(status, 200)
        self.assertIn('Iced Spanish Latte', filtered)
        self.assertNotIn('Butter Croissant', filtered)
        status, filtered, _ = self.get('/?q=spanish')
        self.assertEqual(status, 200)
        self.assertIn('Spanish Latte', filtered)
        self.assertNotIn('Cinnamon Roll', filtered)

    def test_sql_query_input_does_not_expand_search(self):
        status,body,_=self.get('/?q=%27%20OR%201%3D1--')
        self.assertEqual(status,200)
        self.assertNotIn('Spanish Latte</a>',body)


    def test_audit_records_login_and_denied_admin_without_secrets(self):
        email, pw = self.create_user('audit_visitor@example.test', 'private test password 123')
        status, _, _ = self.login(email, 'incorrect password')
        self.assertEqual(status, 401)
        status, _, _ = self.login(email, pw)
        self.assertEqual(status, 200)
        status, _, _ = self.get('/admin')
        self.assertEqual(status, 403)
        with app.db() as c:
            user_id = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()['id']
            event_names = [r['event'] for r in c.execute(
                'SELECT event FROM audit_events WHERE actor_id=? OR event=? ORDER BY id',
                (user_id, 'login_failed')).fetchall()]
            self.assertIn('login_failed', event_names)
            self.assertIn('login_success', event_names)
            self.assertIn('admin_denied', event_names)
            column_names = [r['name'] for r in c.execute('PRAGMA table_info(audit_events)').fetchall()]
            self.assertNotIn('password', column_names)
            self.assertNotIn('otp', column_names)
            self.assertNotIn('token', column_names)

    def test_audit_log_only_visible_to_admin(self):
        email, pw = self.create_user('audit_admin@example.test')
        self.login(email, pw)
        status, _, _ = self.get('/admin/audit')
        self.assertEqual(status, 403)
        with app.db() as c:
            c.execute("UPDATE users SET role='admin' WHERE email=?", (email,))
        status, body, _ = self.get('/admin/audit')
        self.assertEqual(status, 200)
        self.assertIn('Security audit log', body)
        self.assertIn('admin_denied', body)
        self.assertNotIn(pw, body)

    def test_audit_rejects_unrecognized_event(self):
        with app.db() as c:
            with self.assertRaises(ValueError):
                app.audit_event(c, 'arbitrary sensitive text')


if __name__ == '__main__':
    unittest.main()

# HTTP integration checks for the new Blue Team routes.
class BlueTeamWebTests(WebTestHelpers, unittest.TestCase):
    def test_security_page_protected_and_behaviour_five_enrollments(self):
        self.assertEqual(self.get('/security')[0],401)
        email,pw=self.create_user('behavior-web@example.test')
        self.login(email,pw)
        self.assertIn('Account security center',self.get('/security')[1])
        sample='{"gaps":[100,110,90,120,105,95]}'
        for _ in range(5):
            self.assertEqual(self.post('/security/behavior',{'password':pw,'timing':sample})[0],200)
        with app.db() as c:
            u=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
            row=c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(u['id'],)).fetchone()
            self.assertEqual(len(__import__('json').loads(row['samples'])),5)
        status, page, _ = self.get('/security/behavior')
        self.assertEqual(status, 200)
        self.assertIn('Typing enrollment complete (5/5)', page)
        self.assertNotIn('Save trusted sample', page)
        # Sixth POST must never replace the five trusted samples.
        status, _, _ = self.post('/security/behavior', {'password':pw,'timing':sample})
        self.assertEqual(status, 409)
        with app.db() as c:
            row=c.execute('SELECT samples FROM behavior_profiles WHERE user_id=?',(u['id'],)).fetchone()
            self.assertEqual(len(__import__('json').loads(row['samples'])),5)
        self.post('/logout',{})
        self.login(email,pw)
        with app.db() as c:
            events=c.execute("SELECT COUNT(*) AS n FROM audit_events WHERE event='behavior_anomaly' AND actor_id=?",(u['id'],)).fetchone()['n']
            self.assertGreaterEqual(events,1)  # no timing signal is suspicious but not identity proof

    def test_login_with_partial_typing_enrollment(self):
        import json
        email, pw = self.create_user('partial-typing-login@example.test')
        sample = {'speed': 7.0, 'gap_1': 100, 'gap_2': 100,
                  'gap_3': 100, 'gap_4': 100, 'gap_5': 100}
        with app.db() as c:
            uid = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()['id']
        for count in (1, 2, 3, 4, 5):
            with app.db() as c:
                c.execute('INSERT INTO behavior_profiles(user_id,samples,updated_at) VALUES(?,?,?) '
                          'ON CONFLICT(user_id) DO UPDATE SET samples=excluded.samples,updated_at=excluded.updated_at',
                          (uid, json.dumps([sample] * count), int(time.time())))
            status, _, _ = self.login(email, pw)
            self.assertEqual(status, 200, f'Login failed with {count} typing samples')
            self.assertIn('My account', self.get('/account')[1])
            self.post('/logout', {})

    def test_passkey_register_and_assertion_over_http(self):
        import json,hashlib,struct
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from test_blue_security import enc
        from passkey_security import b64u
        email,pw=self.create_user('passkey-web@example.test')
        self.login(email,pw)
        response=self.post('/passkey/start',{'password':pw})
        self.assertEqual(response[0],200)
        ch=json.loads(response[1])['challenge']
        key=ec.generate_private_key(ec.SECP256R1())
        pub=key.public_key().public_numbers()
        cose=enc({1:2,3:-7,-1:1,-2:pub.x.to_bytes(32,'big'),-3:pub.y.to_bytes(32,'big')})
        rp_hash=hashlib.sha256(b'localhost').digest()
        cred_id=b'web-authenticator-id'
        auth=rp_hash+bytes([0x45])+struct.pack('>I',0)+bytes(16)+struct.pack('>H',len(cred_id))+cred_id+cose
        client=json.dumps({'type':'webauthn.create','challenge':ch,'origin':'http://localhost:8000'}).encode()
        reg={'type':'public-key','rawId':b64u(cred_id),'response':{'clientDataJSON':b64u(client),'attestationObject':b64u(enc({'fmt':'none','attStmt':{},'authData':auth}))}}
        r=self.post('/passkey/finish',{'credential':json.dumps(reg)})
        self.assertEqual(r[0],200,r[1])
        with app.db() as c:
            uid=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()['id']
            self.assertEqual(c.execute('SELECT COUNT(*) FROM passkeys WHERE user_id=?',(uid,)).fetchone()[0],1)
        r=self.post('/passkey/auth/start',{})
        self.assertEqual(r[0],200)
        ch=json.loads(r[1])['challenge']
        body=rp_hash+bytes([0x05])+struct.pack('>I',1)
        client=json.dumps({'type':'webauthn.get','challenge':ch,'origin':'http://localhost:8000'}).encode()
        signature=key.sign(body+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
        assertion={'type':'public-key','rawId':b64u(cred_id),'response':{'clientDataJSON':b64u(client),'authenticatorData':b64u(body),'signature':b64u(signature)}}
        from unittest.mock import patch
        with patch.object(app,'location_time_result',return_value=(True,'allow',0.0)):
            r=self.post('/passkey/auth/finish',{'credential':json.dumps(assertion),'lat':'30.0444','lon':'31.2357'})
        self.assertEqual(r[0],200,r[1]);self.assertIn('Security policy approved',r[1])
        r=self.post('/passkey/auth/finish',{'credential':json.dumps(assertion),'lat':'30.0444','lon':'31.2357'})
        self.assertEqual(r[0],403) # challenge one-time use

    def test_passkey_signature_and_location_time_policy_denials_over_http(self):
        """Fresh WebAuthn challenges exercise each HTTP denial using actual policy math."""
        import datetime, hashlib, json, struct
        from unittest.mock import patch
        from zoneinfo import ZoneInfo
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from passkey_security import b64u
        from blue_security import location_time_result as evaluate_policy

        email,pw=self.create_user('risk-negative@example.test')
        self.login(email,pw)
        private=ec.generate_private_key(ec.SECP256R1())
        ident=b64u(b'negative-policy-credential')
        der=private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        with app.db() as c:
            uid=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()['id']
            c.execute('INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,created_at) VALUES(?,?,?,?,?)',(ident,uid,der,0,0))

        def attempt(lat,lon,when,wrong_signature=False):
            start=self.post('/passkey/auth/start',{})
            self.assertEqual(start[0],200)
            challenge=json.loads(start[1])['challenge']
            self.assertEqual(json.loads(start[1])['rpId'],'localhost')
            auth=hashlib.sha256(b'localhost').digest()+bytes([5])+struct.pack('>I',0)
            client=json.dumps({'type':'webauthn.get','challenge':challenge,'origin':'http://localhost:8000'}).encode()
            sig=private.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
            if wrong_signature: sig=b'wrong signature'
            credential={'type':'public-key','rawId':ident,'response':{'clientDataJSON':b64u(client),'authenticatorData':b64u(auth),'signature':b64u(sig)}}
            def result(real_lat, real_lon, home_lat, home_lon):
                return evaluate_policy(real_lat,real_lon,home_lat,home_lon,now=when)
            with patch.object(app,'location_time_result',side_effect=result):
                return self.post('/passkey/auth/finish',{'credential':json.dumps(credential),'lat':str(lat),'lon':str(lon)})

        day=datetime.datetime(2026,11,20,9,tzinfo=ZoneInfo('Africa/Cairo'))
        night=datetime.datetime(2026,11,20,23,tzinfo=ZoneInfo('Africa/Cairo'))
        r=attempt(51.5074,-0.1278,day)
        self.assertEqual(r[0],403,r[1]);self.assertIn('(location)',r[1])
        r=attempt(30.0444,31.2357,night)
        self.assertEqual(r[0],403,r[1]);self.assertIn('(time)',r[1])
        r=attempt(30.0444,31.2357,day,wrong_signature=True)
        self.assertEqual(r[0],403,r[1]);self.assertIn('Passkey verification',r[1])
        r=attempt(30.0444,31.2357,day)
        self.assertEqual(r[0],200,r[1]);self.assertIn('Security policy approved',r[1])
        with app.db() as c:
            self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM audit_events WHERE event='risk_location_denied' AND actor_id=?",(uid,)).fetchone()[0],1)
            self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM audit_events WHERE event='risk_time_denied' AND actor_id=?",(uid,)).fetchone()[0],1)

    def test_passkey_setup_requires_authenticated_session_and_password(self):
        self.assertEqual(self.post('/passkey/start',{'password':'anything'})[0],401)
        email,pw=self.create_user('pk-wrong-password@example.test')
        self.login(email,pw)
        self.assertEqual(self.post('/passkey/start',{'password':'wrong'})[0],403)
        self.assertEqual(self.post('/passkey/auth/start',{})[0],403)

    def test_optional_enforced_passkey_login_cannot_bypass_gate(self):
        import json,hashlib,struct
        from unittest.mock import patch
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from passkey_security import b64u
        email,pw=self.create_user('enforced-pk@example.test')
        key=ec.generate_private_key(ec.SECP256R1())
        ident=b64u(b'credential-for-enforced-login')
        der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        with app.db() as c:
            uid=c.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()['id']
            c.execute('INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,created_at) VALUES(?,?,?,?,?)',(ident,uid,der,0,0))
        with patch.object(app,'RISK_GATE_ENFORCE',True):
            status,html,_=self.login(email,pw)
            self.assertEqual(status,200)
            self.assertIn('Passkey verification',html)
            self.assertEqual(self.get('/account')[0],401)
            start=self.post('/passkey/auth/start',{})
            self.assertEqual(start[0],200)
            ch=json.loads(start[1])['challenge']
            auth=hashlib.sha256(b'localhost').digest()+bytes([5])+struct.pack('>I',1)
            client=json.dumps({'type':'webauthn.get','challenge':ch,'origin':'http://localhost:8000'}).encode()
            signature=key.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
            cred={'type':'public-key','rawId':ident,'response':{'clientDataJSON':b64u(client),'authenticatorData':b64u(auth),'signature':b64u(signature)}}
            with patch.object(app,'location_time_result',return_value=(True,'allow',0.0)):
                finish=self.post('/passkey/auth/finish',{'credential':json.dumps(cred),'lat':'30.0444','lon':'31.2357'})
            self.assertEqual(finish[0],200,finish[1])
            self.assertIn('login_complete',finish[1])
            self.assertIn('My account',self.get('/account')[1])

    def test_security_js_served_and_csp_allows_own_script(self):
        status,body,headers=self.get('/security')
        self.assertEqual(status,401)
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
        r=self.get('/static/security.js')
        self.assertEqual(r[0],200)
        self.assertIn('navigator.credentials',r[1])

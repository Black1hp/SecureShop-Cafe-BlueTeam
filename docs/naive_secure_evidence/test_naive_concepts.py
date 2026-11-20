"""Isolated, in-memory teaching examples. NO network server, accounts, or real database.

These exercises demonstrate insecure design patterns and their consequences; they
are NOT a recovered/previous vulnerable version of SecureShop Cafe.
"""
import html
import unittest


class NaiveConceptDemonstrations(unittest.TestCase):
    def test_01_client_controlled_price(self):
        # Naive checkout trusts the submitted price, despite catalog price of 2499 cents.
        catalog_price = 2499
        attacker_form = {'product_id': '1', 'price_cents': '1', 'qty': '1'}
        naive_total = int(attacker_form['price_cents']) * int(attacker_form['qty'])
        self.assertEqual(naive_total, 1)
        self.assertNotEqual(naive_total, catalog_price)

    def test_02_coupon_reuse(self):
        naive_discount = lambda code: 10 if code == 'TEST10' else 0
        self.assertEqual([naive_discount('TEST10'), naive_discount('TEST10')], [10, 10])

    def test_03_negative_quantity(self):
        naive_cart_total = lambda qty, unit: qty * unit
        self.assertLess(naive_cart_total(-1, 2499), 0)

    def test_04_missing_csrf(self):
        naive_accepts_post = lambda logged_in, request: logged_in and request['method'] == 'POST'
        forged = {'method': 'POST', 'csrf': None}
        self.assertTrue(naive_accepts_post(True, forged))

    def test_05_missing_role_authorization(self):
        naive_admin_route = lambda logged_in: logged_in
        self.assertTrue(naive_admin_route(True))  # ordinary signed-in user can enter

    def test_06_idor(self):
        orders = {7: {'owner': 1, 'total': 2499}}
        attacker_user = 2
        naive_lookup = orders.get(7)  # no owner check
        self.assertNotEqual(naive_lookup['owner'], attacker_user)
        self.assertIsNotNone(naive_lookup)

    def test_07_raw_html_injection(self):
        attacker_name = '<script>alert(1)</script>'
        naive_html = '<p>' + attacker_name + '</p>'
        self.assertIn('<script>', naive_html)
        self.assertNotIn('<script>', '<p>' + html.escape(attacker_name) + '</p>')

    def test_08_sql_string_concatenation(self):
        search = "' OR 1=1--"
        naive_sql = "SELECT * FROM products WHERE name LIKE '%" + search + "%'"
        self.assertIn('OR 1=1--', naive_sql)
        # Constructing this dangerous string is the demonstration; nothing executes it.

    def test_09_mfa_identity_unbound(self):
        secrets = {'alice': 'ALICE-SECRET', 'bob': 'BOB-SECRET'}
        pending_password_user = 'alice'
        naive_otp_lookup = lambda submitted_user: secrets[submitted_user]
        self.assertEqual(naive_otp_lookup('bob'), 'BOB-SECRET')
        self.assertNotEqual(naive_otp_lookup('bob'), secrets[pending_password_user])

    def test_10_reusable_challenge(self):
        naive_check = lambda presented, stored: presented == stored
        challenge = 'example-challenge'
        self.assertTrue(naive_check(challenge, challenge))
        self.assertTrue(naive_check(challenge, challenge))  # replay accepted

    def test_11_no_location_time_gate(self):
        naive_gate = lambda authenticated, lat, lon, hour: authenticated
        self.assertTrue(naive_gate(True, 51.5074, -0.1278, 23))

    def test_12_no_typing_baseline(self):
        naive_detect_anomaly = lambda _: False
        self.assertFalse(naive_detect_anomaly({'speed': 50, 'gap_1': 3000}))


if __name__ == '__main__':
    unittest.main(verbosity=2)

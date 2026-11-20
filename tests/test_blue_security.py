"""Deterministic CET431 typing behavior and passkey security tests; no real credentials or geolocation."""
import datetime
import hashlib
import json
import struct
import unittest
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from blue_security import (parse_timing,build_profile,anomaly_score,haversine_km,
                           location_time_result,local_hour_ok)
from passkey_security import (b64u,client_data,cbor,parse_authenticator_data,
                              verify_assertion,verify_registration)


def cbi(n):
    if n<24:return bytes([n])
    if n<256:return bytes([24,n])
    if n<65536:return bytes([25])+n.to_bytes(2,'big')
    return bytes([26])+n.to_bytes(4,'big')


def enc(v):
    if isinstance(v,int):
        if v<0:
            b=cbi(-1-v);return bytes([b[0]|0x20])+b[1:]
        return cbi(v)
    if isinstance(v,bytes):
        b=cbi(len(v));return bytes([b[0]|0x40])+b[1:]+v
    if isinstance(v,str):
        data=v.encode(); b=cbi(len(data));return bytes([b[0]|0x60])+b[1:]+data
    if isinstance(v,dict):
        b=cbi(len(v));return bytes([b[0]|0xa0])+b[1:]+b''.join(enc(k)+enc(val) for k,val in v.items())
    raise TypeError(type(v))


class BehavioralTests(unittest.TestCase):
    def test_five_samples_then_anomaly(self):
        samples = [parse_timing(json.dumps({'gaps':[110+i,120+i,100+i,130+i,115+i]})) for i in range(5)]
        self.assertTrue(all(samples))
        profile=build_profile(samples)
        self.assertLess(anomaly_score(samples[2],profile),3)
        suspicious=parse_timing(json.dumps({'gaps':[800,900,700,850,950]}))
        self.assertGreater(anomaly_score(suspicious,profile),3)

    def test_invalid_timings_are_not_trusted(self):
        for value in ('', 'not json', '{"gaps":[1,2,3]}', '{"gaps":[NaN,30,40]}', '{"gaps":[10]}'):
            self.assertIsNone(parse_timing(value))

    def test_requires_five_samples(self):
        with self.assertRaises(ValueError):
            build_profile([{'speed':1,'gap_mean':20,'gap_std':1}]*4)


class GeoTimeTests(unittest.TestCase):
    def test_haversine(self):
        self.assertAlmostEqual(haversine_km(30.0444,31.2357,30.0444,31.2357),0)
        self.assertGreater(haversine_km(30.0444,31.2357,51.5074,-0.1278),3000)
        with self.assertRaises(ValueError):haversine_km(91,10,30,31)

    def test_distance_policy_boundary_near_50_km(self):
        """Known test coordinates on either side of the nominal 50 km radius."""
        home_lat,home_lon=30.0444,31.2357
        day=datetime.datetime(2026,11,20,12,tzinfo=ZoneInfo('Africa/Cairo'))
        # About 49 and 51 km due north on a meridian; no real location access.
        self.assertEqual(location_time_result(home_lat+0.44,home_lon,home_lat,home_lon,day)[1],'allow')
        self.assertEqual(location_time_result(home_lat+0.46,home_lon,home_lat,home_lon,day)[1],'location')

    def test_hour_window_boundaries(self):
        for hour,expected in [(7,False),(8,True),(21,True),(22,False)]:
            d=datetime.datetime(2026,11,20,hour,tzinfo=ZoneInfo('Africa/Cairo'))
            self.assertEqual(local_hour_ok(d),expected)

    def test_location_time_policy(self):
        d=datetime.datetime(2026,11,20,10,tzinfo=ZoneInfo('Africa/Cairo'))
        self.assertEqual(location_time_result(30.0444,31.2357,30.0444,31.2357,d)[1],'allow')
        self.assertEqual(location_time_result(51.5074,-0.1278,30.0444,31.2357,d)[1],'location')
        night=datetime.datetime(2026,11,20,23,tzinfo=ZoneInfo('Africa/Cairo'))
        self.assertEqual(location_time_result(30.0444,31.2357,30.0444,31.2357,night)[1],'time')


class WebAuthnTests(unittest.TestCase):
    def setUp(self):
        self.challenge=b64u(b'c'*32)
        self.origin='http://localhost:8000'
        self.rp_id='localhost'
        self.key=ec.generate_private_key(ec.SECP256R1())
        self.public=self.key.public_key()
        self.id=b'id-for-test-123'
        self.cred_id=b64u(self.id)
        self.pub_der=self.public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.rp_hash=hashlib.sha256(self.rp_id.encode()).digest()

    def client(self, operation, challenge=None, origin=None):
        return json.dumps({'type':operation,'challenge':challenge or self.challenge,'origin':origin or self.origin},separators=(',',':')).encode()

    def test_registration_none_attestation_and_real_es256_assertion(self):
        nums=self.public.public_numbers()
        cose=enc({1:2,3:-7,-1:1,-2:nums.x.to_bytes(32,'big'),-3:nums.y.to_bytes(32,'big')})
        auth_reg=self.rp_hash+bytes([0x45])+struct.pack('>I',0)+bytes(16)+struct.pack('>H',len(self.id))+self.id+cose
        attestation=enc({'fmt':'none','attStmt':{},'authData':auth_reg})
        cred={'type':'public-key','rawId':self.cred_id,'response':{'clientDataJSON':b64u(self.client('webauthn.create')),'attestationObject':b64u(attestation)}}
        cid,key_der,count=verify_registration(cred,self.challenge,self.origin,self.rp_id)
        self.assertEqual(cid,self.cred_id)
        self.assertEqual(key_der,self.pub_der)
        auth_assertion=self.rp_hash+bytes([0x05])+struct.pack('>I',1)
        client=self.client('webauthn.get')
        signature=self.key.sign(auth_assertion+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
        assertion={'type':'public-key','rawId':self.cred_id,'response':{'clientDataJSON':b64u(client),'authenticatorData':b64u(auth_assertion),'signature':b64u(signature)}}
        self.assertEqual(verify_assertion(assertion,self.challenge,self.origin,self.rp_id,self.cred_id,self.pub_der,0),1)
        with self.assertRaises(ValueError):
            verify_assertion(assertion,self.challenge,self.origin,self.rp_id,self.cred_id,self.pub_der,1)
        with self.assertRaises(ValueError):
            verify_assertion(assertion,self.challenge,'http://evil.example',self.rp_id,self.cred_id,self.pub_der,0)
        assertion['response']['signature']=b64u(b'invalid-signature')
        with self.assertRaises((ValueError,Exception)):
            verify_assertion(assertion,self.challenge,self.origin,self.rp_id,self.cred_id,self.pub_der,0)

    def test_rp_id_and_uv_required(self):
        auth=self.rp_hash+bytes([0x01])+struct.pack('>I',1)
        with self.assertRaises(ValueError):parse_authenticator_data(auth,self.rp_id)
        with self.assertRaises(ValueError):parse_authenticator_data(auth,'wrong.example')

    def test_challenge_replay_and_wrong_operation(self):
        with self.assertRaises(ValueError):
            client_data(b64u(self.client('webauthn.get')),b64u(b'other'),'http://localhost:8000','webauthn.get')
        with self.assertRaises(ValueError):
            client_data(b64u(self.client('webauthn.get')),self.challenge,self.origin,'webauthn.create')

    def test_cbor_rejects_unsupported_encoding(self):
        with self.assertRaises(ValueError):cbor(b'\x9f\x01\xff')


if __name__=='__main__': unittest.main()

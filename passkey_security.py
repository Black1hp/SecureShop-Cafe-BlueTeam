"""Small WebAuthn ES256 verifier for an educational *localhost-only* demo.

Supports none attestation and ES256 P-256 public keys. No production claim:
use a maintained WebAuthn library for real deployments and broader algorithms.
"""
import base64
import hashlib
import json
import secrets
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def unb64(value):
    if not isinstance(value, str) or len(value) > 12000:
        raise ValueError('Bad encoded data')
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def challenge():
    return b64u(secrets.token_bytes(32))


def cbor(data, position=0, depth=0):
    """Strict bounded subset of CBOR needed for authenticator data and COSE keys."""
    if depth > 8 or position >= len(data):
        raise ValueError('Invalid CBOR')
    initial = data[position]; position += 1
    major, ai = initial >> 5, initial & 31
    if ai < 24: size = ai
    elif ai in (24, 25, 26, 27):
        count = {24:1, 25:2, 26:4, 27:8}[ai]
        if position + count > len(data): raise ValueError('Invalid CBOR length')
        size = int.from_bytes(data[position:position+count], 'big'); position += count
    else: raise ValueError('Indefinite CBOR disallowed')
    if size > 100000: raise ValueError('Oversized CBOR')
    if major == 0: return size, position
    if major == 1: return -1 - size, position
    if major in (2, 3):
        if position + size > len(data): raise ValueError('Truncated CBOR')
        raw = data[position:position+size]; position += size
        return (raw if major == 2 else raw.decode('utf-8')), position
    if major == 4:
        arr = []
        for _ in range(size):
            val, position = cbor(data, position, depth+1); arr.append(val)
        return arr, position
    if major == 5:
        result = {}
        for _ in range(size):
            key, position = cbor(data, position, depth+1)
            if key in result: raise ValueError('Duplicate CBOR key')
            val, position = cbor(data, position, depth+1); result[key] = val
        return result, position
    if major == 7 and size in (20, 21, 22):
        return {20:False,21:True,22:None}[size], position
    raise ValueError('Unsupported CBOR type')


def client_data(encoded, expected_challenge, expected_origin, operation):
    raw = unb64(encoded)
    if len(raw) > 4096: raise ValueError('Client data oversized')
    data = json.loads(raw)
    if (data.get('type') != operation or data.get('challenge') != expected_challenge or
        data.get('origin') != expected_origin or data.get('crossOrigin', False)):
        raise ValueError('Client data mismatch')
    return raw


def parse_authenticator_data(auth_data, rp_id, registration=False):
    if len(auth_data) < 37: raise ValueError('Short authenticator data')
    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError('RP ID hash mismatch')
    flags = auth_data[32]
    if not flags & 0x01 or not flags & 0x04:  # UP and UV both required
        raise ValueError('User presence/verification missing')
    count = struct.unpack('>I', auth_data[33:37])[0]
    if not registration: return count
    if not flags & 0x40 or len(auth_data) < 55:
        raise ValueError('Attested credential data missing')
    index = 53 # 37 header + 16 byte AAGUID
    cred_len = struct.unpack('>H', auth_data[index:index+2])[0]; index += 2
    if not 1 <= cred_len <= 1024 or index+cred_len >= len(auth_data):
        raise ValueError('Bad credential ID length')
    cred_id = auth_data[index:index+cred_len]; index += cred_len
    cose, end = cbor(auth_data, index)
    if not isinstance(cose, dict) or not {1,3,-1,-2,-3}.issubset(cose):
        raise ValueError('Invalid COSE key')
    if cose[1] != 2 or cose[3] != -7 or cose[-1] != 1:
        raise ValueError('Only ES256 P-256 supported')
    x,y = cose[-2],cose[-3]
    if not isinstance(x,bytes) or not isinstance(y,bytes) or len(x)!=32 or len(y)!=32:
        raise ValueError('Bad P-256 coordinates')
    public_key = ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'),int.from_bytes(y,'big'),ec.SECP256R1()).public_key()
    if end != len(auth_data) and not (flags & 0x80):
        raise ValueError('Unexpected CBOR trailing data')
    return cred_id, public_key, count


def verify_registration(credential, expected_challenge, origin, rp_id):
    if credential.get('type') != 'public-key': raise ValueError('Not a public key')
    raw_id = unb64(credential['rawId'])
    client_data(credential['response']['clientDataJSON'],expected_challenge,origin,'webauthn.create')
    attestation_bytes = unb64(credential['response']['attestationObject'])
    if len(attestation_bytes) > 8192: raise ValueError('Attestation too large')
    att, end = cbor(attestation_bytes)
    if end != len(attestation_bytes) or not isinstance(att, dict) or att.get('fmt') != 'none':
        raise ValueError('Only none attestation supported')
    cred_id, pub, count = parse_authenticator_data(att['authData'], rp_id, True)
    if raw_id != cred_id: raise ValueError('Credential ID mismatch')
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return b64u(cred_id), pub.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo), count


def verify_assertion(credential, expected_challenge, origin, rp_id, cred_id, public_key_der, old_counter):
    if credential.get('type') != 'public-key' or unb64(credential['rawId']) != unb64(cred_id):
        raise ValueError('Unrecognized credential')
    response = credential['response']
    raw_client = client_data(response['clientDataJSON'],expected_challenge,origin,'webauthn.get')
    auth_data = unb64(response['authenticatorData'])
    count = parse_authenticator_data(auth_data,rp_id)
    signature = unb64(response['signature'])
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    key = load_der_public_key(public_key_der)
    if not isinstance(key,ec.EllipticCurvePublicKey) or not isinstance(key.curve,ec.SECP256R1):
        raise ValueError('Invalid registered key')
    try:
        key.verify(signature, auth_data+hashlib.sha256(raw_client).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError('Invalid signature') from exc
    if old_counter and count and count <= old_counter:
        raise ValueError('Credential counter did not advance')
    return count

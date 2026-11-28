"""Passkeys (WebAuthn) for the panel, in the standard library only.

Only what the panel needs: "none" attestation, ES256 (ECDSA P-256 + SHA-256) and RS256 keys, user verification
required. Every check here works on public data (public keys, signatures), so plain big-integer arithmetic is fine.
"""
import base64
import hashlib
import hmac
import json
import struct

ES256, RS256 = -7, -257
ALGORITHMS = (ES256, RS256)
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


class WebAuthnError(ValueError):
    pass


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(text):
    text = str(text or '')
    if len(text) > 8192 or not all(c.isalnum() or c in '-_=' for c in text): raise WebAuthnError('Invalid base64url')
    try: return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except (ValueError, TypeError) as exc: raise WebAuthnError('Invalid base64url') from exc


# ------------------------------------------------------------------ CBOR (RFC 8949), the subset WebAuthn uses
def cbor_decode(data, offset=0, depth=0):
    """One item at `offset`: returns (value, next offset). Definite lengths only."""
    if depth > 16: raise WebAuthnError('CBOR nested too deep')
    if offset >= len(data): raise WebAuthnError('CBOR truncated')
    head = data[offset]; offset += 1
    major, info = head >> 5, head & 31
    if info < 24: value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if offset + size > len(data): raise WebAuthnError('CBOR truncated')
        value = int.from_bytes(data[offset:offset + size], 'big'); offset += size
    else: raise WebAuthnError('Unsupported CBOR item')
    if major == 0: return value, offset
    if major == 1: return -1 - value, offset
    if major in (2, 3):
        if offset + value > len(data): raise WebAuthnError('CBOR truncated')
        chunk = bytes(data[offset:offset + value]); offset += value
        if major == 2: return chunk, offset
        try: return chunk.decode('utf-8'), offset
        except UnicodeDecodeError as exc: raise WebAuthnError('Invalid CBOR text') from exc
    if major == 4:
        if value > 64: raise WebAuthnError('CBOR array too long')
        items = []
        for _ in range(value):
            item, offset = cbor_decode(data, offset, depth + 1); items.append(item)
        return items, offset
    if major == 5:
        if value > 64: raise WebAuthnError('CBOR map too long')
        result = {}
        for _ in range(value):
            key, offset = cbor_decode(data, offset, depth + 1)
            if isinstance(key, (list, dict)): raise WebAuthnError('Invalid CBOR map key')
            result[key], offset = cbor_decode(data, offset, depth + 1)
        return result, offset
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], offset
    raise WebAuthnError('Unsupported CBOR item')


# ------------------------------------------------------------------ P-256
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def on_curve(point):
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - A * x - B) % P == 0


def _jacobian_double(p):
    x, y, z = p
    if not y or not z: return (0, 1, 0)
    yy = y * y % P; s = 4 * x * yy % P; zz = z * z % P
    m = (3 * x * x + A * zz * zz) % P
    nx = (m * m - 2 * s) % P
    return nx, (m * (s - nx) - 8 * yy * yy) % P, 2 * y * z % P


def _jacobian_add(p, q):
    if not p[2]: return q
    if not q[2]: return p
    z1z1, z2z2 = p[2] * p[2] % P, q[2] * q[2] % P
    u1, u2 = p[0] * z2z2 % P, q[0] * z1z1 % P
    s1, s2 = p[1] * q[2] * z2z2 % P, q[1] * p[2] * z1z1 % P
    if u1 == u2:
        return _jacobian_double(p) if s1 == s2 else (0, 1, 0)
    hh = (u2 - u1) % P; r = (s2 - s1) % P
    h2 = hh * hh % P; h3 = hh * h2 % P; v = u1 * h2 % P
    nx = (r * r - h3 - 2 * v) % P
    return nx, (r * (v - nx) - s1 * h3) % P, hh * p[2] * q[2] % P


def _to_affine(p):
    if not p[2]: return None
    inv = pow(p[2], P - 2, P); inv2 = inv * inv % P
    return p[0] * inv2 % P, p[1] * inv2 * inv % P


def scalar_mult(k, point):
    result, addend = (0, 1, 0), (point[0], point[1], 1)
    while k:
        if k & 1: result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend); k >>= 1
    return result


def ecdsa_verify(point, message, r, s):
    if not on_curve(point) or not (0 < r < N and 0 < s < N): return False
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, N - 2, N)
    total = _to_affine(_jacobian_add(scalar_mult(e * w % N, G), scalar_mult(r * w % N, point)))
    return total is not None and total[0] % N == r


def der_signature(signature):
    """ECDSA signatures in WebAuthn are DER: SEQUENCE { INTEGER r, INTEGER s }."""
    def integer(data, at):
        if at + 2 > len(data) or data[at] != 0x02: raise WebAuthnError('Invalid signature')
        size = data[at + 1]
        if size == 0 or size > 33 or at + 2 + size > len(data): raise WebAuthnError('Invalid signature')
        return int.from_bytes(data[at + 2:at + 2 + size], 'big'), at + 2 + size
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2: raise WebAuthnError('Invalid signature')
    r, at = integer(signature, 2)
    s, at = integer(signature, at)
    if at != len(signature): raise WebAuthnError('Invalid signature')
    return r, s


# ------------------------------------------------------------------ RSA PKCS#1 v1.5 with SHA-256
SHA256_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')


def rsa_verify(modulus, exponent, message, signature):
    size = (modulus.bit_length() + 7) // 8
    if modulus.bit_length() < 2048 or len(signature) != size: return False
    value = int.from_bytes(signature, 'big')
    if value >= modulus: return False
    encoded = pow(value, exponent, modulus).to_bytes(size, 'big')
    digest = SHA256_PREFIX + hashlib.sha256(message).digest()
    expected = b'\x00\x01' + b'\xff' * (size - len(digest) - 3) + b'\x00' + digest
    return hmac.compare_digest(encoded, expected)


# ------------------------------------------------------------------ COSE keys
def cose_key(raw):
    """A credential public key: returns (alg, normalized key dict) or raises."""
    key, end = cbor_decode(raw)
    if end != len(raw) or not isinstance(key, dict): raise WebAuthnError('Invalid public key')
    alg = key.get(3)
    if alg == ES256:
        x, y = key.get(-2), key.get(-3)
        if key.get(1) != 2 or key.get(-1) != 1 or not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise WebAuthnError('Invalid EC2 key')
        point = (int.from_bytes(x, 'big'), int.from_bytes(y, 'big'))
        if not on_curve(point): raise WebAuthnError('Invalid EC2 key')
        return alg, {'point': point}
    if alg == RS256:
        n, e = key.get(-1), key.get(-2)
        if key.get(1) != 3 or not isinstance(n, bytes) or not isinstance(e, bytes):
            raise WebAuthnError('Invalid RSA key')
        modulus, exponent = int.from_bytes(n, 'big'), int.from_bytes(e, 'big')
        if modulus.bit_length() < 2048 or modulus.bit_length() > 8192 or exponent < 3 or exponent % 2 == 0:
            raise WebAuthnError('Invalid RSA key')
        return alg, {'n': modulus, 'e': exponent}
    raise WebAuthnError('Unsupported key type: use a passkey with ES256 or RS256')


def verify_signature(raw_key, message, signature):
    alg, key = cose_key(raw_key)
    if alg == ES256:
        r, s = der_signature(signature)
        return ecdsa_verify(key['point'], message, r, s)
    return rsa_verify(key['n'], key['e'], message, signature)


# ------------------------------------------------------------------ ceremonies
def _client_data(raw, kind, challenge, origin):
    try: data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc: raise WebAuthnError('Invalid client data') from exc
    if not isinstance(data, dict) or data.get('type') != kind: raise WebAuthnError('Wrong ceremony')
    if not hmac.compare_digest(str(data.get('challenge', '')), b64u(challenge)): raise WebAuthnError('Wrong or expired challenge')
    if data.get('origin') != origin: raise WebAuthnError('Wrong origin')
    if data.get('crossOrigin') is True: raise WebAuthnError('Cross-origin request')
    return data


def _auth_data(data, rp_id):
    if len(data) < 37: raise WebAuthnError('Invalid authenticator data')
    if not hmac.compare_digest(data[:32], hashlib.sha256(rp_id.encode()).digest()): raise WebAuthnError('Wrong site (rpId)')
    flags = data[32]
    if not flags & FLAG_UP: raise WebAuthnError('The user was not present')
    if not flags & FLAG_UV: raise WebAuthnError('The authenticator did not verify the user (PIN or biometrics)')
    return flags, struct.unpack('>I', data[33:37])[0]


def verify_registration(attestation_object, client_data_json, challenge, origin, rp_id):
    """A new passkey: returns {'id','key','alg','count'} (id and key base64url)."""
    _client_data(client_data_json, 'webauthn.create', challenge, origin)
    attestation, end = cbor_decode(attestation_object)
    if end != len(attestation_object) or not isinstance(attestation, dict): raise WebAuthnError('Invalid attestation')
    data = attestation.get('authData')
    if not isinstance(data, bytes): raise WebAuthnError('Invalid attestation')
    flags, count = _auth_data(data, rp_id)
    if not flags & FLAG_AT or len(data) < 55: raise WebAuthnError('No credential in the attestation')
    size = struct.unpack('>H', data[53:55])[0]
    if not 16 <= size <= 1023 or len(data) < 55 + size: raise WebAuthnError('Invalid credential id')
    credential = data[55:55 + size]
    _, key_end = cbor_decode(data, 55 + size)
    raw_key = data[55 + size:key_end]
    alg, _ = cose_key(raw_key)
    return {'id': b64u(credential), 'key': b64u(raw_key), 'alg': alg, 'count': count}


def verify_assertion(stored, authenticator_data, client_data_json, signature, challenge, origin, rp_id):
    """A sign-in with a stored passkey ({'key','count'}): returns the new signature counter."""
    _client_data(client_data_json, 'webauthn.get', challenge, origin)
    _, count = _auth_data(authenticator_data, rp_id)
    message = authenticator_data + hashlib.sha256(client_data_json).digest()
    if not verify_signature(unb64u(stored['key']), message, signature): raise WebAuthnError('Invalid signature')
    old = int(stored.get('count') or 0)
    if (count or old) and count <= old: raise WebAuthnError('The signature counter went back: the passkey may have been copied')
    return count

"""0.25: passkeys (WebAuthn) for the panel, verified in the standard library."""
import hashlib
import json
import os
import secrets
import struct
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_v010_features import auth  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import sudo_list

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import awg31webauthn as wa  # noqa: E402

SITE = 'panel.example.test'
ORIGIN = 'https://' + SITE


# ------------------------------------------------------------------ a software authenticator for the tests
def cbor(value):
    def head(major, n):
        if n < 24: return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size): return bytes([major << 5 | info]) + n.to_bytes(size, 'big')
    if value is None: return b'\xf6'
    if isinstance(value, bool): return bytes([0xf5 if value else 0xf4])
    if isinstance(value, int): return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes): return head(2, len(value)) + value
    if isinstance(value, str): return head(3, len(value.encode())) + value.encode()
    if isinstance(value, list): return head(4, len(value)) + b''.join(cbor(x) for x in value)
    if isinstance(value, dict): return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


def der(r, s):
    def integer(n):
        raw = n.to_bytes((n.bit_length() + 8) // 8, 'big')
        return b'\x02' + bytes([len(raw)]) + raw
    body = integer(r) + integer(s)
    return b'\x30' + bytes([len(body)]) + body


class Authenticator:
    def __init__(self, rp_id=SITE):
        self.secret = secrets.randbelow(wa.N - 1) + 1
        self.point = wa._to_affine(wa.scalar_mult(self.secret, wa.G))
        self.id = os.urandom(32)
        self.count = 0
        self.rp_id = rp_id

    def cose(self):
        return cbor({1: 2, 3: -7, -1: 1, -2: self.point[0].to_bytes(32, 'big'), -3: self.point[1].to_bytes(32, 'big')})

    def sign(self, message):
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        while True:
            k = secrets.randbelow(wa.N - 1) + 1
            r = wa._to_affine(wa.scalar_mult(k, wa.G))[0] % wa.N
            s = pow(k, wa.N - 2, wa.N) * (e + r * self.secret) % wa.N
            if r and s: return der(r, s)

    def client(self, kind, challenge, origin=ORIGIN):
        return json.dumps({'type': kind, 'challenge': challenge, 'origin': origin, 'crossOrigin': False}).encode()

    def auth_data(self, flags, extra=b'', rp_id=None):
        return hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + struct.pack('>I', self.count) + extra

    def create(self, challenge, origin=ORIGIN, flags=0x45):
        self.count += 1
        data = self.auth_data(flags, b'\x00' * 16 + struct.pack('>H', len(self.id)) + self.id + self.cose())
        return {'attestationObject': wa.b64u(cbor({'fmt': 'none', 'attStmt': {}, 'authData': data})),
                'clientDataJSON': wa.b64u(self.client('webauthn.create', challenge, origin))}

    def get(self, challenge, origin=ORIGIN, flags=0x05, rp_id=None, bump=1):
        self.count += bump
        data = self.auth_data(flags, rp_id=rp_id)
        client = self.client('webauthn.get', challenge, origin)
        return {'id': wa.b64u(self.id), 'authenticatorData': wa.b64u(data), 'clientDataJSON': wa.b64u(client),
                'signature': wa.b64u(self.sign(data + hashlib.sha256(client).digest()))}


# ------------------------------------------------------------------ the verifier
def test_registration_and_assertion_are_checked_strictly():
    device = Authenticator()
    challenge = os.urandom(32)
    made = device.create(wa.b64u(challenge))
    stored = wa.verify_registration(wa.unb64u(made['attestationObject']), wa.unb64u(made['clientDataJSON']), challenge, ORIGIN, SITE)
    assert stored['id'] == wa.b64u(device.id) and stored['alg'] == -7 and stored['count'] == 1
    proof = device.get(wa.b64u(challenge))
    args = lambda p: (wa.unb64u(p['authenticatorData']), wa.unb64u(p['clientDataJSON']), wa.unb64u(p['signature']))
    assert wa.verify_assertion(stored, *args(proof), challenge, ORIGIN, SITE) == 2
    stored['count'] = 2
    bad = [
        (device.get(wa.b64u(challenge)), os.urandom(32), ORIGIN, SITE, 'challenge'),          # another challenge
        (device.get(wa.b64u(challenge), origin='https://evil.test'), challenge, ORIGIN, SITE, 'origin'),
        (device.get(wa.b64u(challenge), flags=0x01), challenge, ORIGIN, SITE, 'verify'),       # no user verification
        (device.get(wa.b64u(challenge), rp_id='evil.test'), challenge, ORIGIN, SITE, 'rpId'),
    ]
    for proof, expected_challenge, origin, rp_id, why in bad:
        with pytest.raises(wa.WebAuthnError, match=why):
            wa.verify_assertion(stored, *args(proof), expected_challenge, origin, rp_id)
    with pytest.raises(wa.WebAuthnError, match='counter'):                                   # a cloned authenticator
        wa.verify_assertion({**stored, 'count': device.count + 1}, *args(device.get(wa.b64u(challenge))), challenge, ORIGIN, SITE)
    proof = device.get(wa.b64u(challenge))
    data, client, signature = args(proof)
    with pytest.raises(wa.WebAuthnError, match='signature'):
        wa.verify_assertion(stored, data, client, signature[:-2] + bytes([signature[-2] ^ 1, signature[-1]]), challenge, ORIGIN, SITE)
    other = Authenticator()
    with pytest.raises(wa.WebAuthnError, match='signature'):
        wa.verify_assertion({'key': wa.b64u(other.cose()), 'count': 0}, data, client, signature, challenge, ORIGIN, SITE)
    # Registration without user verification, for another site or as a get: refused.
    for made, why in ((device.create(wa.b64u(challenge), flags=0x41), 'verify'), (device.create(wa.b64u(challenge), origin='https://x.test'), 'origin')):
        with pytest.raises(wa.WebAuthnError, match=why):
            wa.verify_registration(wa.unb64u(made['attestationObject']), wa.unb64u(made['clientDataJSON']), challenge, ORIGIN, SITE)


def test_cbor_and_keys_reject_malformed_input():
    assert wa.cbor_decode(cbor({1: [b'x', 'y', -5, True, None]})) == ({1: [b'x', 'y', -5, True, None]}, 10)
    for raw in (b'', b'\x5f', b'\x59\x00', b'\x9f', b'\xa1\x80\x01', bytes([0x81]) * 40 + b'\x00'):
        with pytest.raises(wa.WebAuthnError):
            wa.cbor_decode(raw)
    with pytest.raises(wa.WebAuthnError, match='EC2'):
        wa.cose_key(cbor({1: 2, 3: -7, -1: 1, -2: b'\x01' * 32, -3: b'\x02' * 32}))                # not on the curve
    with pytest.raises(wa.WebAuthnError, match='Unsupported'):
        wa.cose_key(cbor({1: 1, 3: -8, -1: 6, -2: b'\x01' * 32}))
    with pytest.raises(wa.WebAuthnError):
        wa.unb64u('not base64!')


def test_rsa_and_ecdsa_against_an_independent_library():
    pytest.importorskip('cryptography')
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    key = rsa.generate_private_key(65537, 2048)
    numbers = key.public_key().public_numbers()
    raw = cbor({1: 3, 3: -257, -1: numbers.n.to_bytes(256, 'big'), -2: numbers.e.to_bytes(3, 'big')})
    signature = key.sign(b'message', padding.PKCS1v15(), hashes.SHA256())
    assert wa.verify_signature(raw, b'message', signature) and not wa.verify_signature(raw, b'other', signature)
    eckey = ec.generate_private_key(ec.SECP256R1())
    point = eckey.public_key().public_numbers()
    raw = cbor({1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, 'big'), -3: point.y.to_bytes(32, 'big')})
    assert wa.verify_signature(raw, b'message', eckey.sign(b'message', ec.ECDSA(hashes.SHA256())))


# ------------------------------------------------------------------ root side
def test_passkeys_are_stored_with_the_password_and_their_counter(auth):
    admin, file = auth
    device = Authenticator()
    credential = {'id': wa.b64u(device.id), 'key': wa.b64u(device.cose()), 'alg': -7, 'count': 1, 'name': 'Laptop'}
    with pytest.raises(ValueError, match='password'):
        admin.passkey_add({'password': 'wrong', 'credential': credential})
    admin.passkey_add({'password': 'the-right-password', 'credential': credential})
    stored = json.loads(file.read_text())
    assert stored['passkeys'][0]['name'] == 'Laptop' and stored['auth_version'] == 'v1'
    with pytest.raises(ValueError, match='already'):
        admin.passkey_add({'password': 'the-right-password', 'credential': credential})
    for bad in ({**credential, 'id': 'x'}, {**credential, 'alg': -8}, {**credential, 'count': -1}, {**credential, 'name': 'a\nb'}):
        with pytest.raises(ValueError):
            admin.passkey_add({'password': 'the-right-password', 'credential': {**bad, 'id': bad['id'] if bad['id'] == 'x' else wa.b64u(os.urandom(32))}})
    admin.passkey_used({'id': credential['id'], 'count': 5})
    with pytest.raises(ValueError, match='back'):
        admin.passkey_used({'id': credential['id'], 'count': 5})
    assert json.loads(file.read_text())['passkeys'][0]['used']
    admin.passkey_delete({'id': credential['id']})
    assert json.loads(file.read_text())['passkeys'] == []
    with pytest.raises(ValueError, match='No such'):
        admin.passkey_delete({'id': credential['id']})
    events = [json.loads(x)['event'] for x in Path(os.environ['AWG31_AUDIT']).read_text().splitlines()]
    assert events == ['passkey_added', 'passkey_deleted']


def test_passkey_operations_are_wired_and_installed():
    panel, bot = sudo_list('AWG31_SUDO_COMMANDS'), sudo_list('AWG31_BOT_SUDO_COMMANDS')
    assert {'passkey-add', 'passkey-delete', 'passkey-used'} <= set(panel) and not {'passkey-add', 'passkey-used'} & set(bot)
    for script in ('setup-wizard.sh', 'upgrade-core.sh', 'upgrade-ui.sh'):
        assert 'awg31webauthn.py' in (ROOT / 'scripts' / script).read_text(), script
    assert 'cryptography' not in (ROOT / 'src/requirements.txt').read_text()            # no new dependency


# ------------------------------------------------------------------ panel
def browser(app):
    return TestClient(app.app, base_url=ORIGIN, follow_redirects=False, headers={'Origin': ORIGIN})


def test_register_a_passkey_and_sign_in_with_it(ui):
    app, client, calls = ui
    admin = browser(app)
    assert admin.post('/login', data={'password': 'correct-test-password'}).status_code == 303
    page = admin.get('/maintenance?tab=security')
    assert 'id="passkeys"' in page.text and 'data-passkey-register="/maintenance/passkeys"' in page.text
    csrf = token(page)
    assert admin.post('/maintenance/passkeys/options', json={'csrf': 'wrong'}).status_code == 403
    options = admin.post('/maintenance/passkeys/options', json={'csrf': csrf}).json()
    assert options['rp']['id'] == SITE and options['user']['name'] == 'admin' and options['authenticatorSelection']['userVerification'] == 'required'
    device = Authenticator()
    made = admin.post('/maintenance/passkeys', json={'csrf': csrf, 'name': 'Laptop', 'password': 'pw', **device.create(options['challenge'])})
    assert made.status_code == 200 and made.json()['ok']
    sent = [d for op, d in calls if op == 'passkey-add'][-1]
    assert sent['password'] == 'pw' and sent['credential']['id'] == wa.b64u(device.id) and sent['credential']['name'] == 'Laptop'
    # The same challenge cannot be used twice.
    again = admin.post('/maintenance/passkeys', json={'csrf': csrf, 'password': 'pw', **device.create(options['challenge'])})
    assert again.status_code == 400
    stored = json.loads(app.AUTH_FILE.read_text())
    stored['passkeys'] = [{k: sent['credential'][k] for k in ('id', 'key', 'alg', 'count', 'name')}]
    app.AUTH_FILE.write_text(json.dumps(stored))
    # Sign in: no password, no code.
    person = browser(app)
    login = person.get('/login')
    assert 'data-passkey-login="/login/passkey"' in login.text
    options = person.post('/login/passkey/options').json()
    assert options['rpId'] == SITE and options['userVerification'] == 'required'
    reply = person.post('/login/passkey', json={**device.get(options['challenge']), 'next': '/servers'})
    assert reply.json() == {'ok': True, 'next': '/servers'} and person.get('/servers').status_code == 200
    assert [d for op, d in calls if op == 'passkey-used'][-1] == {'id': wa.b64u(device.id), 'count': device.count}
    assert ('audit', {'event': 'login_success', 'target': 'testclient (passkey)'}) in calls
    # Refused: a replayed answer, another site's origin, an unknown passkey.
    replay = device.get(options['challenge'])
    assert browser(app).post('/login/passkey', json=replay).status_code == 400
    fresh = browser(app)
    challenge = fresh.post('/login/passkey/options').json()['challenge']
    assert fresh.post('/login/passkey', json=device.get(challenge, origin='https://evil.test')).status_code == 400
    challenge = fresh.post('/login/passkey/options').json()['challenge']
    assert fresh.post('/login/passkey', json=Authenticator().get(challenge)).status_code == 400
    assert fresh.get('/servers').status_code == 303
    # The list and deletion.
    page = admin.get('/maintenance?tab=security')
    assert '<strong>Laptop</strong>' in page.text
    admin.post('/maintenance/passkeys/delete', data={'csrf': csrf, 'id': wa.b64u(device.id)})
    assert ('passkey-delete', {'id': wa.b64u(device.id)}) in calls


def test_passkeys_need_a_site_name(ui):
    app, client, calls = ui
    plain = TestClient(app.app, base_url='http://203.0.113.7:8443', follow_redirects=False)
    assert plain.post('/login/passkey/options').status_code == 400
    page = client.get('/maintenance?tab=security')                 # the test client's host is "testserver": a name
    assert 'data-passkey-register' in page.text
    ip = TestClient(app.app, base_url='https://203.0.113.7', follow_redirects=False)
    ip.post('/login', data={'password': 'correct-test-password'})
    assert 'только когда панель открыта по доменному имени' in ip.get('/maintenance?tab=security').text
    assert app.rp_of(type('R', (), {'headers': {'host': 'Panel.Example.Test:8443'}})()) == 'panel.example.test'
    assert app.rp_of(type('R', (), {'headers': {'host': '[::1]:8443'}})()) is None


def test_a_viewer_manages_its_own_passkeys(ui):
    app, client, calls = ui
    from test_v024 import record, with_users
    with_users(app, olga=record('olga-password-1'))
    viewer = browser(app)
    app.login_attempts.clear()
    assert viewer.post('/login', data={'username': 'olga', 'password': 'olga-password-1'}).status_code == 303
    page = viewer.get('/maintenance?tab=security')
    options = viewer.post('/maintenance/passkeys/options', json={'csrf': token(page)}).json()
    assert options['user']['name'] == 'olga' and options['user']['id'] != app.passkey_user_id('admin')
    device = Authenticator()
    assert viewer.post('/maintenance/passkeys', json={'csrf': token(page), 'password': 'olga-password-1', **device.create(options['challenge'])}).status_code == 200
    assert [d for op, d in calls if op == 'passkey-add'][-1]['account'] == 'olga'

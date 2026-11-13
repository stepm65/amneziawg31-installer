"""Export format, authentication and bilingual client view regression tests."""
import base64
import hashlib
import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from amnezialink import build_vpn_uri


CONF = '''[Interface]
PrivateKey = clientPrivateBase64key
Address = 10.77.10.2/32
DNS = 1.1.1.1
MTU = 1380
Jc = 4
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = hpkBase64
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = serverPubBase64
PresharedKey = sharedPskBase64
Endpoint = 10.10.20.29:45678
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''


def decoded(uri):
    assert uri.startswith('vpn://')
    payload = uri[6:]
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def test_native_uri_shape_is_v3_and_has_no_I_when_off():
    uri = build_vpn_uri(CONF, name='Laptop', server_ip='10.77.10.1',
                        subnet='10.77.10.0/24', client_public_key='clientPubBase64')
    data = decoded(uri)
    assert data['defaultContainer'] == 'amnezia-awg2'
    awg = data['containers'][0]['awg']
    assert awg['protocol_version'] == '3.1'
    assert awg['port'] == '45678'
    assert awg['HeaderProtectionKey'] == 'hpkBase64'
    assert not any(f'I{i}' in awg for i in range(1, 6))
    client = json.loads(awg['last_config'])
    assert client['client_priv_key'] == 'clientPrivateBase64key'
    assert client['client_pub_key'] == 'clientPubBase64'
    assert client['allowed_ips'] == ['0.0.0.0/0']
    assert '::/0' not in client['allowed_ips']
    assert client['config'] == CONF
    assert data['dns1'] == '1.1.1.1'


def test_native_uri_retains_optional_CPS():
    config = CONF.replace('RandomTrailers = on', 'I1 = <r 48>\nRandomTrailers = on')
    data = decoded(build_vpn_uri(config,name='Laptop',server_ip='10.77.10.1',
                                subnet='10.77.10.0/24',client_public_key='pk'))
    assert data['containers'][0]['awg']['I1'] == '<r 48>'


def test_native_uri_checks_format():
    with pytest.raises(ValueError):
        build_vpn_uri(CONF.replace('10.77.10.2/32', '10.77.11.2/32'),name='x',
                      server_ip='10.77.10.1', subnet='10.77.10.0/24', client_public_key='pub')
    with pytest.raises(ValueError):
        build_vpn_uri('[Interface]\nPrivateKey = x', name='x', server_ip='10.77.10.1',
                      subnet='10.77.10.0/24', client_public_key='pub')


def app_for_test(tmp_path, monkeypatch):
    pwd = 'testpassword1234'
    salt = bytes([1]) * 16
    auth = {'salt':salt.hex(), 'password_hash':hashlib.scrypt(pwd.encode(), salt=salt,
           n=2**14,r=8,p=1,dklen=32).hex(),'session_key':'T'*48}
    path = tmp_path / 'auth.json'
    path.write_text(json.dumps(auth))
    monkeypatch.setenv('AWG31_AUTH',str(path))
    monkeypatch.setenv('AWG31_COOKIE_SECURE','0')
    spec = spec_from_file_location('awg31_web_share_test',Path(__file__).parents[1] / 'src/web.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    client_meta = {'name':'Laptop','ip':'10.77.10.2', 'config':CONF,
                   'client_public_key':'clientPubBase64', 'server_ip':'10.77.10.1',
                   'subnet':'10.77.10.0/24', 'i_enabled':False}
    module.ctl = lambda cmd, data=None: (
        client_meta if cmd=='download' else
        {'interface':'awg0','subnet':'10.77.10.0/24','server_ip':'10.77.10.1',
         'port':45678,'mtu':1380,'mode':'full','endpoint':'10.10.20.29',
         'dns':'1.1.1.1','running':True,'clients':[]} if cmd=='list' else {'ok':True})
    return module


def test_authenticated_tab_qrs_download_and_no_cache(tmp_path,monkeypatch):
    module = app_for_test(tmp_path,monkeypatch)
    client = TestClient(module.app)
    for path in ['/client/Laptop','/client/Laptop/qr?mode=vpn',
                 '/client/Laptop/qr?mode=conf','/client/Laptop/vpn-link']:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers['location'].startswith('/login?next=%2Fclient%2FLaptop')
    client.post('/login',data={'password':'testpassword1234'})
    page = client.get('/client/Laptop')
    assert page.status_code == 200
    assert 'AmneziaVPN Link' in page.text
    assert 'share-tab-conf' in page.text
    assert 'share-tab-vpn' in page.text
    assert 'role="tabpanel"' in page.text
    assert 'clientPrivateBase64key' in page.text
    assert 'Cache-Control' in page.headers
    assert page.headers['Cache-Control'] == 'no-store'
    link = client.get('/client/Laptop/vpn-link?download=1')
    assert link.status_code == 200
    assert 'attachment;' in link.headers['content-disposition']
    assert link.headers['cache-control'] == 'no-store'
    assert decoded(link.text.strip())['defaultContainer'] == 'amnezia-awg2'
    for mode in ['conf','vpn']:
        png = client.get(f'/client/Laptop/qr?mode={mode}&download=1')
        assert png.status_code == 200
        assert png.content.startswith(b'\x89PNG\r\n\x1a\n')
        assert png.headers['cache-control'] == 'no-store'
        assert 'attachment;' in png.headers['content-disposition']
    assert client.get('/client/Laptop/qr?mode=bad').status_code == 404
    en = client.get('/lang/en?next=%2Fclient%2FLaptop', follow_redirects=True)
    assert en.status_code == 200
    assert 'Export configuration' in en.text
    assert 'Download .vpn' in en.text


def test_old_controller_without_public_key_degrades_to_conf(tmp_path,monkeypatch):
    module = app_for_test(tmp_path,monkeypatch)
    raw = module.ctl
    module.ctl = lambda cmd,data=None: ({'config': CONF} if cmd=='download' else raw(cmd,data))
    client = TestClient(module.app)
    client.post('/login',data={'password':'testpassword1234'})
    page = client.get('/client/Laptop')
    assert page.status_code == 200
    assert 'disabled aria-disabled="true"' in page.text
    assert client.get('/client/Laptop/vpn-link').status_code == 422
    assert client.get('/client/Laptop/qr?mode=conf').status_code == 200

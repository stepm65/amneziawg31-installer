from importlib.util import spec_from_file_location,module_from_spec
import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient


def create_app(tmp_path,monkeypatch):
    pwd='testpassword1234'
    salt=b'\x01'*16
    info={'salt':salt.hex(),'password_hash':hashlib.scrypt(pwd.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32).hex(),
          'session_key':'D'*48}
    p=tmp_path/'auth.json'
    p.write_text(json.dumps(info))
    monkeypatch.setenv('AWG31_AUTH',str(p))
    monkeypatch.setenv('AWG31_COOKIE_SECURE','0')
    spec=spec_from_file_location('awg31_web_for_tests',Path(__file__).parents[1] /'src'/'web.py')
    module=module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ctl=lambda op,data=None: ({'name':data['name']} if op=='add' else
    {'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':51820,'clients':0,'running':True}]} if op=='servers' else {
       'interface':'awg0','subnet':'10.77.10.0/24','server_ip':'10.77.10.1',
       'port':51820,'mtu':1280,'endpoint':'vpn.example.net','dns':'1.1.1.1',
       'mode':'full','uplink':'ens3','public_key':'A'*44,'running':True,
       'clients':[]
    } if op=='list' else {'ok':True})
    return module


def test_login_dashboard_csrf_and_cookie(tmp_path,monkeypatch):
    module=create_app(tmp_path,monkeypatch)
    client=TestClient(module.app)
    assert client.get('/',follow_redirects=False).status_code==307
    assert client.get('/health').json()['ok']
    assert client.post('/login',data={'password':'badpassword'}).status_code==200
    response=client.post('/login',data={'password':'testpassword1234'},follow_redirects=False)
    assert response.status_code==303
    assert 'httponly' in response.headers['set-cookie'].lower()
    dashboard=client.get('/')
    assert 'Обзор инфраструктуры' in dashboard.text
    assert '/servers/awg0/overview' in dashboard.text
    assert dashboard.headers['Cache-Control']=='no-store'
    assert client.post('/client',data={'name':'new', 'csrf':'invalid'}).status_code==403
    csrf=client.get('/servers/awg0/clients').text.split('name="csrf" value="')[1].split('"')[0]
    assert client.post('/client',data={'name':'new','csrf':csrf},follow_redirects=False).status_code==303


def test_language_switch_persists_and_translates(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    client = TestClient(module.app)
    ru_login = client.get('/login')
    assert '<html lang="ru">' in ru_login.text
    assert 'Вход администратора' in ru_login.text
    assert client.get('/assets/panel.css').status_code == 200
    assert 'stats-grid' in client.get('/assets/panel.css').text

    switched = client.get('/lang/en?next=%2Flogin', follow_redirects=False)
    assert switched.status_code == 303
    assert switched.headers['location'] == '/login'
    assert 'awg31_lang=en' in switched.headers['set-cookie']
    assert 'max-age=31536000' in switched.headers['set-cookie'].lower()
    en_login = client.get('/login')
    assert '<html lang="en">' in en_login.text
    assert 'Administrator sign in' in en_login.text
    assert 'Sign in' in en_login.text
    assert client.post('/login', data={'password': 'incorrect'}).text.find('Incorrect password') >= 0

    client.post('/login', data={'password': 'testpassword1234'})
    dashboard = client.get('/')
    assert 'Server overview' in dashboard.text
    assert 'awg0' in dashboard.text
    assert '/servers/awg0/overview' in dashboard.text
    assert '/servers/awg0/settings' in client.get('/servers/awg0/overview').text
    assert 'lang="en"' in dashboard.text
    assert 'lang="ru"' not in dashboard.text
    ru_switch = client.get('/lang/ru', follow_redirects=False)
    assert ru_switch.status_code == 303
    assert 'Обзор инфраструктуры' in client.get('/').text


def test_language_switch_rejects_external_redirects(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    client = TestClient(module.app)
    response = client.get('/lang/en?next=%2F%2Fevil.example', follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/'
    assert client.get('/lang/fr').status_code == 404


def test_english_client_messages(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    module.ctl = lambda op, data=None: (
        {'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'clients':1,'running':True}]} if op=='servers' else
        {'name': data['name']} if op == 'add' else
        {'config': '[Interface]\nPrivateKey = example'} if op == 'download' else
        {'interface': 'awg0', 'subnet': '10.77.10.0/24', 'port': 45678,
         'mtu': 1380, 'endpoint': 'vpn.example.net', 'dns': '1.1.1.1',
         'mode': 'full', 'running': True,
         'clients': [{'name': 'KLIN', 'ip': '10.77.10.2', 'enabled': True, 'stats': {}}]}
        if op == 'list' else {'ok': True})
    client = TestClient(module.app)
    client.get('/lang/en')
    client.post('/login', data={'password': 'testpassword1234'})
    dashboard = client.get('/servers/awg0/clients')
    assert 'KLIN' in dashboard.text
    assert 'No handshake yet' in dashboard.text
    assert 'Disable' in dashboard.text
    assert 'Delete' in dashboard.text
    detail = client.get('/client/KLIN')
    assert 'Download .conf' in detail.text
    assert 'Save QR' in detail.text
    assert 'Keep them confidential' in detail.text


def test_live_traffic_endpoint_requires_auth_and_omits_secrets(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    module.ctl = lambda op, data=None: ({'servers':[{'interface':'awg0','subnet':'10.77.10.0/24','port':45678,'clients':1,'running':True}]} if op=='servers' else {
        'running': True, 'subnet': '10.77.10.0/24', 'port': 45678,
        'mtu': 1380, 'mode': 'full', 'endpoint': '10.10.20.29',
        'dns': '1.1.1.1', 'interface': 'awg0',
        'private_key': 'SECRET-PRIVATE-KEY',
        'clients': [{'name': 'KLIN', 'ip': '10.77.10.2', 'enabled': True,
                     'private_key': 'SECRET-CLIENT-KEY',
                     'stats': {'received': 1024, 'sent': 8192, 'handshake': 0}}],
    })
    client = TestClient(module.app)
    assert client.get('/api/traffic').status_code == 401
    client.post('/login', data={'password': 'testpassword1234'})
    result = client.get('/api/traffic')
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    assert result.json() == {'rx': 1024, 'tx': 8192, 'connected': 0, 'clients': 1, 'running': True}
    assert 'SECRET' not in result.text
    ui = client.get('/')
    assert '/assets/panel.js?v=0.9.2' in ui.text
    assert '/assets/md3.css?v=0.9.2' in ui.text
    assert 'md-sys-color-primary' in client.get('/assets/md3.css').text
    assert 'data-confirm=' in client.get('/servers/awg0/clients').text
    assert 'client-search' in client.get('/servers/awg0/clients').text
    assert 'Content-Security-Policy' in ui.headers
    assert "script-src 'self'" in ui.headers['Content-Security-Policy']
    js = client.get('/assets/panel.js')
    assert js.status_code == 200
    assert 'traffic-chart' in js.text
    assert 'stats-grid' in client.get('/assets/panel.css').text


def test_login_layout_desktop_and_mobile_markup(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    client = TestClient(module.app)
    response = client.get('/login')
    assert response.status_code == 200
    assert 'class="shell shell-auth"' in response.text
    assert 'class="main main-login"' in response.text
    assert 'class="card login-card"' in response.text
    assert 'class="login-overview"' in response.text
    assert 'grid-template-columns:minmax(0,1.1fr) minmax(370px,440px)' in client.get('/assets/md3.css').text
    assert 'grid-template-columns:minmax(0,1fr);max-width:470px' in client.get('/assets/md3.css').text
    assert '/assets/md3.css?v=0.9.2' in response.text
    assert 'type="password"' in response.text
    assert 'autocomplete="current-password"' in response.text
    assert 'class="sidebar"' not in response.text


def test_login_layout_language_and_error(tmp_path, monkeypatch):
    module = create_app(tmp_path, monkeypatch)
    client = TestClient(module.app)
    assert 'Доступ к консоли' in client.get('/login').text
    response = client.post('/login', data={'password':'invalid-password'})
    assert 'Неверный пароль' in response.text
    assert 'class="shell shell-auth"' in response.text
    client.get('/lang/en?next=%2Flogin')
    assert 'Console access' in client.get('/login').text

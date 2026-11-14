"""Telegram bot: access control, the menus, the narrow controller allowlist and notifications.

The bot is driven with real Telegram update objects; the controller is an
in-memory model that refuses every command missing from the bot's sudo rule,
exactly as sudo does on a server.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
bot_module = SourceFileLoader('awg31bot_test', str(ROOT / 'src/awg31bot.py')).load_module()
ADMIN, STRANGER = 111222333, 999888777
TOKEN = '123456789:' + 'A' * 35


def sudo_list(name):
    script = f'. {ROOT}/scripts/sudoers.sh; printf "%s\\n" "${{{name}[@]}}"'
    return set(subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True).stdout.split())


BOT_ALLOWED = sudo_list('AWG31_BOT_SUDO_COMMANDS')


class FakeApi:
    def __init__(self):
        self.calls, self.files = [], []

    def call(self, method, http_timeout=30, **params):
        self.calls.append((method, params))
        return {}

    def send_file(self, method, field, chat_id, filename, content, caption):
        self.files.append((method, chat_id, filename, content, caption))

    def texts(self):
        return [p['text'] for m, p in self.calls if m in ('sendMessage', 'editMessageText')]

    def buttons(self):
        for method, params in reversed(self.calls):
            if params.get('reply_markup'):
                return [b['callback_data'] for row in params['reply_markup']['inline_keyboard'] for b in row]
        return []


class FakeController:
    """What `sudo awg31mgr` does for the user awgbot."""

    def __init__(self):
        self.running = {'awg0': True}
        self.clients = {'awg0': {'alice': self.new_client('10.8.0.2')}}
        self.audit, self.log, self.backups = [], [], []
        self.module_ok, self.panel = True, 'active'

    @staticmethod
    def new_client(ip):
        return {'ip': ip, 'enabled': True, 'expires_at': '', 'traffic_limit_bytes': 0, 'used_bytes': 0,
                'disabled_reason': '', 'comment': '', 'config_stale': False, 'telegram_id': '', 'owner_export': False,
                'stats': {'handshake': 0, 'received': 0, 'sent': 0}}

    def __call__(self, command, data=None):
        self.log.append((command, data))
        if command not in BOT_ALLOWED:
            raise bot_module.BotError('controller error (not permitted or unavailable)')
        data = data or {}
        iface = data.get('interface', 'awg0')
        if command == 'servers':
            return {'servers': [{'interface': i, 'running': r, 'subnet': '10.8.0.0/24', 'port': 51820, 'mode': 'full',
                                 'clients': len(self.clients[i])} for i, r in self.running.items()]}
        if command == 'list':
            return {'clients': [{'name': n, **c} for n, c in self.clients[iface].items()]}
        if command == 'add':
            self.clients[iface][data['name']] = self.new_client('10.8.0.9')
            return {'name': data['name'], 'ip': '10.8.0.9', 'config': '[Interface]\n'}
        if command == 'download':
            return {'name': data['name'], 'config': f"[Interface]\nPrivateKey = secret-of-{data['name']}\n"}
        if command in ('enable', 'disable'):
            self.clients[iface][data['name']]['enabled'] = command == 'enable'
            return {'ok': True}
        if command == 'delete':
            del self.clients[iface][data['name']]
            return {'ok': True}
        if command == 'client-policy':
            self.clients[iface][data['name']].update({k: v for k, v in data.items() if k not in ('interface', 'name')})
            return {'ok': True}
        if command.startswith('server-'):
            self.running[iface] = command != 'server-stop'
            return {'ok': True}
        if command == 'diagnostics':
            return {'kernel': {'ok': True, 'output': '6.8.0'}, 'panel': {'ok': self.panel == 'active', 'output': self.panel},
                    'loaded_module': {'ok': self.module_ok, 'output': '1.0.0' if self.module_ok else 'not loaded'}}
        if command == 'backup-create':
            name = f'awg31-20260101T00000{len(self.backups)}Z-aaaaaaaaaa.tar.gz'
            self.backups.insert(0, {'name': name, 'size': 2048})
            self.audit.append({'timestamp': self.stamp(), 'event': 'backup_created', 'target': name})
            return {'ok': True, 'name': name, 'size': 2048}
        if command == 'backup-list':
            return {'backups': self.backups}
        if command == 'audit':
            self.audit.append({'timestamp': self.stamp(), **data})
            return {'ok': True}
        if command == 'audit-list':
            return {'entries': self.audit[-100:]}
        raise AssertionError(command)

    def stamp(self):
        return f'2026-01-01T00:00:{len(self.audit):02d}.000000+00:00'

    def commands(self):
        return [c for c, _ in self.log]


@pytest.fixture
def env(tmp_path):
    api, controller, now = FakeApi(), FakeController(), [1_780_000_000.0]
    config = {'token': TOKEN, 'admins': {ADMIN}, 'lang': 'en', 'api_base': 'https://api.telegram.org',
              'notify': {'server': True, 'clients': True, 'security': True, 'backups': True}}
    bot = bot_module.Bot(config, api=api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: now[0])
    return bot, api, controller, now


def message(text, user=ADMIN, chat_type='private'):
    return {'update_id': 1, 'message': {'message_id': 5, 'text': text, 'from': {'id': user},
                                        'chat': {'id': user if chat_type == 'private' else -100, 'type': chat_type}}}


def press(data, user=ADMIN, chat_type='private'):
    return {'update_id': 2, 'callback_query': {'id': 'q', 'data': data, 'from': {'id': user},
                                               'message': {'message_id': 7, 'chat': {'id': user, 'type': chat_type}}}}


def test_strangers_and_group_chats_get_no_answer_and_change_nothing(env):
    bot, api, controller, _ = env
    bot.handle_update(message('/start', user=STRANGER))
    bot.handle_update(press('s', user=STRANGER))
    bot.handle_update(press('cy:awg0:alice:del', user=STRANGER))
    bot.handle_update(message('/status', chat_type='group'))
    bot.handle_update(press('m', chat_type='supergroup'))
    assert api.calls == [] and api.files == []
    # The only cost of a stranger is one cached, read-only lookup of client owners.
    assert controller.commands() in ([], ['servers', 'list'])
    assert 'alice' in controller.clients['awg0']


def test_administrator_gets_the_menu(env):
    bot, api, _, _ = env
    bot.handle_update(message('/start'))
    assert 'AmneziaWG 3.1 Console' in api.texts()[-1]
    assert {'s', 'cl', 'st', 'bk', 'h'} <= set(api.buttons())


def test_creating_a_client_sends_file_and_qr_and_is_audited(env):
    bot, api, controller, _ = env
    bot.handle_update(press('add:awg0'))
    assert 'add' not in controller.commands()
    bot.handle_update(message('bob-phone'))
    assert 'bob-phone' in controller.clients['awg0']
    kinds = [(method, name) for method, _, name, _, _ in api.files]
    assert kinds == [('sendDocument', 'bob-phone.conf'), ('sendPhoto', 'bob-phone-qr.png')]
    assert b'PrivateKey' in api.files[0][3] and api.files[1][3].startswith(b'\x89PNG')
    assert all(chat == ADMIN for _, chat, _, _, _ in api.files)
    # Handing out a configuration is recorded, so the panel can later tell when it went stale.
    assert ('download', {'interface': 'awg0', 'name': 'bob-phone', 'mark': True}) in controller.log
    assert controller.audit[-1] == {'timestamp': controller.audit[-1]['timestamp'], 'event': 'client_added',
                                    'target': f'awg0/bob-phone (telegram {ADMIN})'}
    # The name prompt is finished: the next text is not taken for another client.
    bot.handle_update(message('second'))
    assert 'second' not in controller.clients['awg0']


@pytest.mark.parametrize('name', ['', 'has space', 'кириллица', '-dash', 'a' * 33, 'x;rm -rf /', '<b>bold</b>'])
def test_bad_client_names_never_reach_the_controller(env, name):
    bot, api, controller, _ = env
    bot.handle_update(press('add:awg0'))
    bot.handle_update(message(name or ' '))
    assert 'add' not in controller.commands()


def test_delete_needs_a_second_press(env):
    bot, api, controller, _ = env
    bot.handle_update(press('ca:awg0:alice:del'))
    assert 'alice' in controller.clients['awg0'] and 'cy:awg0:alice:del' in api.buttons()
    bot.handle_update(press('cy:awg0:alice:del'))
    assert 'alice' not in controller.clients['awg0']
    assert controller.audit[-1]['event'] == 'client_deleted'


def test_stop_and_restart_need_confirmation_but_start_does_not(env):
    bot, api, controller, _ = env
    bot.handle_update(press('sa:awg0:stop'))
    assert controller.running['awg0'] and 'sy:awg0:stop' in api.buttons()
    bot.handle_update(press('sy:awg0:stop'))
    assert not controller.running['awg0']
    bot.handle_update(press('sa:awg0:start'))
    assert controller.running['awg0']
    assert [e['event'] for e in controller.audit] == ['server_stopped', 'server_started']


@pytest.mark.parametrize('data', ['s:awg0;id', 's:../etc', 'c:awg0:../../x', 'ca:awg0:alice:shell', 'sy:awg0:delete',
                                  'cy:awg0:alice:purge', 'ce:awg0:alice:99999', 'cq:awg0:alice:-5', 'zz', 'sa:awg100:stop'])
def test_forged_button_data_is_rejected(env, data):
    bot, api, controller, _ = env
    bot.handle_update(press(data))
    assert not {'delete', 'server-stop', 'server-restart', 'client-policy', 'add'} & set(controller.commands())
    assert 'bad request' in api.texts()[-1]


def test_the_bot_cannot_do_what_the_sudo_rule_withholds(env):
    """Even a bug in the bot cannot delete a server or restore a backup: sudo refuses."""
    panel = sudo_list('AWG31_SUDO_COMMANDS')
    withheld = {'server-delete', 'server-create', 'backup-restore', 'backup-export', 'backup-delete', 'password-change',
                'settings', 'profile-import', 'session-revoke', 'backup-policy-set', 'delete-batch', 'client-network'}
    # The one command only the bot has hands out archives that are already encrypted.
    assert BOT_ALLOWED - panel == {'backup-export-encrypted'} and not BOT_ALLOWED & withheld
    rule = subprocess.run(['bash', '-c', f'. {ROOT}/scripts/sudoers.sh; awg31_render_bot_sudoers'],
                          capture_output=True, text=True, check=True).stdout
    assert rule.startswith('awgbot ALL=(root) NOPASSWD: /usr/local/sbin/awg31mgr servers,')
    assert '*' not in rule and 'ALL\n' not in rule.split('NOPASSWD:')[1]
    bot, _, controller, _ = env
    for command in sorted(withheld):
        with pytest.raises(bot_module.BotError):
            controller(command, {'interface': 'awg0', 'confirm': 'awg0'})


def test_every_screen_uses_only_permitted_commands(env):
    bot, api, controller, _ = env
    for update in [message('/menu'), message('/servers'), message('/clients'), message('/status'), message('/backup'),
                   message('/help'), press('s:awg0'), press('cl:awg0:0'), press('c:awg0:alice'), press('ca:awg0:alice:conf'),
                   press('ca:awg0:alice:qr'), press('ca:awg0:alice:off'), press('ca:awg0:alice:on'), press('bky'),
                   press('sy:awg0:restart'), press('ce:awg0:alice:30'), press('cq:awg0:alice:50')]:
        bot.handle_update(update)
    bot.tick()
    assert set(controller.commands()) <= BOT_ALLOWED
    assert not any('Error' in text for text in api.texts()), api.texts()


def test_quota_and_expiry_by_button_and_by_text(env):
    bot, api, controller, _ = env
    alice = controller.clients['awg0']['alice']
    bot.handle_update(press('cq:awg0:alice:50'))
    assert alice['traffic_limit_bytes'] == 50 * 1024 ** 3
    bot.handle_update(press('ca:awg0:alice:quota'))
    bot.handle_update(message('1,5'))
    assert alice['traffic_limit_bytes'] == int(1.5 * 1024 ** 3)
    bot.handle_update(press('ca:awg0:alice:quota'))
    bot.handle_update(message('lots'))
    assert alice['traffic_limit_bytes'] == int(1.5 * 1024 ** 3) and 'GiB' in api.texts()[-1]
    bot.handle_update(press('ca:awg0:alice:exp'))
    bot.handle_update(message('2099-12-31'))
    assert alice['expires_at'] == '2099-12-31'
    bot.handle_update(press('ce:awg0:alice:0'))
    assert alice['expires_at'] == ''


def test_a_prompt_expires(env):
    bot, api, controller, now = env
    bot.handle_update(press('add:awg0'))
    now[0] += bot_module.PENDING_SECONDS + 1
    bot.handle_update(message('late'))
    assert 'late' not in controller.clients['awg0'] and 'timed out' in api.texts()[-1]


def test_client_text_is_escaped(env):
    bot, api, controller, _ = env
    controller.clients['awg0']['alice']['comment'] = '<a href="x">Tom & Jerry</a>'
    bot.handle_update(press('c:awg0:alice'))
    assert '&lt;a href=&quot;x&quot;&gt;Tom &amp; Jerry&lt;/a&gt;' in api.texts()[-1]


def notifications(api, start):
    return [p['text'] for m, p in api.calls[start:] if m == 'sendMessage']


def test_notifications_from_the_audit_log(env):
    bot, api, controller, _ = env
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'login_success', 'target': '198.51.100.7'})
    bot.tick()
    assert notifications(api, 0) == [], 'history must not be replayed on the first start'
    start = len(api.calls)
    for event, target in [('login_failed', '203.0.113.5'), ('login_failed', '203.0.113.6'), ('login_success', '198.51.100.7'),
                          ('password_changed', ''), ('client_disabled', 'awg0/alice (auto)'), ('client_disabled', 'awg0/bob'),
                          ('backup_created', 'awg31-x.tar.gz'), ('backup_failed', 'disk full'),
                          ('client_deleted', f'awg0/old (telegram {ADMIN})')]:
        controller.audit.append({'timestamp': controller.stamp(), 'event': event, 'target': target})
    bot.tick()
    sent = notifications(api, start)
    assert len(sent) == 6, sent
    assert 'Failed sign-in attempts to the web panel: 2' in sent[0] and '203.0.113.6' in sent[0]
    assert '198.51.100.7' in sent[1] and 'password was changed' in sent[2]
    assert 'awg0/alice' in sent[3] and 'automatically' in sent[3]
    assert 'awg31-x.tar.gz' in sent[4] and 'disk full' in sent[5]
    start = len(api.calls)
    bot.tick()
    assert notifications(api, start) == [], 'nothing is reported twice'


def test_own_backup_is_not_reported_back(env):
    bot, api, controller, _ = env
    bot.tick()
    bot.handle_update(press('bky'))
    assert 'Backup created' in api.texts()[-1]
    start = len(api.calls)
    bot.tick()
    assert notifications(api, start) == []


def test_server_module_and_panel_notifications(env):
    bot, api, controller, now = env
    bot.tick()
    start = len(api.calls)
    controller.running['awg0'] = False
    controller.module_ok, controller.panel = False, 'failed'
    bot.tick()
    sent = notifications(api, start)
    assert len(sent) == 3 and 'awg0' in sent[0] and 'kernel module' in sent[1] and 'web panel is down' in sent[2]
    start = len(api.calls)
    bot.tick()
    assert notifications(api, start) == [], 'a lasting problem is reported once'
    controller.running['awg0'] = True
    controller.module_ok, controller.panel = True, 'active'
    bot.tick()
    assert len(notifications(api, start)) == 3
    # Stopping a server from the bot itself is not news to the administrator.
    start = len(api.calls)
    bot.handle_update(press('sy:awg0:stop'))
    bot.tick()
    assert notifications(api, start) == []


def test_expiry_warning_is_sent_once(env):
    bot, api, controller, now = env
    from datetime import datetime, timedelta, timezone
    soon = (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(hours=30)).isoformat()
    controller.clients['awg0']['alice']['expires_at'] = soon
    controller.clients['awg0']['later'] = {**controller.new_client('10.8.0.3'),
                                           'expires_at': (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(days=30)).isoformat()}
    bot.tick()
    bot.tick()
    sent = notifications(api, 0)
    assert len(sent) == 1 and 'alice' in sent[0] and soon[:10] in sent[0]


def test_disabled_notification_groups_stay_silent(env):
    bot, api, controller, _ = env
    bot.config['notify'] = {'server': False, 'clients': False, 'security': False, 'backups': False}
    bot.tick()
    controller.running['awg0'] = False
    for event in ('login_success', 'login_failed', 'password_changed', 'backup_created'):
        controller.audit.append({'timestamp': controller.stamp(), 'event': event, 'target': 'x'})
    bot.tick()
    assert notifications(api, 0) == []


def test_state_survives_a_restart(env, tmp_path):
    bot, api, controller, now = env
    bot.tick()
    controller.audit.append({'timestamp': controller.stamp(), 'event': 'login_success', 'target': '198.51.100.7'})
    bot.tick()
    second_api = FakeApi()
    again = bot_module.Bot(bot.config, api=second_api, controller=controller, state_path=tmp_path / 'state.json', clock=lambda: now[0])
    again.tick()
    assert notifications(second_api, 0) == []


def test_config_and_dates():
    from datetime import datetime, timezone
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert bot_module.parse_expiry('31.12.2026', now) == '2026-12-31'
    assert bot_module.parse_expiry(' 2026-06-01 ', now) == '2026-06-01'
    for bad in ('31.05.2026', 'tomorrow', '2026-13-01', ''):
        with pytest.raises(ValueError):
            bot_module.parse_expiry(bad, now)
    with pytest.raises(ValueError):
        bot_module.Api('not-a-token')


def test_config_without_administrators_is_refused(tmp_path):
    path = tmp_path / 'telegram.json'
    path.write_text(json.dumps({'token': TOKEN, 'admins': []}))
    with pytest.raises(ValueError):
        bot_module.load_config(path)
    path.write_text(json.dumps({'token': TOKEN, 'admins': [ADMIN], 'lang': 'xx', 'notify': {'security': False}}))
    config = bot_module.load_config(path)
    assert config['admins'] == {ADMIN} and config['lang'] == 'ru'
    assert config['notify'] == {'server': True, 'clients': True, 'security': False, 'backups': True}


class TelegramStub(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        TelegramStub.seen.append((self.path, self.headers['Content-Type'], body))
        if self.path.endswith('/explode'):
            reply, status = {'ok': False, 'description': 'Bad Request: chat not found'}, 400
        else:
            reply, status = {'ok': True, 'result': {'username': 'awg31_test_bot'}}, 200
        payload = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def stub():
    TelegramStub.seen = []
    server = HTTPServer(('127.0.0.1', 0), TelegramStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()


def test_http_client_sends_json_and_multipart(stub):
    api = bot_module.Api(TOKEN, stub)
    assert api.call('getMe', none_is_dropped=None) == {'username': 'awg31_test_bot'}
    path, kind, body = TelegramStub.seen[-1]
    assert path == f'/bot{TOKEN}/getMe' and kind == 'application/json' and json.loads(body) == {}
    api.send_file('sendDocument', 'document', ADMIN, 'alice.conf', b'[Interface]\n', 'caption text')
    path, kind, body = TelegramStub.seen[-1]
    boundary = kind.split('boundary=')[1].encode()
    parts = body.split(b'--' + boundary)
    assert len(parts) == 5 and parts[-1].strip() == b'--'
    assert b'name="chat_id"\r\n\r\n' + str(ADMIN).encode() in parts[1]
    assert b'filename="alice.conf"' in parts[3] and parts[3].endswith(b'\r\n\r\n[Interface]\n\r\n')


def test_errors_never_contain_the_token(stub):
    with pytest.raises(bot_module.BotError) as failure:
        bot_module.Api(TOKEN, stub).call('explode')
    assert 'chat not found' in str(failure.value) and TOKEN not in str(failure.value)
    with pytest.raises(bot_module.BotError) as failure:
        bot_module.Api(TOKEN, 'http://127.0.0.1:9').call('getMe')
    assert TOKEN not in str(failure.value) and TOKEN.split(':')[1] not in str(failure.value)


def test_setup_helper_checks_a_token_over_stdin(stub):
    run = subprocess.run([sys.executable, str(ROOT / 'src/awg31bot.py'), 'check-token'], input=TOKEN + '\n', text=True,
                         capture_output=True, env={**os.environ, 'AWG31_TELEGRAM_API': stub, 'NO_PROXY': '*', 'no_proxy': '*'})
    assert run.returncode == 0 and run.stdout.strip() == 'awg31_test_bot'
    bad = subprocess.run([sys.executable, str(ROOT / 'src/awg31bot.py'), 'check-token'], input='garbage\n', text=True,
                         capture_output=True, env={**os.environ, 'AWG31_TELEGRAM_API': stub})
    assert bad.returncode == 1 and 'garbage' not in bad.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason='the manager refuses to run without root')
def test_failed_scheduled_backup_leaves_an_audit_record(tmp_path):
    policy = tmp_path / 'policy.json'
    policy.write_text(json.dumps({'frequency': 'daily', 'hour': 3, 'minute': 0, 'weekday': 0, 'retention_days': 30, 'max_copies': 20}))
    blocker = tmp_path / 'not-a-directory'
    blocker.write_text('x')
    env = {'PATH': os.environ['PATH'], 'AWG31_ROOT': str(tmp_path / 'root'), 'AWG31_BACKUP_DIR': str(blocker / 'full'),
           'AWG31_BACKUP_POLICY': str(policy), 'AWG31_AUDIT': str(tmp_path / 'audit.jsonl'),
           'AWG31_CONFIG_DIR': str(tmp_path / 'conf')}
    run = subprocess.run([sys.executable, str(ROOT / 'src/awg31mgr'), 'backup-run'], env=env, capture_output=True, text=True)
    assert run.returncode == 1
    records = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    assert records[-1]['event'] == 'backup_failed' and records[-1]['target']


OWNER = 555666777


def test_owner_sees_only_their_own_clients_and_nothing_else(env):
    bot, api, controller, now = env
    controller.clients['awg0']['alice'].update(telegram_id=str(OWNER), used_bytes=3 * 1024 ** 3,
                                               traffic_limit_bytes=10 * 1024 ** 3, expires_at='2030-05-01T23:59:59+00:00')
    controller.clients['awg0']['secret-boss'] = controller.new_client('10.8.0.7')
    bot.handle_update(message('/start', user=OWNER))
    text = api.texts()[-1]
    assert 'Your VPN' in text and 'alice' in text and '3.0 GiB of 10.0 GiB' in text and '2030-05-01' in text
    assert 'secret-boss' not in text and '10.8.0' not in text and 'awg0' not in text
    assert api.buttons() == ['mr:awg0:alice', 'me'] and api.files == []
    # Nothing an administrator can do is reachable for an owner, whatever they send.
    before = len(controller.log)
    now[0] += 10
    for update in [press('cy:awg0:alice:del', user=OWNER), message('/add evil', user=OWNER), press('sy:awg0:stop', user=OWNER),
                   press('ca:awg0:alice:conf', user=OWNER), press('cq:awg0:alice:0', user=OWNER), press('bky', user=OWNER)]:
        now[0] += 10
        bot.handle_update(update)
    assert set(c for c, _ in controller.log[before:]) <= {'servers', 'list'}
    assert 'alice' in controller.clients['awg0'] and controller.running['awg0'] and api.files == []
    assert controller.clients['awg0']['alice']['traffic_limit_bytes'] == 10 * 1024 ** 3
    assert all(p.get('chat_id') == OWNER for m, p in api.calls if m in ('sendMessage', 'editMessageText'))


def test_owner_requests_are_rate_limited_and_strangers_stay_cheap(env):
    bot, api, controller, now = env
    controller.clients['awg0']['alice']['telegram_id'] = str(OWNER)
    bot.handle_update(message('hi', user=OWNER))
    answers = len(api.calls)
    for _ in range(20):
        bot.handle_update(message('hi', user=OWNER))
    assert len(api.calls) == answers, 'a flood from one owner is answered once'
    calls = len(controller.log)
    for n in range(50):
        bot.handle_update(message('/start', user=STRANGER + n))
    assert len(controller.log) == calls and len(api.calls) == answers, 'strangers cause no controller calls and get no reply'
    bot.handle_update(message('hi', user=OWNER, chat_type='group'))
    assert len(api.calls) == answers


def test_admin_sets_and_clears_the_owner_from_the_bot(env):
    bot, api, controller, now = env
    bot.handle_update(press('ca:awg0:alice:tg'))
    bot.handle_update(message('@username'))
    assert controller.clients['awg0']['alice']['telegram_id'] == '' and 'numeric ID' in api.texts()[-1]
    bot.handle_update(message(str(OWNER)))
    assert controller.clients['awg0']['alice']['telegram_id'] == str(OWNER)
    assert f'Owner (Telegram ID): {OWNER}' in api.texts()[-1]
    bot.handle_update(message('/start', user=OWNER))
    assert 'Your VPN' in api.texts()[-1], 'the new owner is served at once, not after the cache expires'
    bot.handle_update(press('ca:awg0:alice:tg'))
    bot.handle_update(message('0'))
    assert controller.clients['awg0']['alice']['telegram_id'] == ''
    now[0] += 10
    count = len(api.calls)
    bot.handle_update(message('/start', user=OWNER))
    assert len(api.calls) == count, 'a removed owner gets no answer any more'


def test_owner_is_warned_about_expiry_even_when_admin_notifications_are_off(env):
    bot, api, controller, now = env
    from datetime import datetime, timedelta, timezone
    bot.config['notify'] = {'server': False, 'clients': False, 'security': False, 'backups': False}
    soon = (datetime.fromtimestamp(now[0], timezone.utc) + timedelta(hours=20)).isoformat()
    controller.clients['awg0']['alice'].update(telegram_id=str(OWNER), expires_at=soon)
    bot.tick()
    bot.tick()
    sent = [p for m, p in api.calls if m == 'sendMessage']
    assert len(sent) == 1 and sent[0]['chat_id'] == OWNER and 'alice' in sent[0]['text'] and 'awg0' not in sent[0]['text']


def test_owner_gets_config_and_qr_only_with_the_switch_on(env):
    bot, api, controller, now = env
    alice = controller.clients['awg0']['alice']
    alice['telegram_id'] = str(OWNER)
    controller.clients['awg0']['other'] = {**controller.new_client('10.8.0.8'), 'owner_export': True, 'telegram_id': '424242'}
    bot.tick()
    bot.handle_update(message('/start', user=OWNER))
    assert api.buttons() == ['me'], 'no download buttons while the switch is off'
    now[0] += 10
    bot.handle_update(press('mc:awg0:alice', user=OWNER))
    now[0] += 10
    bot.handle_update(press('mq:awg0:other', user=OWNER))      # somebody else's client, export allowed there
    assert api.files == [] and 'download' not in controller.commands()

    bot.handle_update(press('ca:awg0:alice:xon'))              # the administrator turns the switch on
    assert alice['owner_export'] is True and 'may get the config' in api.texts()[-1]
    now[0] += 10
    bot.handle_update(message('/start', user=OWNER))
    assert api.buttons() == ['mc:awg0:alice', 'mq:awg0:alice', 'me']
    now[0] += 10
    bot.handle_update(press('mc:awg0:alice', user=OWNER))
    now[0] += 10
    bot.handle_update(press('mq:awg0:alice', user=OWNER))
    assert [(m, chat, name) for m, chat, name, _, _ in api.files] == [('sendDocument', OWNER, 'alice.conf'),
                                                                      ('sendPhoto', OWNER, 'alice-qr.png')]
    assert 'awg0' not in api.files[0][4]
    assert controller.audit[-1]['event'] == 'client_config_sent' and controller.audit[-1]['target'] == f'awg0/alice (owner {OWNER})'
    start = len(api.calls)
    bot.tick()
    told = [p for m, p in api.calls[start:] if m == 'sendMessage']
    assert len(told) == 2 and all(p['chat_id'] == ADMIN and 'awg0/alice' in p['text'] for p in told)

    for change in ({'enabled': False}, {'enabled': True, 'owner_export': False}, {'owner_export': True, 'telegram_id': '424242'}):
        alice.update(change)
        now[0] += 10
        bot.handle_update(press('mc:awg0:alice', user=OWNER))
    assert len(api.files) == 2, 'disabled client, switch off or another owner: nothing is sent'


def test_export_permission_does_not_pass_to_another_owner():
    ctl = SourceFileLoader('awg31ctl_owner', str(ROOT / 'src/awg31ctl')).load_module()
    old = {'comment': '', 'expires_at': '', 'traffic_limit_bytes': 0, 'telegram_id': '111222333', 'owner_export': 1}
    assert ctl.validate_policy({'comment': 'x'}, old)['owner_export'] == 1
    assert ctl.validate_policy({'telegram_id': '444555666'}, old)['owner_export'] == 0
    assert ctl.validate_policy({'telegram_id': '444555666', 'owner_export': True}, old)['owner_export'] == 1
    assert ctl.validate_policy({'telegram_id': ''}, old)['owner_export'] == 0
    assert ctl.validate_policy({'owner_export': True}, {})['owner_export'] == 0, 'no owner, nothing to allow'
    assert ctl.validate_policy({'owner_export': '1', 'telegram_id': '111222333'})['owner_export'] == 1
    assert ctl.validate_policy({'owner_export': False}, old)['owner_export'] == 0

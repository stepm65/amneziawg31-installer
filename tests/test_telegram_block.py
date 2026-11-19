"""0.13.0: the Telegram block of the panel — per-event switches, CPU/memory/disk thresholds,
a crontab schedule for the summary, the API server, switching the bot off, a new token and a test message.
"""
import json
import re
import time
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from test_password_guards import PASSWORD, admin, as_panel  # noqa: F401  (pytest fixture)
from test_telegram_bot import ADMIN, STRANGER, env, message, notifications  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
bot_module = SourceFileLoader('awg31bot_block', str(ROOT / 'src/awg31bot.py')).load_module()


def local(text):
    return time.strptime(text, '%Y-%m-%d %H:%M')


# ------------------------------------------------------------------ one list of events everywhere
def test_bot_controller_and_panel_know_the_same_events(admin):
    module, _ = admin
    assert module.TELEGRAM_EVENTS == bot_module.EVENTS
    assert module.TELEGRAM_THRESHOLDS == bot_module.THRESHOLDS
    source = (ROOT / 'src/web.py').read_text()
    groups = re.search(r'TG_EVENT_GROUPS = \((.*?)\n\)', source, re.S).group(1)
    shown = {event: group for group, events in re.findall(r"\('(\w+)', '[\w-]+', \(([^)]*)\)\)", groups)
             for event in re.findall(r"'(\w+)'", events)}
    assert shown == bot_module.EVENTS
    for event in bot_module.EVENTS:
        assert f"'tg_e_{event}'" in source, f'a label for {event}'


# ------------------------------------------------------------------ crontab schedule
def test_crontab_schedule_is_read_like_cron(admin):
    module, _ = admin
    due = lambda expr, when: bot_module.cron_due(bot_module.cron_fields(expr), local(when))
    assert due('0 9 * * *', '2026-06-02 09:00') and not due('0 9 * * *', '2026-06-02 09:01')
    assert due('*/15 * * * *', '2026-06-02 13:45') and not due('*/15 * * * *', '2026-06-02 13:50')
    assert due('30 8 * * 1-5', '2026-06-05 08:30') and not due('30 8 * * 1-5', '2026-06-06 08:30'), 'Friday yes, Saturday no'
    assert due('0 9 * * 7', '2026-06-07 09:00') and due('0 9 * * 0', '2026-06-07 09:00'), 'both 0 and 7 are Sunday'
    assert due('0 */6 * * *', '2026-06-02 18:00') and not due('0 */6 * * *', '2026-06-02 19:00')
    # Day of month and weekday both given: either one is enough, as in cron.
    assert due('0 9 1 * 1', '2026-06-01 09:00') and due('0 9 1 * 1', '2026-06-08 09:00') and not due('0 9 1 * 1', '2026-06-09 09:00')
    assert due('@daily', '2026-06-02 09:00') and due('weekly', '2026-06-08 09:00')
    for good in ('0 9 * * *', '5,35 */2 1-15 1-12/2 1-5', '@hourly', 'daily'):
        bot_module.cron_fields(good)
        assert module.telegram_schedule(good) != 'off'
    for bad in ('0 9 * *', '60 9 * * *', '0 24 * * *', '0 9 0 * *', '0 9 * 13 *', '0 9 * * 8', '9-1 * * * *', '*/0 * * * *',
                'hourly', 'rm -rf / * * *'):
        with pytest.raises(ValueError):
            bot_module.cron_fields(bad)
        with pytest.raises(ValueError):
            module.telegram_schedule(bad)
    assert module.telegram_schedule('  0  9 * * 1 ') == '0 9 * * 1' and module.telegram_schedule('') == 'off'
    assert module.telegram_schedule('weekly') == '0 9 * * 1'


def test_summary_follows_the_schedule_and_names_the_period(env, monkeypatch):
    bot, api, controller, now = env
    monkeypatch.setenv('TZ', 'UTC')
    time.tzset()
    bot.config['digest'] = '0 */6 * * *'
    now[0] = datetime(2026, 6, 2, 5, 58, tzinfo=timezone.utc).timestamp()
    bot.tick()
    assert not [t for t in notifications(api, 0) if 'Digest' in t], 'switching on sends nothing at once'
    now[0] += 240                                   # 06:02: the 06:00 run was between two checks
    bot.tick()
    assert len([t for t in notifications(api, 0) if 'Digest' in t]) == 1
    now[0] += 6 * 3600
    start = len(api.calls)
    bot.tick()
    assert any('Digest for the last 6 h' in t for t in notifications(api, start))
    bot.config['digest'] = 'off'
    now[0] += 6 * 3600
    start = len(api.calls)
    bot.tick()
    assert not [t for t in notifications(api, start) if 'Digest' in t]
    assert bot.period_text(3600) == 'for the last hour' and bot.period_text(86400) == 'for the last day'
    assert bot.period_text(7 * 86400) == 'for the last week' and bot.period_text(3 * 86400) == 'for the last 3 days'


# ------------------------------------------------------------------ per-event switches and thresholds
def test_each_event_has_its_own_switch(env):
    bot, api, controller, _ = env
    bot.config['events'] = {key: key == 'login_failed' for key in bot_module.EVENTS}
    bot.tick()
    for event in ('login_success', 'login_failed', 'password_changed'):
        controller.audit.append({'timestamp': controller.stamp(), 'event': event, 'target': '198.51.100.7'})
    bot.tick()
    sent = notifications(api, 0)
    assert len(sent) == 1 and 'Failed sign-in' in sent[0]


def test_disk_and_memory_above_the_threshold_are_told_once_and_when_they_pass(env):
    bot, api, controller, _ = env
    G = 1024 ** 3
    sample = {'cpu': (1000, 900), 'memory': (8 * G, 4 * G), 'disk': (100 * G, 20 * G)}
    bot.host_sample = lambda: dict(sample)
    bot.config['thresholds'] = {'cpu': 90, 'memory': 90, 'disk': 75}
    bot.tick()
    sent = notifications(api, 0)
    assert len(sent) == 1 and 'disk is 80% full (threshold 75%), 20.0 GiB free' in sent[0]
    bot.tick()
    assert len(notifications(api, 0)) == 1, 'said once'
    sample['disk'] = (100 * G, 28 * G)              # 72 %: below the line but within the 5 % margin
    bot.tick()
    assert len(notifications(api, 0)) == 1
    sample['disk'] = (100 * G, 40 * G)
    bot.tick()
    assert 'below the threshold again: 60% full' in notifications(api, 0)[-1]
    sample['memory'] = (8 * G, int(0.4 * G))
    bot.tick()
    assert 'Memory use is 95%' in notifications(api, 0)[-1]


def test_cpu_must_stay_high_for_three_minutes(env):
    bot, api, controller, _ = env
    counters = [0, 0]
    load = [0.97]

    def sample():
        counters[0] += 1000
        counters[1] += int(1000 * (1 - load[0]))
        return {'cpu': tuple(counters)}
    bot.host_sample = sample
    for _ in range(3):
        bot.tick()
    assert notifications(api, 0) == [], 'the first reading only sets the baseline; two high minutes are not enough'
    bot.tick()
    assert 'CPU load has been 97% for 3 min' in notifications(api, 0)[-1]
    load[0] = 0.2
    bot.tick()
    assert 'CPU load is below the threshold again: 20%' in notifications(api, 0)[-1]
    bot.config['events'] = {key: key != 'cpu' for key in bot_module.EVENTS}
    load[0] = 0.99
    for _ in range(5):
        bot.tick()
    assert 'CPU load has been' not in notifications(api, 0)[-1]


def test_older_settings_keep_their_meaning(tmp_path):
    path = tmp_path / 'telegram.json'
    path.write_text(json.dumps({'token': '123456789:' + 'A' * 35, 'admins': [ADMIN], 'digest': 'weekly',
                                'notify': {'server': False, 'backups': False}}))
    config = bot_module.load_config(path)
    assert config['digest'] == '0 9 * * 1' and config['backup_file'] is False
    assert not config['events']['server_state'] and not config['events']['backup_created'] and config['events']['cpu']
    path.write_text(json.dumps({'token': '123456789:' + 'A' * 35, 'admins': [ADMIN], 'digest': 'every day please',
                                'thresholds': {'cpu': 'x', 'disk': 3, 'memory': 500}}))
    config = bot_module.load_config(path)
    assert config['digest'] == 'off' and config['thresholds'] == {'cpu': 90, 'memory': 100, 'disk': 10}


# ------------------------------------------------------------------ /id
def test_anyone_learns_their_own_id_in_a_private_chat(env):
    bot, api, controller, now = env
    bot.handle_update(message('/id', user=STRANGER))
    bot.handle_update(message('/id', user=STRANGER))
    bot.handle_update(message('/id', user=STRANGER, chat_type='group'))
    sent = [p for m, p in api.calls if m == 'sendMessage']
    assert len(sent) == 1 and sent[0]['chat_id'] == STRANGER and str(STRANGER) in sent[0]['text']
    now[0] += 31
    bot.handle_update(message('/id', user=STRANGER))
    assert len([m for m, _ in api.calls if m == 'sendMessage']) == 2
    bot.handle_update(message('/start', user=STRANGER))
    assert len([m for m, _ in api.calls if m == 'sendMessage']) == 2, 'nothing else for strangers'


# ------------------------------------------------------------------ controller
def connected(tmp_path, **extra):
    path = tmp_path / 'bot/telegram.json'
    path.write_text(json.dumps({'token': '123456789:' + 'T' * 35, 'admins': [ADMIN], 'viewers': [], 'lang': 'ru',
                                'notify': {'server': True, 'clients': True, 'security': True, 'backups': True}, **extra}))
    path.chmod(0o640)
    return path


def test_events_thresholds_schedule_and_switching_off_are_saved(admin, monkeypatch):
    module, tmp = admin
    path = connected(tmp)
    commands = []
    monkeypatch.setattr(module.subprocess, 'run', lambda cmd, **k: commands.append(cmd) or
                        type('P', (), {'returncode': 0, 'stdout': '', 'stderr': ''})())
    as_panel(monkeypatch)
    module.telegram_set({'admins': str(ADMIN), 'digest': '30 8 * * 1-5', 'enabled': False, 'backup_file': True,
                         'events': {'login': True, 'cpu': True, 'unknown': True}, 'thresholds': {'cpu': '85'}})
    saved = json.loads(path.read_text())
    assert saved['digest'] == '30 8 * * 1-5' and saved['backup_file'] is True
    assert {k for k, v in saved['events'].items() if v} == {'login', 'cpu'} and 'unknown' not in saved['events']
    assert saved['thresholds'] == {'cpu': 85, 'memory': 90, 'disk': 90}
    assert saved['notify'] == {'server': False, 'clients': False, 'security': True, 'backups': False}
    assert ['systemctl', 'disable', '--now', 'awg31-bot.service'] in commands
    commands.clear()
    module.telegram_set({'admins': str(ADMIN), 'enabled': True})
    assert ['systemctl', 'enable', 'awg31-bot.service'] in commands and ['systemctl', 'restart', 'awg31-bot.service'] in commands
    for bad in ({'thresholds': {'disk': 5}}, {'thresholds': {'cpu': 'many'}}, {'digest': '0 25 * * *'}, {'events': ['login']}):
        with pytest.raises(ValueError):
            module.telegram_set({'admins': str(ADMIN), **bad})
    status = module.telegram_status()
    assert status['events']['login'] and not status['events']['server_state'] and status['thresholds']['cpu'] == 85
    assert status['digest'] == '30 8 * * 1-5' and status['api_base'] == 'https://api.telegram.org'
    assert '123456789:' not in json.dumps(status)


def test_api_server_and_new_token_need_the_password(admin, monkeypatch):
    module, tmp = admin
    path = connected(tmp)
    as_panel(monkeypatch)
    with pytest.raises(ValueError, match='password'):
        module.telegram_set({'admins': str(ADMIN), 'api_base': 'https://bot-api.example.net'})
    for bad in ('http://bot-api.example.net', 'https://example.net/?x=1', 'ftp://example.net', 'https://exa mple.net'):
        with pytest.raises(ValueError):
            module.telegram_set({'admins': str(ADMIN), 'api_base': bad, 'password': PASSWORD})
    module.telegram_set({'admins': str(ADMIN), 'api_base': 'https://bot-api.example.net/', 'password': PASSWORD})
    assert json.loads(path.read_text())['api_base'] == 'https://bot-api.example.net'
    module.telegram_set({'admins': str(ADMIN), 'api_base': 'https://bot-api.example.net'})      # unchanged: no password
    module.telegram_set({'admins': str(ADMIN), 'api_base': '', 'password': PASSWORD})
    assert 'api_base' not in json.loads(path.read_text()), 'empty means api.telegram.org again'
    module.telegram_set({'admins': str(ADMIN), 'api_base': 'http://127.0.0.1:8081', 'password': PASSWORD})

    new_token = '987654321:' + 'N' * 35
    seen = {}

    def probe(cmd, **kwargs):
        if cmd[-1] == 'check-token':
            seen.update(cmd=cmd, input=kwargs.get('input'), api=kwargs.get('env', {}).get('AWG31_TELEGRAM_API'))
        return type('P', (), {'returncode': 0, 'stdout': 'new_bot\n', 'stderr': ''})()
    monkeypatch.setattr(module.subprocess, 'run', probe)
    (tmp / 'probe.py').write_text('# stands in for the installed copy of awg31bot.py\n')
    monkeypatch.setattr(module, 'TELEGRAM_PROBE', tmp / 'probe.py')
    with pytest.raises(ValueError, match='password'):
        module.telegram_set({'admins': str(ADMIN), 'token': new_token})
    module.telegram_set({'admins': str(ADMIN), 'token': new_token, 'password': PASSWORD})
    saved = json.loads(path.read_text())
    assert saved['token'] == new_token and saved['username'] == 'new_bot' and saved['admins'] == [ADMIN]
    assert seen['input'] == new_token + '\n' and new_token not in ' '.join(seen['cmd']), 'the token goes on stdin only'
    assert seen['api'] == 'http://127.0.0.1:8081', 'checked against the configured API server'


def test_the_disconnect_request_reaches_the_controller_with_its_password():
    # awg31mgr drops stdin for operations listed as having no payload; the password must not be dropped.
    source = (ROOT / 'src/awg31mgr').read_text()
    no_payload = set(re.findall(r"'([a-z0-9-]+)'", re.search(r'no_payload = \{(.*?)\}', source, re.S).group(1)))
    for op in ('telegram-connect', 'telegram-disconnect', 'telegram-set', 'backup-encryption-set', 'backup-encryption-change',
               'totp-enable', 'totp-disable'):
        assert op not in no_payload, op
    assert 'telegram-test' in no_payload

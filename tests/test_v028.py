"""0.28: access schedules, access requests through the bot, messages to client owners."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from test_password_guards import admin  # noqa: F401  (pytest fixture)
from test_workflows import ui, token  # noqa: F401  (pytest fixture)
from test_telegram_bot import sudo_list, env, message, press, bot_module, ADMIN, STRANGER  # noqa: F401
from test_v015 import ctl, db, row  # noqa: F401  (pytest fixture)

ROOT = Path(__file__).resolve().parents[1]
WEEKDAYS = {'days': [0, 1, 2, 3, 4], 'from': '07:00', 'to': '22:00', 'tz': 'Europe/Moscow'}


# ------------------------------------------------------------------ schedule rules
def at(text):
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def test_schedule_is_validated_and_stored_compactly():
    stored = ctl.valid_schedule({**WEEKDAYS, 'days': [4, 0, 1, 1, 2, 3]})
    assert json.loads(stored) == WEEKDAYS and ' ' not in stored
    assert ctl.valid_schedule('') == '' and ctl.valid_schedule({}) == ''
    for bad, why in (({**WEEKDAYS, 'days': []}, 'день'), ({**WEEKDAYS, 'days': [7]}, 'день'), ({**WEEKDAYS, 'from': '7:00'}, 'ЧЧ:ММ'),
                     ({**WEEKDAYS, 'to': '07:00'}, 'совпадают'), ({**WEEKDAYS, 'tz': 'Mars/Olympus'}, 'пояс'),
                     ({**WEEKDAYS, 'tz': '../etc/passwd'}, 'пояс'), ('not json', 'формат'), ([1, 2], 'формат')):
        with pytest.raises(ValueError, match=why):
            ctl.valid_schedule(bad)


@pytest.mark.parametrize('moment, expected', [
    ('2026-11-30T06:59:00+03:00', False),      # Monday before 07:00 Moscow
    ('2026-11-30T07:00:00+03:00', True),
    ('2026-11-30T21:59:00+03:00', True),
    ('2026-11-30T22:00:00+03:00', False),
    ('2026-11-28T12:00:00+03:00', False),      # Saturday
    ('2026-11-30T04:30:00+00:00', True),       # 07:30 in Moscow, written in UTC
])
def test_a_day_window_in_its_time_zone(moment, expected):
    assert ctl.schedule_open(json.dumps(WEEKDAYS), at(moment)) is expected


@pytest.mark.parametrize('moment, expected', [
    ('2026-11-27T23:00:00+00:00', True),       # Friday night: the window starts on Friday
    ('2026-11-28T06:59:00+00:00', True),       # ...and runs into Saturday morning
    ('2026-11-28T07:00:00+00:00', False),
    ('2026-11-28T23:00:00+00:00', False),      # Saturday night is not a start day
    ('2026-11-30T05:00:00+00:00', False),      # Monday morning: Sunday did not start one
])
def test_a_window_over_midnight(moment, expected):
    rule = json.dumps({'days': [4], 'from': '22:00', 'to': '07:00', 'tz': 'UTC'})
    assert ctl.schedule_open(rule, at(moment)) is expected


def test_the_sampler_switches_clients_by_their_schedule(db):
    con, call, _ = db
    call(ctl.clients_add, {'name': 'kid'})
    call(ctl.clients_add, {'name': 'adult'})
    call(ctl.client_policy_update, {'name': 'kid', 'schedule': WEEKDAYS})
    assert row(con, 'kid')['schedule'] and row(con, 'adult')['schedule'] == ''
    result = ctl.sample_usage(con, now=at('2026-11-28T12:00:00+03:00'))            # Saturday
    assert result['schedule_disabled'] == ['kid'] and row(con, 'kid')['disabled_reason'] == 'schedule' and row(con, 'adult')['enabled']
    result = ctl.sample_usage(con, now=at('2026-11-30T08:00:00+03:00'))            # Monday morning
    assert result['schedule_enabled'] == ['kid'] and row(con, 'kid')['enabled'] and row(con, 'kid')['disabled_reason'] == ''
    # Expired meanwhile: the schedule does not bring it back.
    ctl.sample_usage(con, now=at('2026-11-30T23:00:00+03:00'))
    con.execute("UPDATE clients SET expires_at='2026-11-01T00:00:00+00:00' WHERE name='kid'"); con.commit()
    assert ctl.sample_usage(con, now=at('2026-12-01T08:00:00+03:00'))['schedule_enabled'] == []
    # Removing the schedule brings back a client it stopped.
    con.execute("UPDATE clients SET expires_at='', enabled=0, disabled_reason='schedule' WHERE name='kid'"); con.commit()
    call(ctl.client_policy_update, {'name': 'kid', 'schedule': ''})
    assert row(con, 'kid')['enabled'] == 1 and row(con, 'kid')['schedule'] == ''
    # Other policy edits keep the schedule.
    call(ctl.client_policy_update, {'name': 'adult', 'schedule': WEEKDAYS})
    call(ctl.client_policy_update, {'name': 'adult', 'comment': 'x'})
    assert json.loads(row(con, 'adult')['schedule']) == WEEKDAYS
    assert json.loads(call(lambda c: ctl.clients_action(c, 'download'), {'name': 'adult'})['schedule']) == WEEKDAYS   # the client page
    assert 'schedule' in ctl.MOVE_KEEP


def test_client_page_edits_the_schedule(ui):
    app, client, calls = ui
    page = client.get('/servers/awg0/clients/alpha')
    assert 'Расписание доступа' in page.text and 'name="schedule_day" value="6"' in page.text and 'name="schedule_tz"' in page.text
    client.post('/servers/awg0/clients/alpha/policy', data={
        'csrf': token(page), 'comment': '', 'expires_at': '', 'quota_gib': '0', 'schedule_present': '1', 'schedule_on': '1',
        'schedule_day': ['0', '2', '9'], 'schedule_from': '08:00', 'schedule_to': '20:30', 'schedule_tz': 'Europe/Moscow'})
    sent = [d for op, d in calls if op == 'client-policy'][-1]
    assert sent['schedule'] == {'days': [0, 2], 'from': '08:00', 'to': '20:30', 'tz': 'Europe/Moscow'}
    client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(page), 'comment': '', 'expires_at': '', 'quota_gib': '0',
                                                             'schedule_present': '1'})
    assert [d for op, d in calls if op == 'client-policy'][-1]['schedule'] == ''
    client.post('/servers/awg0/clients/alpha/policy', data={'csrf': token(page), 'comment': '', 'expires_at': '', 'quota_gib': '0'})
    assert 'schedule' not in [d for op, d in calls if op == 'client-policy'][-1]       # an older form leaves it alone
    assert app.schedule_text(json.dumps(WEEKDAYS), 'ru') == 'Пн–Пт 07:00–22:00 (Europe/Moscow)'
    assert app.schedule_text(json.dumps({**WEEKDAYS, 'days': list(range(7))}), 'en').startswith('daily')


# ------------------------------------------------------------------ access requests
def with_requests(bot, **settings):
    bot.config['requests'] = bot_module.request_settings({'enabled': True, **settings})


def test_strangers_are_still_ignored_unless_requests_are_on(env):
    bot, api, controller, now = env
    bot.handle_update(message('/start', user=STRANGER))
    bot.handle_update(press('rq', user=STRANGER))
    assert api.calls == [] and 'add' not in controller.commands()


def test_a_request_goes_to_the_administrator_and_makes_a_client(env):
    bot, api, controller, now = env
    with_requests(bot, server='awg0', days=30, quota_gb=50, speed=20)
    original = controller.__call__

    def add_with_owner(command, data=None):
        result = original(command, data)
        if command == 'add':
            controller.clients['awg0'][data['name']].update(telegram_id=data['telegram_id'], owner_export=data['owner_export'])
        return result
    bot.ctl = add_with_owner
    sender = {'update_id': 3, 'message': {'message_id': 5, 'text': 'hi', 'chat': {'id': STRANGER, 'type': 'private'},
                                          'from': {'id': STRANGER, 'first_name': 'Анна', 'username': 'anna_k'}}}
    bot.handle_update(sender)
    assert 'ask for access' in api.texts()[-1] and api.buttons() == ['rq']
    bot.handle_update(sender)
    assert len(api.calls) == 1                                    # answered once in 30 seconds
    query = {'update_id': 4, 'callback_query': {'id': 'q', 'data': 'rq', 'from': {'id': STRANGER, 'first_name': 'Анна', 'username': 'anna_k'},
                                                'message': {'message_id': 7, 'chat': {'id': STRANGER, 'type': 'private'}}}}
    bot.handle_update(query)
    to_admin = [p for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == ADMIN][-1]
    assert 'Access request' in to_admin['text'] and '@anna_k' in to_admin['text'] and str(STRANGER) in to_admin['text']
    assert [b['callback_data'] for b in to_admin['reply_markup']['inline_keyboard'][0]] == [f'ra:{STRANGER}', f'rj:{STRANGER}']
    assert 'went to the administrator' in api.texts()[-1]
    bot.handle_update(query)
    assert 'is with the administrator' in api.texts()[-1]
    assert json.loads(bot.state_path.read_text())['requests'][str(STRANGER)]['status'] == 'pending'
    bot.handle_update(press(f'ra:{STRANGER}'))
    added = [d for c, d in controller.log if c == 'add'][-1]
    assert added['name'] == 'tg-anna_k' and added['telegram_id'] == str(STRANGER) and added['traffic_limit_bytes'] == 50 * 1024 ** 3
    assert added['speed_limit_mbit'] == added['speed_up_mbit'] == 20 and added['expires_at'] and added['owner_export'] is True
    told = [p['text'] for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == STRANGER]
    assert any('Access granted' in x for x in told) and any('tg-anna_k' in x for x in told)
    assert any(a['event'] == 'access_request_granted' for a in controller.audit)
    bot.handle_update(press(f'ra:{STRANGER}'))
    assert 'already answered' in api.texts()[-1]                  # one client per request


def test_a_refusal_waits_a_week(env):
    bot, api, controller, now = env
    with_requests(bot)
    bot.handle_update(press('rq', user=STRANGER))
    bot.handle_update(press(f'rj:{STRANGER}'))
    assert any(p['chat_id'] == STRANGER and 'refused' in p['text'] for m, p in api.calls if m == 'sendMessage')
    now[0] += 60
    bot.handle_update(press('rq', user=STRANGER))
    assert 'ask again in a week' in api.texts()[-1] and 'add' not in controller.commands()
    now[0] += 8 * 86400
    bot.handle_update(press('rq', user=STRANGER))
    assert 'went to the administrator' in api.texts()[-1]


def test_too_many_waiting_requests(env):
    bot, api, controller, now = env
    with_requests(bot)
    for n in range(bot_module.REQUEST_PENDING_MAX):
        bot.handle_update(press('rq', user=500000000 + n))
    bot.handle_update(press('rq', user=STRANGER))
    assert 'Too many requests' in api.texts()[-1]


def test_a_viewer_cannot_grant(env):
    bot, api, controller, now = env
    with_requests(bot)
    bot.config['viewers'] = {444555666}
    bot.handle_update(press('rq', user=STRANGER))
    assert not any(p['chat_id'] == 444555666 for m, p in api.calls if m == 'sendMessage')       # only administrators are asked
    bot.handle_update(press(f'ra:{STRANGER}', user=444555666))
    assert 'add' not in controller.commands()


# ------------------------------------------------------------------ messages to owners
def test_the_administrator_messages_every_owner(env):
    bot, api, controller, now = env
    controller.clients['awg0']['alice'].update(telegram_id='700000001')
    controller.clients['awg0']['bob'] = {**controller.new_client('10.8.0.3'), 'telegram_id': '700000002'}
    bot.sleep = lambda seconds: None
    bot.handle_update(press('bc'))
    assert 'client owners (2 now)' in api.texts()[-1]
    bot.handle_update(message('Сервер <b>будет</b> недоступен в воскресенье'))
    assert 'Owners who get the message: 2' in api.texts()[-1] and '&lt;b&gt;будет' in api.texts()[-1]
    bot.handle_update(press('bs:button'))
    sent = [p for m, p in api.calls if m == 'sendMessage' and p['chat_id'] in (700000001, 700000002)]
    assert len(sent) == 2 and all('&lt;b&gt;будет&lt;/b&gt;' in p['text'] for p in sent)
    assert sent[0]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'me'
    assert 'sent: 2 of 2' in api.texts()[-1] and controller.audit[-1]['event'] == 'owners_broadcast'
    bot.handle_update(press('bs:plain'))
    assert 'timed out' in api.texts()[-1] and len([p for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == 700000001]) == 1
    bot.handle_update(press('bc'))
    bot.handle_update(message('x' * 1001))
    assert 'at most 1000' in api.texts()[-1]


def test_a_message_queued_by_the_panel(env, tmp_path, monkeypatch):
    bot, api, controller, now = env
    queue = tmp_path / 'broadcast.json'
    monkeypatch.setattr(bot_module, 'BROADCAST', queue)
    controller.clients['awg0']['alice'].update(telegram_id='700000001')
    bot.sleep = lambda seconds: None
    queue.write_text(json.dumps({'text': 'Новая конфигурация', 'button': False}))
    bot.queued_broadcast()
    assert not queue.exists()
    to_owner = [p for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == 700000001]
    assert len(to_owner) == 1 and 'Новая конфигурация' in to_owner[0]['text'] and to_owner[0].get('reply_markup') is None
    assert any('sent: 1 of 1' in p['text'] for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == ADMIN)
    assert controller.audit[-1]['target'] == '1/1 owners (panel)'
    bot.queued_broadcast()                                         # nothing queued: nothing happens
    assert len([p for m, p in api.calls if m == 'sendMessage' and p['chat_id'] == 700000001]) == 1


# ------------------------------------------------------------------ root side and panel
def test_admin_validates_request_settings_and_queues_messages(admin, monkeypatch):
    module, tmp = admin
    assert module.telegram_requests({'enabled': True, 'server': 'awg1', 'days': '30', 'quota_gb': 5, 'speed': 0}) == \
        {'enabled': True, 'server': 'awg1', 'days': 30, 'quota_gb': 5, 'speed': 0, 'export': True}
    for bad in ({'server': '../x'}, {'days': -1}, {'quota_gb': 'many'}, {'speed': 10001}, 'on'):
        with pytest.raises(ValueError):
            module.telegram_requests(bad)
    queue = tmp / 'bot-state/broadcast.json'
    monkeypatch.setenv('AWG31_BOT_BROADCAST', str(queue))
    with pytest.raises(ValueError, match='not connected'):
        module.telegram_broadcast({'text': 'hi'})
    (tmp / 'bot/telegram.json').write_text(json.dumps({'token': 't', 'admins': [1]}))
    for bad in ({'text': ''}, {'text': 'x' * 1001}, {'text': 'a\x00b'}):
        with pytest.raises(ValueError):
            module.telegram_broadcast(bad)
    assert module.telegram_broadcast({'text': ' Работы в воскресенье \r\n с 10:00 ', 'button': True})['queued']
    assert json.loads(queue.read_text()) == {'text': 'Работы в воскресенье \n с 10:00', 'button': True}
    assert oct(queue.stat().st_mode & 0o777) == '0o600'
    with pytest.raises(ValueError, match='not been sent'):
        module.telegram_broadcast({'text': 'again'})


def test_telegram_tab_has_requests_and_messages(ui):
    app, client, calls = ui
    original = app.ctl

    def fake(op, data=None):
        if op == 'telegram-status':
            return {'configured': True, 'active': 'active', 'enabled': True, 'username': 'awgbot', 'admins': [1], 'viewers': [], 'lang': 'ru',
                    'notify': {}, 'events': {}, 'thresholds': {}, 'digest': 'off',
                    'requests': {'enabled': True, 'server': 'awg0', 'days': 30, 'quota_gb': 0, 'speed': 0, 'export': True}}
        if op == 'owners': return {'owners': [{'id': 'o1', 'telegram_id': '700000001'}, {'id': 'o2', 'telegram_id': ''}]}
        if op in ('telegram-set', 'telegram-broadcast'):
            calls.append((op, dict(data))); return {'ok': True}
        return original(op, data)
    app.ctl = fake
    page = client.get('/maintenance?tab=telegram')
    assert 'Запросы доступа' in page.text and 'Сообщение владельцам' in page.text and '(сейчас их 1)' in page.text
    assert 'name="days" min="0" max="3650" value="30"' in page.text
    client.post('/maintenance/telegram/requests', data={'csrf': token(page), 'enabled': '1', 'server': 'awg0', 'days': '7',
                                                        'quota_gb': '10', 'speed': '', 'export': '1'})
    assert [c for c in calls if c[0] == 'telegram-set'][-1] == ('telegram-set', {'enabled': True, 'requests': {
        'enabled': True, 'server': 'awg0', 'days': '7', 'quota_gb': '10', 'speed': '0', 'export': True}})
    done = client.post('/maintenance/telegram/broadcast', data={'csrf': token(page), 'text': 'Привет', 'button': '1'}, follow_redirects=False)
    assert done.headers['location'].endswith('done=broadcast_queued#tg-broadcast')
    assert [c for c in calls if c[0] == 'telegram-broadcast'][-1] == ('telegram-broadcast', {'text': 'Привет', 'button': True})


def test_new_operations_are_wired():
    panel, bot = set(sudo_list('AWG31_SUDO_COMMANDS')), set(sudo_list('AWG31_BOT_SUDO_COMMANDS'))
    assert 'telegram-broadcast' in panel and 'telegram-broadcast' not in bot
    admin_source = (ROOT / 'src/awg31admin.py').read_text()
    for event in ('access_request_granted', 'access_request_refused', 'owners_broadcast'):
        assert f"'{event}'" in admin_source

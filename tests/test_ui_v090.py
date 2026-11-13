"""v0.9 UX regression tests: server navigation has one clear scope and no selector."""
from test_v080_workflows import ui


def test_server_sidebar_is_a_direct_link_list(ui):
    _, client, calls = ui
    home = client.get('/').text
    assert 'id="server-picker"' not in home
    assert '<select id="server-picker"' not in home
    assert home.count('class="instance-nav-link') == 2
    assert 'href="/servers/awg0/overview"' in home
    assert 'href="/servers/awg1/overview"' in home
    assert 'ЭКЗЕМПЛЯРЫ' in home
    assert 'ТЕКУЩИЙ СЕРВЕР' not in home
    assert 'class="instance-dash-grid"' in home
    assert home.count('class="instance-dashboard"') == 2
    assert 'class="fleet-stat"' not in home
    assert 'class="health-card"' not in home
    assert '2 серверов' in home and '2/2' in home
    assert "f'2" not in home


def test_scoped_tabs_server_identity_and_separate_settings(ui):
    _, client, calls = ui
    p0 = client.get('/servers/awg0/settings').text
    p1 = client.get('/servers/awg1/settings').text
    assert 'СЕРВЕРЫ / AWG1' in p1
    assert '10.77.20.0/24' in p1 and '51821' in p1
    assert '10.77.10.0/24' in p0
    assert p1.count('<a class="server-tab') == 4
    for segment in ('overview', 'clients', 'monitoring', 'settings'):
        assert f'href="/servers/awg1/{segment}"' in p1
    assert p1.count('class="server-tab active"') == 1
    assert '<h2>Подключение</h2>' in p1
    assert 'action="/servers/awg1/settings"' in p1
    assert 'id="server-picker"' not in p1
    assert 'class="scope-banner"' not in p1
    assert 'class="stats-grid"' not in client.get('/servers/awg1/overview').text
    assert 'class="server-home-grid"' in client.get('/servers/awg1/overview').text


def test_diagnostics_is_one_grouped_list_and_privileged_actions_unchanged(ui):
    _, client, calls = ui
    html = client.get('/maintenance?tab=diagnostics').text
    assert '<h1>Обслуживание</h1>' in html
    assert '<h2>Диагностика</h2>' in html
    assert 'class="diag-list"' in html
    assert 'class="diag-row ' in html
    assert 'class="health-card ' not in html
    assert 'class="health-grid"' not in html
    assert 'href="/maintenance?tab=backups"' in html
    assert 'name="csrf"' in client.get('/maintenance?tab=backups').text
    assert 'action="/maintenance/backup/delete"' in client.get('/maintenance?tab=backups').text


def test_css_mobile_layout_and_no_selector_js(ui):
    _, client, calls = ui
    css = client.get('/assets/md3.css').text
    js = client.get('/assets/panel.js').text
    assert 'grid-template-columns:248px minmax(0,1fr)' in css
    assert '.server-tabs' in css and '.instance-nav-list' in css
    assert '.diag-row' in css and '.instance-dashboard' in css
    assert '@media(max-width:650px)' in css
    assert 'server-picker' not in js
    assert 'nav-open' in js
    home = client.get('/').text
    assert 'md3.css?v=0.9.3' in home
    assert 'panel.js?v=0.9.3' in home
    english = client.get('/lang/en?next=%2Fservers%2Fawg1%2Fsettings')
    assert english.status_code == 200
    text = english.text
    assert 'Settings' in text and 'Clients' in text

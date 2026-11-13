"""Console usability and destructive operations regression tests."""
from pathlib import Path
from test_v080_workflows import ui, token


def test_primary_server_deletion_is_explicit_and_backed_up(ui):
    _, client, calls = ui
    listing = client.get('/servers')
    assert 'action="/server/awg0/delete"' in listing.text
    assert 'name="confirm" value="awg0"' in listing.text
    assert 'баз' in listing.text
    assert client.post('/server/awg0/delete', data={'csrf':'invalid'}).status_code == 403
    response = client.post('/server/awg0/delete',
                           data={'csrf': token(listing), 'confirm':'awg0'},
                           follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/servers'
    assert ('server-delete', {'interface':'awg0','confirm':'awg0'}) in calls


def test_bulk_client_delete_scoped_and_validated(ui):
    _, client, calls = ui
    page = client.get('/servers/awg1/clients')
    assert 'id="select-all-peers"' in page.text
    assert 'id="bulk-delete-button"' in page.text
    assert 'name="names" value="beta"' in page.text
    csrf = token(page)
    assert client.post('/servers/awg1/clients/bulk-delete',
                       data={'csrf':csrf,'names':'beta'},follow_redirects=False).status_code == 303
    assert ('delete-batch',{'names':['beta'],'interface':'awg1'}) in calls
    assert not any(op == 'delete-batch' and d['interface'] == 'awg0' for op,d in calls)
    assert client.post('/servers/awg1/clients/bulk-delete',
                       data={'csrf':csrf,'names':'../../etc/passwd'}).status_code == 422
    assert client.post('/servers/awg1/clients/bulk-delete',
                       data={'csrf':csrf}).status_code == 422
    assert client.post('/servers/awg1/clients/bulk-delete',
                       data={'csrf':'bad','names':'beta'}).status_code == 403


def test_settings_visible_confirm_and_redirect(ui):
    _, client, calls = ui
    page = client.get('/servers/awg1/settings')
    assert '<section class="advanced-box" id="obfuscation">' in page.text
    assert '<details class="advanced-box"' not in page.text
    assert 'id="obfuscation-fields"' in page.text
    response = client.post('/servers/awg1/settings',
                           data={'csrf':token(page),'endpoint':'vpn.example.test','port':'51821'},
                           follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/servers/awg1/settings?saved=1'
    saved = client.get(response.headers['location']).text
    assert 'class="settings-success"' in saved
    assert 'Настройки сохранены' in saved
    overview = client.get('/servers/awg1/overview').text
    assert 'action="/server/awg1/stop"' in overview
    js = client.get('/assets/panel.js').text
    assert 'modal.showModal()' in js
    assert 'window.confirm(' not in js


def test_russian_host_metric_labels(ui):
    _, client, _ = ui
    root = client.get('/').text
    for label in ('Процессор','Память','Подкачка','Диск','СЕТЬ / СОЕДИНЕНИЯ'):
        assert label in root

"""Console usability and destructive operations regression tests."""
from pathlib import Path
from test_workflows import ui, token


def test_primary_server_deletion_is_explicit_and_backed_up(ui):
    _, client, calls = ui
    listing = client.get('/servers')
    assert 'action="/server/awg0/delete"' in listing.text
    # The name must be typed by the admin; it is no longer pre-filled in a hidden field.
    assert 'name="confirm" value="awg0"' not in listing.text
    assert 'type="text" name="confirm" required' in listing.text and 'pattern="awg0"' in listing.text
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


def test_client_expiry_edit_preserves_time_and_submits_single_value(ui):
    app, client, calls = ui
    original = app.ctl
    expiry = '2028-02-29T22:30:00+00:00'
    def with_expiry(op, data=None):
        result = original(op, data)
        if op == 'download':
            result['expires_at'] = expiry
        return result
    app.ctl = with_expiry
    page = client.get('/servers/awg1/clients/beta')
    assert page.status_code == 200
    assert page.text.count('name="expires_at"') == 1
    assert f'value="{expiry}"' in page.text
    assert 'data-expiry-open="policy-expires"' in page.text
    assert 'type="date"' not in page.text
    response = client.post('/servers/awg1/clients/beta/policy',
                           data={'csrf':token(page), 'expires_at':expiry, 'comment':'NAS'},
                           follow_redirects=False)
    assert response.status_code == 303
    assert ('client-policy', {'name':'beta', 'expires_at':expiry, 'comment':'NAS',
                             'traffic_limit_bytes':0, 'interface':'awg1'}) in calls

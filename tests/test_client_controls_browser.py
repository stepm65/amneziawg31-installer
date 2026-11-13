"""Browser regressions. Install playwright and its Chromium browser to run."""
import os
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from test_workflows import ui

playwright = pytest.importorskip('playwright.sync_api')


@pytest.fixture
def page(ui):
    app, client, _ = ui
    original = app.ctl
    def fake(op, data=None):
        result = original(op, data)
        if op == 'list':
            result['clients'].append({'name':'offline', 'ip':'10.77.10.3',
                                      'enabled':False, 'stats':{}})
        if op == 'download':
            result['expires_at'] = '2028-02-29T22:30:00+00:00'
        return result
    app.ctl = fake
    paths = ['/servers/awg0/clients', '/servers/awg0/clients/alpha',
             '/assets/panel.js', '/assets/panel.css', '/assets/md3.css']
    responses = {path: client.get(path) for path in paths}
    anonymous = TestClient(app.app)
    responses['/login'] = anonymous.get('/login')
    assert all(response.status_code == 200 for response in responses.values())
    def serve(route):
        path = urlsplit(route.request.url).path
        if path not in responses:
            route.abort()
            return
        response = responses[path]
        route.fulfill(body=response.content, content_type=response.headers['content-type'])
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(
            executable_path=os.environ.get('AWG31_TEST_BROWSER_EXECUTABLE'))
        context = browser.new_context(locale='en-US', viewport={'width':1440, 'height':1000})
        context.route('http://panel.test/**', serve)
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        yield page
        browser.close()
        assert errors == []


@pytest.mark.parametrize(('path', 'field_id'), [
    ('/servers/awg0/clients', 'new-expires'),
    ('/servers/awg0/clients/alpha', 'policy-expires'),
])
def test_single_expiry_input_calendar_and_manual_entry(page, path, field_id):
    page.goto('http://panel.test' + path)
    field = page.locator('#' + field_id)
    button = page.locator('[data-expiry-open="' + field_id + '"]')
    calendar = page.locator('#' + field_id + '-calendar')
    assert page.locator('.expiry-input input').count() == 1
    field.fill('29.02.2028')
    button.click()
    assert 'февраль' in calendar.locator('strong').inner_text().lower()
    calendar.locator('[data-day="29"]').press('ArrowRight')
    assert calendar.is_visible()
    assert 'март' in calendar.locator('strong').inner_text().lower()
    page.keyboard.press('Enter')
    assert field.input_value() == '01.03.2028'
    assert not calendar.is_visible()
    field.fill('2028-02-29T22:30:00+00:00')
    button.click()
    page.keyboard.press('Escape')
    assert field.input_value() == '2028-02-29T22:30:00+00:00'
    button.click()
    calendar.locator('[data-clear]').click()
    assert field.input_value() == ''
    field.fill('31.02.2028')
    button.click()
    assert calendar.locator('[aria-pressed="true"]').count() == 0
    calendar.locator('[data-today]').click()
    assert len(field.input_value()) == 10
    page.set_viewport_size({'width':390, 'height':844})
    button.click()
    bounds = calendar.bounding_box()
    assert 0 <= bounds['x'] and bounds['x'] + bounds['width'] <= 390
    calendar.locator('[data-day="15"]').click()
    assert field.input_value().startswith('15.')
    assert field.evaluate("field => new FormData(field.form).getAll('expires_at')") == [field.input_value()]


def test_status_checkboxes_combine_with_search(page):
    page.goto('http://panel.test/servers/awg0/clients')
    active = page.get_by_role('checkbox', name='Активные', exact=True)
    disabled = page.get_by_role('checkbox', name='Отключённые', exact=True)
    search = page.locator('#client-search')
    rows = page.locator('tr.client-row:visible')
    assert active.is_checked() and disabled.is_checked()
    assert rows.count() == 2
    disabled.uncheck()
    assert rows.count() == 1
    assert rows.get_attribute('data-name') == 'alpha'
    search.fill('offline')
    assert rows.count() == 0
    disabled.check()
    assert rows.get_attribute('data-name') == 'offline'
    active.uncheck()
    search.fill('10.77.10.3')
    assert rows.count() == 1
    disabled.uncheck()
    assert rows.count() == 0
    active.check()
    disabled.check()
    search.fill('')
    assert rows.count() == 2


def test_api_session_expiry_opens_login_page(page):
    page.route('**/servers/awg0/api/traffic',
               lambda route: route.fulfill(status=401, json={'detail':'Требуется вход'}))
    page.goto('http://panel.test/servers/awg0/clients')
    page.evaluate("fetch('/servers/awg0/api/traffic')")
    page.wait_for_url('**/login?next=%2Fservers%2Fawg0%2Fclients')


@pytest.mark.parametrize('width', [1600, 1024, 390])
def test_client_detail_alignment_and_visible_network_settings(page, width):
    page.set_viewport_size({'width':width, 'height':1000})
    page.goto('http://panel.test/servers/awg0/clients/alpha')
    assert page.locator('#edit-routed-subnets').is_visible()
    assert page.locator('.client-options form > button[type="submit"]').is_visible()
    cards = page.locator('.client-detail > .detail-card')
    assert cards.count() == 3
    bounds = [card.bounding_box() for card in cards.all()]
    assert max(box['x'] for box in bounds) - min(box['x'] for box in bounds) < 1
    assert max(box['width'] for box in bounds) - min(box['width'] for box in bounds) < 1
    gaps = [bounds[i+1]['y'] - bounds[i]['y'] - bounds[i]['height'] for i in range(2)]
    assert abs(gaps[0] - gaps[1]) < 1
    inputs = page.locator('.client-policy input:not([type="hidden"])')
    input_bounds = [field.bounding_box() for field in inputs.all()]
    assert max(box['width'] for box in input_bounds) - min(box['width'] for box in input_bounds) < 1
    assert max(box['height'] for box in input_bounds) - min(box['height'] for box in input_bounds) < 1
    if width == 1600:
        assert max(box['y'] for box in input_bounds) - min(box['y'] for box in input_bounds) < 1

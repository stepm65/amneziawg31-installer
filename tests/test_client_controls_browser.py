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
    if field_id == 'new-expires':
        page.locator('[data-modal-open="add-client-modal"]').click()      # the new-client form is a dialog
    field = page.locator('#' + field_id)
    button = page.locator('[data-expiry-open="' + field_id + '"]')
    calendar = page.locator('#' + field_id + '-calendar')
    # One text field per expiry control (the list page also has the batch form's control).
    assert field.locator('xpath=ancestor::*[contains(@class,"expiry-input")][1]').locator('input').count() == 1
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


def test_state_chips_combine_with_search_and_show_a_count(page):
    page.goto('http://panel.test/servers/awg0/clients')
    chip = lambda name: page.locator(f'[data-client-chip="{name}"]')
    search = page.locator('#client-search')
    rows = page.locator('tr.client-row:visible')
    count = page.locator('#client-count')
    assert chip('all').get_attribute('aria-pressed') == 'true'
    assert [chip(x).locator('b').inner_text() for x in ('all', 'online', 'offline', 'disabled')] == ['2', '0', '1', '1']
    assert rows.count() == 2
    chip('disabled').click()                       # switched off: only "offline" (its access is off)
    assert rows.count() == 1 and rows.get_attribute('data-name') == 'offline'
    assert chip('disabled').get_attribute('aria-pressed') == 'true' and chip('all').get_attribute('aria-pressed') == 'false'
    assert count.inner_text() == '1 из 2 клиентов'
    search.fill('alpha')                           # a chip and a search narrow together
    assert rows.count() == 0
    chip('offline').click()                        # enabled but no tunnel right now: alpha
    assert rows.count() == 1 and rows.get_attribute('data-name') == 'alpha'
    chip('online').click()
    assert rows.count() == 0
    chip('all').click()
    search.fill('')
    assert rows.count() == 2 and count.inner_text() == '2 клиентов'


def test_bulk_bar_appears_with_a_selection_and_clears(page):
    page.goto('http://panel.test/servers/awg0/clients')
    bar = page.locator('#bulk-toolbar')
    assert not bar.is_visible()
    page.locator('.peer-select').first.check()
    assert bar.is_visible() and 'Выбрано: 1' in page.locator('#bulk-selection-count').inner_text()
    assert page.locator('#bulk-delete-button').is_enabled()
    page.locator('#bulk-clear').click()
    assert not bar.is_visible() and not page.locator('.peer-select').first.is_checked()


def test_row_menu_opens_inside_the_viewport_and_closes_on_escape(page):
    page.goto('http://panel.test/servers/awg0/clients')
    menu = page.locator('details.row-menu').first
    menu.locator('summary').click()
    assert menu.get_attribute('open') is not None
    box = menu.locator('.row-menu-list').bounding_box()
    viewport = page.viewport_size
    assert box['x'] >= 0 and box['y'] >= 0 and box['x'] + box['width'] <= viewport['width']
    assert [x.inner_text().strip() for x in menu.locator('.row-menu-list > a, .row-menu-list button').all()][0] == 'Конфигурация'
    page.keyboard.press('Escape')
    assert menu.get_attribute('open') is None


@pytest.mark.parametrize('width', [1280, 1366])
def test_row_menu_is_reachable_on_laptop_screens_and_survives_a_scroll(page, width):
    """On 1280-1366 px the table used to push the menu column out of view, and the page scroll
    that opening a menu near the bottom edge causes used to close it again."""
    page.set_viewport_size({'width': width, 'height': 700})
    page.goto('http://panel.test/servers/awg0/clients')
    wrap = page.locator('#clients .table-scroll').bounding_box()
    summary = page.locator('details.row-menu summary').last
    box = summary.bounding_box()
    assert box['x'] + box['width'] <= wrap['x'] + wrap['width'] + 0.5
    assert page.evaluate("() => { const w = document.querySelector('#clients .table-scroll'); return w.scrollWidth <= w.clientWidth; }")
    summary.click()
    menu = page.locator('details.row-menu').last
    assert menu.get_attribute('open') is not None
    page.mouse.wheel(0, 60)
    page.wait_for_timeout(200)
    assert menu.get_attribute('open') is not None
    anchor = summary.bounding_box()
    listed = menu.locator('.row-menu-list').bounding_box()
    assert abs(listed['y'] - (anchor['y'] + anchor['height'] + 6)) < 2 or abs(listed['y'] + listed['height'] + 6 - anchor['y']) < 2


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
    assert cards.count() >= 3
    bounds = [card.bounding_box() for card in cards.all()]
    assert max(box['x'] for box in bounds) - min(box['x'] for box in bounds) < 1
    assert max(box['width'] for box in bounds) - min(box['width'] for box in bounds) < 1
    gaps = [bounds[i+1]['y'] - bounds[i]['y'] - bounds[i]['height'] for i in range(len(bounds) - 1)]
    assert max(gaps) - min(gaps) < 1
    inputs = page.locator('.client-policy input:not([type="hidden"]):not([type="checkbox"])')
    input_bounds = [field.bounding_box() for field in inputs.all()]
    assert max(box['width'] for box in input_bounds) - min(box['width'] for box in input_bounds) < 1
    assert max(box['height'] for box in input_bounds) - min(box['height'] for box in input_bounds) < 1
    if width == 1600:
        # The policy fields stand in a grid: a wide screen fits them in a couple of rows.
        assert len({round(box['y']) for box in input_bounds}) <= 3


def test_template_blocks_go_in_with_their_own_comments(page):
    """A template adds only the blocks whose commands are missing, each with its comment, set apart by a blank line."""
    import web
    texts = {key: web.extra_template_text(key, lambda k: web.tr('ru', k)) for key, _ in web.EXTRA_TEMPLATES}
    page.goto('http://panel.test/servers/awg0/clients/alpha')
    block = page.locator('[data-extra-lines]').first
    area = block.locator('textarea')
    def insert(key):
        index = [k for k, _ in web.EXTRA_TEMPLATES].index(key)
        block.locator('.extra-menu-item').nth(index).evaluate('button => button.click()')
        return area.input_value()
    area.evaluate('(el, value) => { el.value = value; }', texts['nat'])
    assert insert('gateway') == texts['gateway'], 'NAT is not repeated; the other blocks come with their comments'
    assert insert('gateway') == texts['gateway'] and insert('mss') == texts['gateway'], 'nothing new: nothing added'
    area.evaluate('el => { el.value = "PostUp = echo mine"; }')
    assert insert('mss') == 'PostUp = echo mine\n\n' + texts['mss']

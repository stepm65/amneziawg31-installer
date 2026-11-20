"""Every page of the panel in a real browser, under the panel's own Content-Security-Policy:
an inline style or script, a blocked resource or a JavaScript error fails the test.
Install playwright and its Chromium (python -m playwright install chromium) to run it."""
import os
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from test_workflows import ui  # noqa: F401  (pytest fixture)

playwright = pytest.importorskip('playwright.sync_api')

PAGES = ['/', '/servers', '/servers/awg0/overview', '/servers/awg0/clients', '/servers/awg0/clients/alpha',
         '/servers/awg0/monitoring', '/servers/awg0/settings',
         *(f'/maintenance?tab={tab}' for tab in ('diagnostics', 'backups', 'restore', 'profiles', 'security',
                                                  'telegram', 'logs', 'audit', 'system', 'update'))]
KEEP_HEADERS = ('content-type', 'content-security-policy', 'cache-control')


def serve_from(client):
    def handler(route):
        parts = urlsplit(route.request.url)
        if route.request.method != 'GET':
            route.abort()
            return
        reply = client.get(parts.path + (f'?{parts.query}' if parts.query else ''), follow_redirects=False)
        headers = {k: v for k, v in reply.headers.items() if k.lower() in KEEP_HEADERS}
        if reply.status_code in (301, 302, 303, 307):
            headers['location'] = reply.headers['location']
        route.fulfill(status=reply.status_code, headers=headers, body=reply.content)
    return handler


def crawl(client, paths, viewport):
    problems = []
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=os.environ.get('AWG31_TEST_BROWSER_EXECUTABLE'))
        context = browser.new_context(locale='ru-RU', viewport=viewport)
        context.route('http://panel.test/**', serve_from(client))
        # Anything leaving the panel (a CDN, an analytics script) is a finding as well.
        context.route(lambda url: not url.startswith('http://panel.test/'), lambda route: (problems.append(f'external request {route.request.url}'), route.abort()))
        context.add_init_script("window.__csp=[];document.addEventListener('securitypolicyviolation',"
                                "e=>window.__csp.push(e.violatedDirective+' '+(e.blockedURI||'inline')+' '+(e.sourceFile||'')+':'+e.lineNumber));")
        page = context.new_page()
        current = {'path': ''}
        page.on('pageerror', lambda error: problems.append(f'{current["path"]}: JS error {error}'))
        page.on('console', lambda message: message.type == 'error' and problems.append(f'{current["path"]}: console {message.text}'))
        for path in paths:
            current['path'] = path
            reply = page.goto('http://panel.test' + path, wait_until='load')
            assert reply.status == 200, f'{path}: HTTP {reply.status}'
            page.wait_for_timeout(150)
            problems.extend(f'{path}: CSP {item}' for item in page.evaluate('window.__csp'))
        browser.close()
    return problems


def test_every_page_runs_clean_under_the_csp(ui):
    app, client, _ = ui
    problems = crawl(client, PAGES, {'width': 1440, 'height': 1000})
    anonymous = TestClient(app.app)
    problems += crawl(anonymous, ['/login'], {'width': 1440, 'height': 1000})
    assert problems == []


def test_phone_width_pages_run_clean(ui):
    app, client, _ = ui
    assert crawl(client, ['/', '/servers/awg0/clients', '/servers/awg0/clients/alpha', '/maintenance?tab=update'],
                 {'width': 390, 'height': 844}) == []

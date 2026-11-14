#!/usr/bin/env python3
"""A stand-in for api.telegram.org used by the installation smoke test.

POST /bot<token>/<method>   what the bot calls; every call is recorded
POST /_push                 queue one update for the next getUpdates
GET  /_calls                everything the bot has sent so far, as JSON
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
QUEUE, CALLS, NEXT_ID = [], [], [1]


class Handler(BaseHTTPRequestHandler):
    def reply(self, value):
        payload = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        try:
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass                      # the bot was stopped in the middle of a long poll

    def do_GET(self):
        with LOCK:
            self.reply(CALLS)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        if self.path == '/_push':
            with LOCK:
                update = json.loads(body)
                update['update_id'] = NEXT_ID[0]
                NEXT_ID[0] += 1
                QUEUE.append(update)
            return self.reply({'ok': True})
        method = self.path.rsplit('/', 1)[-1]
        if method == 'getUpdates':
            offset = int(json.loads(body).get('offset') or 0)
            deadline = time.time() + 3
            while True:
                with LOCK:
                    QUEUE[:] = [u for u in QUEUE if u['update_id'] >= offset]
                    pending = list(QUEUE)
                if pending or time.time() > deadline:
                    return self.reply({'ok': True, 'result': pending})
                time.sleep(0.2)
        text = body.decode('utf-8', 'replace') if 'multipart' in (self.headers.get('Content-Type') or '') else json.loads(body or b'{}')
        with LOCK:
            CALLS.append({'method': method, 'body': text})
        self.reply({'ok': True, 'result': {'username': 'awg31_smoke_bot', 'message_id': 1}})

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()

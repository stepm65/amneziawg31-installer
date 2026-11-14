"""How the panel and the bot reach the root controller.

First the control helper (awg31helper, a local socket); when it is not running
or not reachable yet, `sudo -n awg31mgr` exactly as before. Both paths grant the
same operations: the helper reads its permissions from the same sudo rules.
"""
import json
import os
import socket
import struct
import subprocess

SOCKET = os.environ.get('AWG31_HELPER_SOCKET', '/run/awg31/control.sock')
MANAGER = os.environ.get('AWG31_MGR_PATH', '/usr/local/sbin/awg31mgr')
MAX_REPLY = 96 * 1024 * 1024          # a backup export is up to ~27 MiB of base64


def _read_exact(connection, size):
    chunks, left = [], size
    while left:
        chunk = connection.recv(min(left, 1 << 20))
        if not chunk:
            raise ConnectionError('the control helper closed the connection')
        chunks.append(chunk)
        left -= len(chunk)
    return b''.join(chunks)


def call(command, text=None, timeout=35):
    """Run one controller operation; returns (returncode, stdout, stderr) like subprocess.run."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(SOCKET)
    except OSError:
        # Not installed, not started yet, or this process has not got the group yet.
        # Nothing was sent, so running the operation through sudo cannot run it twice.
        connection.close()
        return via_sudo(command, text, timeout)
    try:
        body = json.dumps({'op': command, 'input': text}).encode('utf-8')
        connection.sendall(struct.pack('>I', len(body)) + body)
        size = struct.unpack('>I', _read_exact(connection, 4))[0]
        if size > MAX_REPLY:
            raise ConnectionError('reply too large')
        reply = json.loads(_read_exact(connection, size).decode('utf-8'))
        return int(reply['rc']), str(reply['stdout']), str(reply['stderr'])
    except socket.timeout:
        raise subprocess.TimeoutExpired(command, timeout) from None
    finally:
        connection.close()


def via_sudo(command, text=None, timeout=35):
    proc = subprocess.run(['sudo', '-n', MANAGER, command], input=text, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr

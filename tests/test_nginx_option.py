"""Pure Nginx TLS/installer integration tests; no root, firewall or nginx needed."""
import os
import shutil
import subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / 'scripts' / 'setup-nginx.sh'
INSTALL = (ROOT / 'scripts/setup-wizard.sh').read_text()


def shell(command):
    return subprocess.run(['bash', '-c', f'source "{PROXY}"; {command}'],
                          capture_output=True, text=True, check=False)


def test_disabled_proxy_has_no_side_effects():
    p = subprocess.run(['bash', str(PROXY)], env={**os.environ, 'AWG31_PROXY_MODE': 'none'},
                       text=True, capture_output=True)
    assert p.returncode == 0
    assert '127.0.0.1' in p.stdout


def test_nginx_mode_asked_in_install_wizard():
    for token in ('NGINX_MODE=self-signed', 'NGINX_MODE=existing', 'NGINX_MODE=none',
                  'NGINX_CERT', 'NGINX_KEY', 'NGINX_HTTPS_PORT', 'scripts/setup-nginx.sh',
                  'AWG31_PROXY_MODE="$NGINX_MODE"', 'AWG31_PROXY_SELINUX_ACK'):
        assert token in INSTALL


def test_tls_config_is_ipv4_only_localhost_and_secure():
    p = shell("proxy_render_config vpn.example.com 443 8080 /a/cert.pem /a/key.pem")
    assert p.returncode == 0, p.stderr
    assert 'listen 443 ssl;' in p.stdout
    assert 'server_name vpn.example.com;' in p.stdout
    assert 'proxy_pass http://127.0.0.1:8080;' in p.stdout
    assert 'ssl_protocols TLSv1.2 TLSv1.3;' in p.stdout
    assert 'X-Forwarded-Proto https;' in p.stdout
    assert 'listen [::]' not in p.stdout
    assert 'ssl_certificate_key /a/key.pem;' in p.stdout
    assert 'http://0.0.0.0' not in p.stdout


@pytest.mark.parametrize('host', ['vpn.example.net', '10.10.20.29', 'vps1', 'vpn-site.example.co.uk'])
def test_valid_hosts(host):
    assert shell(f"proxy_validate_host '{host}'").returncode == 0


@pytest.mark.parametrize('host', ['vpn.example.com;return', 'foo bar', 'https://vpn.example.com',
                                  'vpn.example.com/path', '::1', '*.example.net', 'x\nlisten 80'])
def test_host_injection_rejected(host):
    assert shell(f"proxy_validate_host '{host}'").returncode != 0


def test_host_port_validation():
    for port in ('443', '8443', '65535', '1'):
        assert shell(f'proxy_validate_port {port}').returncode == 0
    for port in ('0', '65536', 'abc', '443;true'):
        assert shell(f"proxy_validate_port '{port}'").returncode != 0


def test_certificate_generation_and_validation(tmp_path):
    if not shutil.which('openssl'):
        pytest.skip('OpenSSL not installed')
    d = tmp_path/'tls'
    (d/'certs').mkdir(parents=True)
    (d/'private').mkdir()
    crt=d/'certs'/'crt.pem'
    key=d/'private'/'priv.key'
    proc=shell(f"proxy_self_signed_cert 10.10.20.29 '{d}' '{crt}' '{key}'; proxy_validate_certificate '{crt}' '{key}'")
    assert proc.returncode == 0, proc.stderr
    assert crt.exists() and key.exists()
    assert (key.stat().st_mode & 0o777) == 0o600
    info=subprocess.run(['openssl','x509','-in',str(crt),'-noout','-ext','subjectAltName'],capture_output=True,text=True,check=True)
    assert 'IP Address:10.10.20.29' in info.stdout
    assert shell(f"proxy_validate_certificate '{crt}' '{key}'").returncode == 0
    crt2=d/'certs'/'crt2.pem'
    key2=d/'private'/'key2.pem'
    proc2=shell(f"proxy_self_signed_cert vpn.example.com '{d}' '{crt2}' '{key2}'")
    assert proc2.returncode == 0
    assert shell(f"proxy_validate_certificate '{crt}' '{key2}'").returncode != 0
    assert shell(f"proxy_self_signed_cert vpn.example.com '{d}' '{crt}' '{key}'").returncode != 0

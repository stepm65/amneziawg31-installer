from importlib.machinery import SourceFileLoader
import ipaddress
from pathlib import Path
import sqlite3

import pytest

ctl = SourceFileLoader('awg31ctl', str(Path(__file__).parents[1] / 'src' / 'awg31ctl')).load_module()


def base_config(**overrides):
    data = dict(subnet='10.77.10.0/24', server_ip='10.77.10.1', port=51820,
                mtu=1280, endpoint='vpn.example.net', dns='1.1.1.1',
                mode='full', uplink='ens3', private_key='a'*44,
                public_key='b'*44, header_key='c'*44,
                Jc=4, Jmin=10, Jmax=50, S1=12, S2=12, S3=12, S4=12)
    data.update(overrides)
    return data


def test_subnet_and_ipv6_rejected():
    assert str(ctl.parse_network('10.77.10.0/24')) == '10.77.10.0/24'
    assert str(ctl.parse_network('10.10.10.0/29')) == '10.10.10.0/29'
    for name in ('2001:db8::/64','10.77.10.3/24','10.0.0.0/23','127.0.0.0/24'):
        with pytest.raises(ValueError): ctl.parse_network(name)
    with pytest.raises(ValueError): ctl.valid_dns('2001:db8::1')
    with pytest.raises(ValueError): ctl.valid_endpoint('2001:db8::1')


def test_server_client_profiles_are_31_and_ipv4_only():
    cfg = base_config()
    peer = {'name':'phone', 'ip':'10.77.10.2','private_key':'q'*44,
            'public_key':'p'*44,'psk':'k'*44,'enabled':1}
    server = ctl.server_config(cfg,[peer])
    client = ctl.client_config(cfg,peer)
    for conf in (server,client):
        assert 'HeaderProtectionKey' in conf
        assert 'RandomTrailers = on' in conf
        assert 'DisableCookies = on' in conf
        assert 'ContentPaddingAddition' in conf
        assert 'S1 = 12' in conf
        assert '::/0' not in conf
        assert 'ip6tables' not in conf
    assert 'AllowedIPs = 10.77.10.2/32' in server
    assert 'AllowedIPs = 0.0.0.0/0' in client


def test_full_tunnel_only_ipv4_nat():
    cfg=base_config(mode='full')
    server=ctl.server_config(cfg,[])
    assert 'iptables -w -t nat -A POSTROUTING -s 10.77.10.0/24 -o ens3 -j MASQUERADE' in server
    assert 'iptables -w -I FORWARD 1 -i awg0 -o ens3 -s 10.77.10.0/24 -j ACCEPT' in server
    assert 'iptables -w -I FORWARD 1 -i ens3 -o awg0 -d 10.77.10.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' in server
    assert 'PostDown = iptables -w -D FORWARD' in server
    assert '0.0.0.0/0' in ctl.client_config(cfg,{'private_key':'a','ip':'10.77.10.2','psk':'b'})


def test_dangerous_input_rejected():
    for bad in ('eth0;touch /tmp/hacked','foo bar','/tmp/why'):
        with pytest.raises(ValueError): ctl.validate_settings({'subnet':'10.77.10.0/24','port':51820,
                'mtu':1280,'endpoint':'example.com','dns':'1.1.1.1','mode':'full','uplink':bad}, initial=True)
    with pytest.raises(ValueError): ctl.valid_endpoint('example.net;rm')
    with pytest.raises(ValueError): ctl.valid_port('99999')
    with pytest.raises(ValueError): ctl.valid_mtu('560')


def test_init_and_clients_with_mock_commands(tmp_path,monkeypatch):
    monkeypatch.setattr(ctl,'DB',tmp_path/'state.sqlite3')
    monkeypatch.setattr(ctl,'CONF',tmp_path/'awg0.conf')
    monkeypatch.setattr(ctl,'LOCK',tmp_path/'lock')
    from io import StringIO
    import sys
    key_number={'n':0}
    def fake_run(*argv,stdin=None):
        if argv[:2]==('awg','genkey'):
            key_number['n']+=1
            return 'A'*43 + '='
        if argv[:2]==('awg','pubkey'): return 'B'*43+'='
        if argv[:2]==('awg','genpsk'): return 'C'*43+'='
        if argv[:2]==('awg-quick','strip'): return '[Interface]\nPrivateKey = AAA\n'
        return ''
    monkeypatch.setattr(ctl,'run',fake_run)
    # No dependency on the host's iproute2: the interface is reported as running.
    monkeypatch.setattr(ctl.subprocess,'run',lambda *a,**k: type('P',(),{'returncode':0,'stdout':'[]','stderr':''})())
    monkeypatch.delenv('AWG31_GENERATE_PARAMS',raising=False)
    monkeypatch.setattr(sys,'stdin',StringIO('{"subnet":"10.77.10.0/29","port":443,"mtu":1280,"endpoint":"vpn.example.net","dns":"1.1.1.1","mode":"split","uplink":"ens3"}'))
    assert ctl.init()['ok'] is True
    assert (tmp_path/'awg0.conf').stat().st_mode & 0o777 == 0o600
    # The primary server must not get the static WireGuard-like H1-H4 = 1..4.
    created=(tmp_path/'awg0.conf').read_text()
    headers=[int(created.split(f'H{n} = ')[1].split()[0]) for n in range(1,5)]
    assert len(set(headers))==4 and min(headers)>=10_000
    con=ctl.get_conn()
    monkeypatch.setattr(sys,'stdin',StringIO('{"name":"phone"}'))
    item=ctl.clients_add(con)
    assert item['ip']=='10.77.10.2'
    assert 'HeaderProtectionKey' in item['config']
    assert con.execute('SELECT COUNT(*) FROM clients').fetchone()[0] == 1
    monkeypatch.setattr(sys,'stdin',StringIO('{"name":"phone"}'))
    assert ctl.clients_action(con,'disable')['ok']
    assert '[Peer]' not in ctl.CONF.read_text()
    monkeypatch.setattr(sys,'stdin',StringIO('{"name":"phone"}'))
    assert ctl.clients_action(con,'enable')['ok']
    assert '[Peer]' in ctl.CONF.read_text()
    con.close()


def test_apply_rollback_after_sync_error(tmp_path,monkeypatch):
    monkeypatch.setattr(ctl,'CONF',tmp_path/'awg0.conf')
    original='[Interface]\nPrivateKey = previous-secret\n'
    ctl.atomic_write(ctl.CONF,original)
    def failing_run(*args,**kwargs):
        if args[:2]==('awg-quick','strip'):
            return '[Interface]\nPrivateKey = some-secret'
        if args[:2]==('awg','syncconf'):
            raise RuntimeError('simulate failed kernel apply')
        return ''
    monkeypatch.setattr(ctl,'run',failing_run)
    monkeypatch.setattr(ctl.subprocess,'run', lambda *a,**k: type('P',(),{'returncode':0})())
    class DummyConn:
        pass
    monkeypatch.setattr(ctl,'peer_rows',lambda con:[])
    with pytest.raises(RuntimeError): ctl.apply(base_config(),DummyConn())
    assert ctl.CONF.read_text()==original


def test_default_mode_is_full_and_split_opt_in():
    setting = ctl.validate_settings({'subnet':'10.77.10.0/24', 'port':51820,
        'mtu':1280, 'endpoint':'vpn.example.net', 'dns':'1.1.1.1', 'uplink':'ens3'}, initial=True)
    assert setting['mode'] == 'full'
    cfg = base_config(mode='split')
    assert 'AllowedIPs = 10.77.10.0/24' in ctl.client_config(cfg, {'private_key':'x', 'ip':'10.77.10.2', 'psk':'y'})
    split_server = ctl.server_config(cfg, [])
    assert 'MASQUERADE' not in split_server and 'ens3' not in split_server      # no NAT, no uplink rules
    assert 'sysctl' not in split_server                                          # forwarding stays off by default

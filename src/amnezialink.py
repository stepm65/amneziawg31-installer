"""AmneziaVPN native vpn:// export for an AWG 3.1 peer.

This is an optional export alongside the canonical AmneziaWG .conf. The
native structure follows AmneziaVPN client JSON export conventions and still
requires a real-app interoperability test before a stable release.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import json
import re
from typing import Mapping

# Values expected in AmneziaWG 3.1 client [Interface] configuration.
AWG_FIELDS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
              'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey',
              'ContentPaddingAddition', 'RandomTrailers', 'DisableCookies',
              'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
              'KeepaliveTimeout', 'MaxHandshakeAttempts')


def _fields(conf: str) -> tuple[dict[str, str], dict[str, str]]:
    parser = configparser.ConfigParser(interpolation=None, strict=True,
                                      comment_prefixes=('#', ';'))
    parser.optionxform = str
    parser.read_string(conf)
    if not parser.has_section('Interface') or not parser.has_section('Peer'):
        raise ValueError('Client configuration needs Interface and Peer sections')
    interface = dict(parser.items('Interface'))
    peer = dict(parser.items('Peer'))
    for key in ('PrivateKey', 'Address'):
        if not interface.get(key):
            raise ValueError(f'Missing Interface.{key}')
    for key in ('PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs'):
        if not peer.get(key):
            raise ValueError(f'Missing Peer.{key}')
    return interface, peer


def build_vpn_uri(conf: str, *, name: str, server_ip: str,
                  subnet: str, client_public_key: str) -> str:
    """Encode one client as AmneziaVPN's URL-safe Base64 JSON vpn:// format.

    No private keys are logged, persisted or returned except inside the
    explicit on-demand share URI itself.
    """
    interface, peer = _fields(conf)
    address = ipaddress.IPv4Interface(interface['Address'])
    server_net = ipaddress.IPv4Network(subnet, strict=True)
    ipaddress.IPv4Address(server_ip)
    if address.ip not in server_net:
        raise ValueError('Client address is not in VPN subnet')
    endpoint = peer['Endpoint']
    if ':' not in endpoint:
        raise ValueError('Endpoint must contain a UDP port')
    host, port_str = endpoint.rsplit(':', 1)
    if not host or not re.fullmatch(r'[0-9]+', port_str) or not 1 <= int(port_str) <= 65535:
        raise ValueError('Invalid endpoint')
    if not client_public_key:
        raise ValueError('Client public key is not available')
    allowed = [s.strip() for s in peer['AllowedIPs'].split(',') if s.strip()]
    if not allowed:
        raise ValueError('AllowedIPs is empty')
    awg = {
        'port': port_str,
        'transport_proto': 'udp',
        'protocol_version': '3.1',
        'subnet_address': server_ip,
        'subnet_cidr': str(server_net.prefixlen),
    }
    client = {
        'hostName': host,
        'port': int(port_str),
        'client_ip': str(address.ip),
        'client_priv_key': interface['PrivateKey'],
        'client_pub_key': client_public_key,
        'server_pub_key': peer['PublicKey'],
        'psk_key': peer['PresharedKey'],
        'clientId': client_public_key,
        'allowed_ips': allowed,
        'mtu': interface.get('MTU', '1280'),
        'persistent_keep_alive': peer.get('PersistentKeepalive', '25'),
        'config': conf,
    }
    for key in AWG_FIELDS:
        value = interface.get(key)
        if value:
            awg[key] = value
            client[key] = value
    # CPS I1-I5 are optional and must never be invented for AWG 3.1.
    for number in range(1, 6):
        key = f'I{number}'
        if interface.get(key):
            awg[key] = interface[key]
            client[key] = interface[key]
    awg['last_config'] = json.dumps(client, ensure_ascii=False, separators=(',', ':'))
    root = {
        'containers': [{'container': 'amnezia-awg2', 'awg': awg}],
        'defaultContainer': 'amnezia-awg2',
        'description': f'AWG 3.1 - {name}',
        'hostName': host,
    }
    if interface.get('DNS'):
        dns = [d.strip() for d in interface['DNS'].split(',') if d.strip()]
        for idx, value in enumerate(dns[:2], 1):
            ipaddress.IPv4Address(value)
            root[f'dns{idx}'] = value
    payload = json.dumps(root, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return 'vpn://' + base64.urlsafe_b64encode(payload).decode('ascii').rstrip('=')

"""Build a genuine QUIC v1 Initial packet carrying a TLS 1.3 ClientHello.

Used only to produce an `I1` decoy for AmneziaWG clients: the datagram a real
QUIC client would send first, with a chosen server name (SNI). A middlebox that
decrypts Initial packets (their keys are public, RFC 9001 section 5.2) finds a
well-formed ClientHello instead of noise.

Nothing here protects a secret. The packet is meant to be read by observers, so
a small dependency-free AES-128-GCM is sufficient; it is checked against
RFC 9001 vectors and, in the test suite, against the `cryptography` package.
Do not reuse this module for real encryption.
"""
import hashlib
import hmac
import re
import secrets

INITIAL_SALT_V1 = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
DATAGRAM_SIZE = 1200            # RFC 9000 section 14.1: minimum size of a client Initial
HOST_RE = re.compile(r'(?=.{4,100}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')

# ---------------------------------------------------------------- AES-128 (encrypt only)
_SBOX = []


def _init_sbox():
    p = q = 1
    box = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)      # multiply by 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        box[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    box[0] = 0x63
    _SBOX.extend(box)


_init_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1


def _expand_key(key):
    if len(key) != 16:
        raise ValueError('AES-128 key must be 16 bytes')
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = [_SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _encrypt_block(round_keys, block):
    state = [a ^ b for a, b in zip(block, round_keys[0])]
    for rnd in range(1, 11):
        state = [_SBOX[b] for b in state]
        # ShiftRows on a column-major state
        state = [state[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if rnd != 10:
            mixed = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c:c + 4]
                t = a0 ^ a1 ^ a2 ^ a3
                mixed += [a0 ^ t ^ _xtime(a0 ^ a1), a1 ^ t ^ _xtime(a1 ^ a2),
                          a2 ^ t ^ _xtime(a2 ^ a3), a3 ^ t ^ _xtime(a3 ^ a0)]
            state = mixed
        state = [a ^ b for a, b in zip(state, round_keys[rnd])]
    return bytes(state)


def aes128_encrypt_block(key, block):
    return _encrypt_block(_expand_key(key), block)


# ---------------------------------------------------------------- GCM
def _gf_mult(x, y):
    z = 0
    v = y
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            z ^= v
        v = (v >> 1) ^ (0xe1 << 120) if v & 1 else v >> 1
    return z


def _ghash(h, aad, ciphertext):
    def blocks(data):
        for i in range(0, len(data), 16):
            yield int.from_bytes(data[i:i + 16].ljust(16, b'\x00'), 'big')
    x = 0
    for block in blocks(aad):
        x = _gf_mult(x ^ block, h)
    for block in blocks(ciphertext):
        x = _gf_mult(x ^ block, h)
    lengths = (len(aad) * 8 << 64) | (len(ciphertext) * 8)
    return _gf_mult(x ^ lengths, h)


def aes128_gcm_encrypt(key, nonce, plaintext, aad):
    """Return ciphertext || 16-byte tag (96-bit nonce)."""
    if len(nonce) != 12:
        raise ValueError('GCM nonce must be 12 bytes')
    round_keys = _expand_key(key)
    h = int.from_bytes(_encrypt_block(round_keys, bytes(16)), 'big')
    out = bytearray()
    for index in range(0, len(plaintext), 16):
        counter = nonce + (index // 16 + 2).to_bytes(4, 'big')
        stream = _encrypt_block(round_keys, counter)
        out += bytes(a ^ b for a, b in zip(plaintext[index:index + 16], stream))
    tag = _ghash(h, aad, bytes(out)) ^ int.from_bytes(_encrypt_block(round_keys, nonce + b'\x00\x00\x00\x01'), 'big')
    return bytes(out) + tag.to_bytes(16, 'big')


# ---------------------------------------------------------------- QUIC key schedule
def _hkdf_expand_label(secret, label, length):
    full = b'tls13 ' + label
    info = length.to_bytes(2, 'big') + bytes([len(full)]) + full + b'\x00'
    out = b''
    block = b''
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def client_initial_keys(dcid):
    """(key, iv, hp) of the client's Initial packets for this Destination Connection ID."""
    initial = hmac.new(INITIAL_SALT_V1, dcid, hashlib.sha256).digest()
    client = _hkdf_expand_label(initial, b'client in', 32)
    return (_hkdf_expand_label(client, b'quic key', 16), _hkdf_expand_label(client, b'quic iv', 12),
            _hkdf_expand_label(client, b'quic hp', 16))


def _varint(value):
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (0x4000 | value).to_bytes(2, 'big')
    if value < 0x40000000:
        return (0x80000000 | value).to_bytes(4, 'big')
    return (0xc000000000000000 | value).to_bytes(8, 'big')


# ---------------------------------------------------------------- TLS ClientHello
def _extension(kind, body):
    return kind.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body


def _transport_parameters():
    def param(identifier, value):
        return _varint(identifier) + _varint(len(value)) + value
    return b''.join([
        param(0x01, _varint(30000)),          # max_idle_timeout, ms
        param(0x03, _varint(1472)),           # max_udp_payload_size
        param(0x04, _varint(15728640)),       # initial_max_data
        param(0x05, _varint(6291456)),        # initial_max_stream_data_bidi_local
        param(0x06, _varint(6291456)),        # initial_max_stream_data_bidi_remote
        param(0x07, _varint(6291456)),        # initial_max_stream_data_uni
        param(0x08, _varint(100)),            # initial_max_streams_bidi
        param(0x09, _varint(103)),            # initial_max_streams_uni
        param(0x0e, _varint(8)),              # active_connection_id_limit
        param(0x0f, b''),                     # initial_source_connection_id: empty, as in the header
    ])


def client_hello(host, rng=secrets.token_bytes):
    name = host.encode('ascii')
    server_name = (len(name) + 3).to_bytes(2, 'big') + b'\x00' + len(name).to_bytes(2, 'big') + name
    groups = bytes.fromhex('001d00170018')                       # x25519, secp256r1, secp384r1
    signatures = bytes.fromhex('040308040401050308050501080606010201')
    key_share = b'\x00\x1d\x00\x20' + rng(32)                     # x25519 public key
    extensions = b''.join([
        _extension(0x0000, server_name),
        _extension(0x000a, len(groups).to_bytes(2, 'big') + groups),
        _extension(0x000d, len(signatures).to_bytes(2, 'big') + signatures),
        _extension(0x0010, b'\x00\x03\x02h3'),                    # ALPN: h3
        _extension(0x002b, b'\x02\x03\x04'),                      # supported_versions: TLS 1.3
        _extension(0x002d, b'\x01\x01'),                          # psk_key_exchange_modes: psk_dhe_ke
        _extension(0x0033, len(key_share).to_bytes(2, 'big') + key_share),
        _extension(0x0039, _transport_parameters()),              # quic_transport_parameters
    ])
    body = (b'\x03\x03' + rng(32) + b'\x00'                       # legacy_version, random, empty session id
            + b'\x00\x06\x13\x01\x13\x02\x13\x03'                 # TLS_AES_128_GCM, AES_256_GCM, CHACHA20
            + b'\x01\x00'                                         # null compression
            + len(extensions).to_bytes(2, 'big') + extensions)
    return b'\x01' + len(body).to_bytes(3, 'big') + body


# ---------------------------------------------------------------- packet
def normalize_host(host):
    value = str(host or '').strip().lower().rstrip('.')
    if not HOST_RE.fullmatch(value) or value.replace('.', '').isdigit():
        raise ValueError('Server name must be a DNS name such as www.example.com')
    return value


def build_initial(host, rng=secrets.token_bytes):
    """One 1200-byte QUIC v1 Initial datagram with a ClientHello for `host`."""
    host = normalize_host(host)
    dcid = rng(8)
    hello = client_hello(host, rng)
    crypto_frame = b'\x06\x00' + _varint(len(hello)) + hello      # CRYPTO, offset 0
    packet_number = b'\x00'
    header_length = 1 + 4 + 1 + len(dcid) + 1 + 1 + 2             # flags, version, DCID, SCID, token, length
    plaintext_length = DATAGRAM_SIZE - header_length - len(packet_number) - 16
    if len(crypto_frame) > plaintext_length:
        raise ValueError('ClientHello does not fit into one Initial packet')
    plaintext = crypto_frame + bytes(plaintext_length - len(crypto_frame))   # PADDING frames
    header = (b'\xc0' + b'\x00\x00\x00\x01' + bytes([len(dcid)]) + dcid + b'\x00' + b'\x00'
              + _varint(len(packet_number) + plaintext_length + 16))
    key, iv, hp = client_initial_keys(dcid)
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.rjust(12, b'\x00')))
    sealed = aes128_gcm_encrypt(key, nonce, plaintext, header + packet_number)
    # Header protection (RFC 9001 section 5.4): sample starts 4 bytes after the packet number begins.
    sample = sealed[4 - len(packet_number):20 - len(packet_number)]
    mask = aes128_encrypt_block(hp, sample)
    first = bytes([header[0] ^ (mask[0] & 0x0f)])
    protected_number = bytes(a ^ b for a, b in zip(packet_number, mask[1:]))
    packet = first + header[1:] + protected_number + sealed
    assert len(packet) == DATAGRAM_SIZE
    return packet

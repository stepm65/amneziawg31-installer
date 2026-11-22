#!/usr/bin/env bash
# End-to-end check of a real installation. Runs on a disposable machine only
# (the GitHub Actions runner): it installs, reconfigures and finally purges.
# Usage: sudo bash tests/smoke/check_install.sh   (from a repository checkout)
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
step(){ printf '\n=== %s ===\n' "$*"; }
fail(){ printf 'SMOKE FAILED: %s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || fail 'run as root'
[[ "${CI:-}" == true || "${AWG31_SMOKE_ALLOW:-}" == yes ]] || fail 'refusing to run outside CI (set AWG31_SMOKE_ALLOW=yes on a disposable machine)'
export AWG31_UNATTENDED=1 AWG31_ENDPOINT=203.0.113.10 AWG31_PANEL_PORT=18080 AWG31_FIRST_CLIENT=ci-client
MGR=/usr/local/sbin/awg31mgr
CONF=/etc/amnezia/amneziawg/awg0.conf
panel(){ curl --noproxy '*' -fsS --max-time 10 "http://127.0.0.1:$1/health" >/dev/null; }
forward(){ iptables -w -S FORWARD; }

if [[ -n "${AWG31_SMOKE_FROM:-}" ]]; then
    # Update from the previous release, roll back to it, and update again: the
    # rest of the checks then run on an installation that went through all three.
    step "Installing the previous release $AWG31_SMOKE_FROM from GitHub"
    bash "$ROOT/install.sh" "$AWG31_SMOKE_FROM"
    [[ "v$(awg31 version)" == "$AWG31_SMOKE_FROM" ]] || fail "the previous release is not installed: $(awg31 version)"
    clients_before="$("$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; print(sorted((c["name"],c["public_key"]) for c in json.load(sys.stdin)["clients"]))')"
    conf_before="$(sha256sum "$CONF" | cut -d' ' -f1)"
    step "Updating $AWG31_SMOKE_FROM to $(cat "$ROOT/VERSION")"
    bash "$ROOT/install.sh"
    [[ "$(awg31 version)" == "$(cat "$ROOT/VERSION")" ]] || fail 'the update did not install the new version'
    panel 18080 || fail 'panel is down after the update from the previous release'
    [[ "$(sha256sum "$CONF" | cut -d' ' -f1)" == "$conf_before" ]] || fail 'the update changed the VPN configuration'
    clients_now="$("$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; print(sorted((c["name"],c["public_key"]) for c in json.load(sys.stdin)["clients"]))')"
    [[ "$clients_now" == "$clients_before" ]] || fail 'clients changed during the update'
    step "Rolling back to $AWG31_SMOKE_FROM"
    awg31 rollback --yes || fail 'rollback to the previous release failed'
    [[ "v$(awg31 version)" == "$AWG31_SMOKE_FROM" ]] || fail "rollback did not bring back $AWG31_SMOKE_FROM: $(awg31 version)"
    panel 18080 || fail 'panel is down after the rollback'
    runuser -u awgpanel -- sudo -n "$MGR" servers </dev/null >/dev/null || fail 'panel sudo permission broken after the rollback'
    [[ "$(sha256sum "$CONF" | cut -d' ' -f1)" == "$conf_before" ]] || fail 'the rollback changed the VPN configuration'
    step 'Updating again to the version under test'
    bash "$ROOT/install.sh"
    [[ "$(awg31 version)" == "$(cat "$ROOT/VERSION")" ]] || fail 'the second update did not install the new version'
    step 'Unattended installation (done through the update above)'
else
    step 'Unattended installation'
    bash "$ROOT/install.sh"
fi
awg show awg0 >/dev/null || fail 'awg0 is not up'
panel 18080 || fail 'panel does not answer'
[[ -s /root/awg31-initial-password.txt && "$(stat -c %a /root/awg31-initial-password.txt)" == 600 ]] || fail 'password file missing or not 0600'
[[ "$(awg31 version)" == "$(cat "$ROOT/VERSION")" ]] || fail 'awg31 version mismatch'
systemctl is-active --quiet awg31-sampler.timer awg31-kernel-check.timer || fail 'timers are not active'

step 'Primary server has random obfuscation'
grep -E '^(Jc|S1|H1|H2|H3|H4) = ' "$CONF"
if grep -qE '^H1 = 1$' "$CONF"; then fail 'H1 is the plain WireGuard value'; fi

step 'Firewall rules of a full-tunnel server'
forward
forward | grep -q -- '-d 169.254.0.0/16 -i awg0 -j DROP' || fail 'metadata service is not blocked'
forward | grep -q -- '-i awg0 -o awg0 -j ACCEPT' || fail 'client-to-client rule missing'
iptables -w -t nat -S POSTROUTING | grep -q MASQUERADE || fail 'NAT rule missing'
[[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'forwarding is off'

step 'Panel: sign in, create a client, download its configuration'
python3 - <<'PY'
import http.cookiejar, re, urllib.parse, urllib.request
base = 'http://127.0.0.1:18080'
password = open('/root/awg31-initial-password.txt').read().strip()
class Jar(http.cookiejar.CookieJar):
    def set_cookie(self, cookie):
        cookie.secure = False          # the panel marks cookies Secure; this check talks plain HTTP on loopback
        super().set_cookie(cookie)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(Jar()))
def post(path, **fields):
    return opener.open(base + path, urllib.parse.urlencode(fields).encode(), timeout=30)
assert post('/login', password='wrong-password-123').geturl().endswith('/login')
post('/login', password=password)
page = opener.open(base + '/servers/awg0/clients', timeout=30).read().decode()
assert 'ci-client' in page, 'first client is not listed'
token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
value = __import__('json').load(opener.open(base + '/api/cps/generate?preset=quictls&host=www.example.com', timeout=30))['value']
post('/servers/awg0/clients', csrf=token, name='smoke', i_enabled='1', i1=value, quota_gib='0', comment='smoke test')
config = opener.open(base + '/servers/awg0/clients/smoke/download', timeout=30).read().decode()
assert 'AllowedIPs = 0.0.0.0/0' in config and 'I1 = <b 0x' in config and 'PrivateKey' in config
home = opener.open(base + '/', timeout=30).read().decode()
installed = open('/opt/awg31-panel/VERSION').read().strip()
assert f'<span>v{installed}</span>' in home, 'the installed version is not shown in the sidebar'
opener.open(base + '/logout', timeout=30)
try:
    final = opener.open(base + '/servers/awg0/clients', timeout=30).geturl()
except Exception as exc:
    final = str(exc)
assert '/login' in final, 'still signed in after logout: ' + final
print('panel checks passed')
PY
awg show awg0 | grep -c '^peer' | grep -qx 2 || fail 'expected two peers on awg0'

step 'Control helper: socket, permissions, fallback, speed'
systemctl is-active --quiet awg31-helper.service || fail 'control helper is not running'
[[ "$(stat -c '%U:%G %a' /run/awg31/control.sock)" == 'root:awg31ctl 660' ]] || fail 'helper socket has wrong owner or mode'
id -nG awgpanel | tr ' ' '\n' | grep -qx awg31ctl || fail 'awgpanel is not in awg31ctl'
panel_pid="$(systemctl show -p MainPID --value awg31-panel.service)"
grep -qw "$(getent group awg31ctl | cut -d: -f3)" <(grep '^Groups:' "/proc/$panel_pid/status") || fail 'the running panel has not got the awg31ctl group'
cat >/tmp/awg31-probe.py <<'PY'
import json, statistics, sys, time
sys.path.insert(0, '/opt/awg31-panel')
import awg31client
mode, op = sys.argv[1], sys.argv[2]
data = json.dumps({'interface': 'awg0'})
if mode == 'helper-only':
    def no_sudo(*args):
        raise SystemExit('fell back to sudo')
    awg31client.via_sudo = no_sudo
    code, out, err = awg31client.call(op, data)
    print(code, (out or err).strip()[:200])
    sys.exit(0)
call = awg31client.call if mode == 'helper' else awg31client.via_sudo
times = []
for _ in range(15):
    started = time.perf_counter()
    code, out, err = call(op, data)
    times.append((time.perf_counter() - started) * 1000)
    assert code == 0, err
print(f'{statistics.median(times):.1f}')
PY
chmod 644 /tmp/awg31-probe.py
probe(){ runuser -u "$1" -- /opt/awg31-panel/.venv/bin/python3 /tmp/awg31-probe.py "${@:2}"; }
probe awgpanel helper-only list | grep -q '^0 ' || fail 'the panel user does not reach the controller through the helper'
probe awgpanel helper-only password-reset | grep -q 'Operation not permitted' || fail 'the helper ran a console-only operation for the panel'
probe awgpanel helper-only totp-reset | grep -q 'Operation not permitted' || fail 'the helper ran totp-reset for the panel'
if runuser -u nobody -- python3 -c 'import socket; socket.socket(socket.AF_UNIX).connect("/run/awg31/control.sock")' 2>/dev/null; then
    fail 'an unrelated user can connect to the helper socket'
fi
via_sudo_ms="$(probe awgpanel sudo list)"
via_helper_ms="$(probe awgpanel helper list)"
servers_sudo_ms="$(probe awgpanel sudo servers)"
servers_helper_ms="$(probe awgpanel helper servers)"
echo "median of 15 calls: list ${via_sudo_ms} ms via sudo, ${via_helper_ms} ms via helper; servers ${servers_sudo_ms} ms via sudo, ${servers_helper_ms} ms via helper"
python3 -c "import sys; sys.exit(0 if float('$via_helper_ms') < float('$via_sudo_ms') else 1)" || fail 'the helper is not faster than sudo'
systemctl stop awg31-helper.service
[[ ! -e /run/awg31/control.sock ]] || fail 'socket left behind after stop'
probe awgpanel sudo list >/dev/null || fail 'sudo path does not work'
runuser -u awgpanel -- /opt/awg31-panel/.venv/bin/python3 -c 'import sys; sys.path.insert(0,"/opt/awg31-panel"); import awg31client; sys.exit(awg31client.call("servers")[0])' \
    || fail 'no fallback to sudo while the helper is stopped'
systemctl start awg31-helper.service
for attempt in $(seq 1 25); do [[ -S /run/awg31/control.sock ]] && break; sleep 0.2; done
probe awgpanel helper-only servers | grep -q '^0 ' || fail 'helper did not come back'

step 'Isolate clients, close private networks'
echo '{"interface":"awg0","client_to_client":"off","private_access":"off"}' | "$MGR" settings
forward
forward | grep -q -- '-i awg0 -o awg+ -j DROP' || fail 'isolation rule missing'
forward | grep -q -- '-d 10.0.0.0/8 -i awg0' || forward | grep -q -- '-d 10.0.0.0/8 .*-j DROP' || fail 'private network rule missing'
if forward | grep -q -- '-i awg0 -o awg0 -j ACCEPT'; then fail 'allow rule survived isolation'; fi
echo '{"interface":"awg0","client_to_client":"on","private_access":"on"}' | "$MGR" settings
if forward | grep -q -- '-o awg+ -j DROP'; then fail 'isolation rule survived'; fi

step 'Server services closed to clients; client IPv6 blocked'
echo '{"interface":"awg0","host_access":"off","ipv6_block":"on"}' | "$MGR" settings >/dev/null
iptables -w -S INPUT | grep awg0
first="$(iptables -w -S INPUT | grep -n -- '-i awg0' | head -n1)"
last="$(iptables -w -S INPUT | grep -n -- '-i awg0' | tail -n1)"
grep -q 'ESTABLISHED' <<<"$first" || fail 'replies to the server are not allowed first'
grep -q -- '-i awg0 -j DROP' <<<"$last" || fail 'the DROP rule for clients is not last'
echo '{"interface":"awg0","name":"ci-client"}' | "$MGR" download | grep -q 'AllowedIPs = 0.0.0.0/0, ::/0' || fail 'IPv6 is not routed into the tunnel'
awg show awg0 >/dev/null || fail 'awg0 went down after the switches'
echo '{"interface":"awg0","host_access":"on","ipv6_block":"off"}' | "$MGR" settings >/dev/null
if iptables -w -S INPUT | grep -q -- '-i awg0'; then fail 'INPUT rules survived host_access=on'; fi

step 'Speed limit of one client'
echo '{"interface":"awg0","name":"ci-client","speed_limit_mbit":10}' | "$MGR" client-policy >/dev/null
tc -s qdisc show dev awg0
tc class show dev awg0 | grep -qi 'rate 10Mbit' || fail 'no HTB class for the limited client'
tc filter show dev awg0 parent ffff: | grep -qi 'police' || fail 'no upload policer for the limited client'
echo '{"interface":"awg0"}' | "$MGR" server-restart >/dev/null
awg show awg0 >/dev/null || fail 'awg0 did not come back with a speed limit configured'
tc class show dev awg0 | grep -qi 'rate 10Mbit' || fail 'the limit is lost after a restart'
echo '{"interface":"awg0","name":"ci-client","speed_limit_mbit":0}' | "$MGR" client-policy >/dev/null
if tc qdisc show dev awg0 | grep -q htb; then fail 'shaping stays after the limit was removed'; fi

step 'Several clients at once'
echo '{"interface":"awg0","prefix":"team","count":3,"quota_period":"monthly","traffic_limit_bytes":1073741824}' | "$MGR" add-batch \
  | python3 -c 'import json,sys; c=json.load(sys.stdin)["clients"]; assert [x["name"] for x in c]==["team-01","team-02","team-03"] and all("PrivateKey" in x["config"] for x in c)'
awg show awg0 | grep -c '^peer' | grep -qx 5 || fail 'expected five peers after the batch'

step 'Extra [Interface] lines for router clients'
echo '{"interface":"awg0","names":["team-01","team-02"],"mode":"replace","extra_lines":"postup = echo up\nTable = 200"}' \
  | runuser -u awgpanel -- sudo -n "$MGR" client-extra | grep -q '"team-01"' || fail 'the panel cannot set extra lines'
echo '{"interface":"awg0","name":"team-01"}' | "$MGR" download | python3 -c '
import json, sys
x = json.load(sys.stdin)
head = x["config"].split("[Peer]")[0]
assert "PostUp = echo up" in head and "Table = 200" in head, head
assert "PostUp" not in x["link_config"] and "Table" not in x["link_config"]'
echo '{"interface":"awg0","names":["team-01"],"extra_lines":"[Peer]"}' | "$MGR" client-extra >/dev/null 2>&1 \
  && fail 'a section in the extra lines was accepted'
"$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; c={x["name"]:x for x in json.load(sys.stdin)["clients"]}; assert c["team-01"]["extra_lines"] and not c["team-03"]["extra_lines"]'

step 'Bulk actions, key replacement and invitations through the panel rule'
panel_mgr(){ runuser -u awgpanel -- sudo -n "$MGR" "$@"; }
echo '{"interface":"awg0","names":["team-01","team-02"],"action":"disable"}' | panel_mgr client-batch \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["disabled"]==["team-01","team-02"], r'
awg show awg0 peers | wc -l | grep -qx 3 || fail 'bulk disable did not remove the peers'
echo '{"interface":"awg0","names":["team-01","team-02"],"action":"enable"}' | panel_mgr client-batch | grep -q '"enabled": \["team-01", "team-02"\]' \
  || fail 'bulk enable failed'
echo '{"interface":"awg0","names":["team-03"],"action":"extend","days":30}' | panel_mgr client-batch | grep -q '"no_expiry"' \
  || fail 'a client without expiry was extended'
old_key="$("$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; print({c["name"]:c["public_key"] for c in json.load(sys.stdin)["clients"]}["team-03"])')"
echo '{"interface":"awg0","name":"team-03"}' | panel_mgr client-rekey | grep -q 'PrivateKey = ' || fail 'key replacement returned no configuration'
new_key="$("$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; print({c["name"]:c["public_key"] for c in json.load(sys.stdin)["clients"]}["team-03"])')"
[[ "$new_key" != "$old_key" ]] || fail 'the public key did not change'
awg show awg0 peers | grep -qxF "$new_key" || fail 'the new key is not on the interface'
if awg show awg0 peers | grep -qxF "$old_key"; then fail 'the old key still works'; fi
INVITE="$(echo '{"interface":"awg0","name":"team-03","days":1,"export":true}' | panel_mgr client-invite | python3 -c 'import json,sys; print(json.load(sys.stdin)["code"])')"
if grep -rqF "$INVITE" /var/lib/awg31-panel; then fail 'the invitation code is stored in clear'; fi
if echo "{\"interface\":\"awg0\",\"code\":\"$INVITE\",\"telegram_id\":\"555000111\"}" | panel_mgr invite-redeem >/dev/null 2>&1; then
    fail 'the panel user may redeem an invitation'
fi

step 'Router subscription, masking profile, rotation, packet check, MSS and sysctl'
grep -q '^net.ipv4.tcp_syncookies = 1' /etc/sysctl.d/96-awg31-network.conf || fail 'the network sysctl file is missing'
[[ "$(sysctl -n net.ipv4.conf.all.rp_filter)" == 2 ]] || fail 'rp_filter is not loose'
if [[ -n "${AWG31_SMOKE_FROM:-}" ]]; then
    # A server from an older release keeps what it had: MSS clamping stays off until switched on.
    if iptables -w -t mangle -S FORWARD | grep -q TCPMSS; then fail 'the update switched MSS clamping on by itself'; fi
else
    iptables -w -t mangle -S FORWARD | grep -q -- '-o awg0 .*TCPMSS --clamp-mss-to-pmtu' || fail 'no MSS clamping for a new server'
fi
SUB="$(echo '{"interface":"awg0","name":"team-03"}' | panel_mgr sub-token | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
if grep -rqF "$SUB" /var/lib/awg31-panel; then fail 'the subscription token is stored in clear'; fi
echo "{\"interface\":\"awg0\",\"token\":\"$SUB\",\"addr\":\"198.51.100.7\"}" | panel_mgr sub-fetch \
  | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["found"] and "PrivateKey = " in r["config"] and len(r["etag"]) == 32, r'
echo '{"interface":"awg0","token":"0000000000000000000000000000000000000000000"}' | panel_mgr sub-fetch | grep -q '"found": false' \
  || fail 'an unknown subscription token was accepted'
echo '{"interface":"awg0","profile":"stun","i1":{"team-01":"<b 0x000100002112a442><r 12>"}}' | panel_mgr mask-apply >/dev/null
echo '{"interface":"awg0","name":"team-01"}' | "$MGR" download | grep -q 'I1 = <b 0x000100002112a442><r 12>' || fail 'the masking profile did not set I1'
old_port="$(awg show awg0 listen-port)"
old_h1="$(grep '^H1 = ' "$CONF")"
echo '{"interface":"awg0","parts":["port","obfuscation"]}' | panel_mgr rotate | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["port"] != r["old_port"], r'
new_port="$(awg show awg0 listen-port)"
[[ "$new_port" != "$old_port" ]] || fail 'the port did not change on the interface'
grep -q "^ListenPort = $new_port$" "$CONF" || fail 'the configuration file has the old port'
[[ "$(grep '^H1 = ' "$CONF")" != "$old_h1" ]] || fail 'the obfuscation did not change'
awg show awg0 peers | grep -q . || fail 'clients were lost by the rotation'
echo "{\"interface\":\"awg0\",\"token\":\"$SUB\"}" | panel_mgr sub-fetch | grep -q "Endpoint = 203.0.113.10:$new_port" \
  || fail 'the subscription does not hand out the new port'
echo '{"interface":"awg0","days":7,"parts":["port"]}' | panel_mgr rotate-schedule | grep -q '"days": 7' || fail 'rotation schedule not saved'
echo '{"interface":"awg0","days":0}' | panel_mgr rotate-schedule >/dev/null
(sleep 2; python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); [s.sendto(b'x'*200, ('127.0.0.1', $new_port)) for _ in range(3)]") &
echo '{"interface":"awg0","seconds":5}' | panel_mgr probe | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["incoming"] >= 3 and r["sizes"], r'
wait

step 'Second server next to the first one'
uplink="$(ip -4 route show default | awk '{print $5; exit}')"
echo "{\"interface\":\"awg1\",\"subnet\":\"10.88.0.0/24\",\"port\":\"51999\",\"mtu\":\"1280\",\"endpoint\":\"203.0.113.10\",\"dns\":\"1.1.1.1\",\"mode\":\"split\",\"uplink\":\"$uplink\"}" | "$MGR" server-create >/dev/null
awg show awg1 >/dev/null || fail 'awg1 is not up'
echo '{"interface":"awg1","name":"second"}' | "$MGR" add | grep -q '10.88.0.' || fail 'client of awg1 has no address from its subnet'
grep -q '^H1 = ' /etc/amnezia/amneziawg/awg1.conf
[[ "$(grep '^H1 = ' /etc/amnezia/amneziawg/awg1.conf)" != "$(grep '^H1 = ' "$CONF")" ]] || fail 'both servers share H1'
"$MGR" servers | grep -q '"awg1"' || fail 'awg1 is not listed'
echo '{"interface":"awg1","confirm":"awg1"}' | "$MGR" server-delete >/dev/null
if ip link show awg1 >/dev/null 2>&1; then fail 'awg1 still exists after deletion'; fi
awg show awg0 >/dev/null || fail 'deleting awg1 hurt awg0'

step 'Change the panel port'
awg31 port 18081
panel 18081 || fail 'panel does not answer on the new port'

step 'Two-factor sign-in and its console reset'
python3 - <<'PY'
import base64, hashlib, hmac, json, os, subprocess, time, urllib.parse, urllib.request
password = open('/root/awg31-initial-password.txt').read().strip()
secret = base64.b32encode(os.urandom(20)).decode()
def code(shift=0):
    step = int(time.time() // 30) + shift
    digest = hmac.new(base64.b32decode(secret), step.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff) % 1000000:06d}'
def manager(op, payload):
    return subprocess.run(['/usr/local/sbin/awg31mgr', op], input=json.dumps(payload), text=True, capture_output=True)
assert manager('totp-enable', {'password': 'wrong-password-1', 'secret': secret, 'code': code()}).returncode != 0
assert manager('totp-enable', {'password': password, 'secret': secret, 'code': '000000'}).returncode != 0
assert manager('totp-enable', {'password': password, 'secret': secret, 'code': code()}).returncode == 0
class Stay(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None
def signed_in(**fields):
    opener = urllib.request.build_opener(Stay)
    try:
        opener.open('http://127.0.0.1:18081/login', urllib.parse.urlencode({'password': password, **fields}).encode(), timeout=30)
        return False                     # 200 = the form again
    except urllib.error.HTTPError as reply:
        return reply.code == 303
assert 'name="code"' in urllib.request.urlopen('http://127.0.0.1:18081/login', timeout=30).read().decode()
assert not signed_in(), 'password alone must not be enough'
assert signed_in(code=code(1)), 'password and code must work'
subprocess.run(['awg31', 'totp-off'], check=True)
assert signed_in(), 'console reset must bring back password-only sign-in'
print('two-factor checks passed')
PY

step 'Backup and verification'
name="$("$MGR" backup-create | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
awg31 restore-check "$name"

step 'Encrypted backup, restore from it'
AWG31_BACKUP_PASSPHRASE='smoke test passphrase 2026' awg31 backup-encryption on
sealed="$("$MGR" backup-create | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
[[ "$sealed" == *.tar.gz.gpg ]] || fail "backup is not encrypted: $sealed"
if ls /var/backups/awg31-panel/full/ | grep -qx "${sealed%.gpg}"; then fail 'a plain copy of the encrypted backup was left'; fi
if grep -aq 'manifest.json' "/var/backups/awg31-panel/full/$sealed"; then fail 'archive content is readable without the passphrase'; fi
gpg --batch --quiet --pinentry-mode loopback --passphrase 'smoke test passphrase 2026' -d "/var/backups/awg31-panel/full/$sealed" | tar tz | grep -qx manifest.json \
  || fail 'stock gpg cannot open the backup'
awg31 restore-check "$sealed"
key_before="$(grep '^PrivateKey' "$CONF")"
echo '{"interface":"awg0","name":"smoke"}' | "$MGR" delete >/dev/null
echo '{"interface":"awg0","name":"after-backup"}' | "$MGR" add >/dev/null
python3 /usr/local/libexec/awg31/scripts/restore-backup.py --apply "$sealed"
for attempt in $(seq 1 30); do panel 18081 2>/dev/null && break; sleep 1; done
panel 18081 || fail 'panel is down after the restore'
awg show awg0 >/dev/null || fail 'awg0 is down after the restore'
clients="$("$MGR" list <<<'{"interface":"awg0"}')"
grep -q '"smoke"' <<<"$clients" || fail 'the restore did not bring back a deleted client'
if grep -q '"after-backup"' <<<"$clients"; then fail 'the restore kept a client created after the backup'; fi
[[ "$(grep '^PrivateKey' "$CONF")" == "$key_before" ]] || fail 'server key changed by the restore'
awg show awg0 | grep -c '^peer' | grep -qx 5 || fail 'peers of the running interface do not match the restored state'
mv /etc/awg31-panel/backup-passphrase /root/passphrase.keep
echo 'a wrong passphrase 123456' >/etc/awg31-panel/backup-passphrase
if awg31 restore-check "$sealed" 2>/dev/null; then fail 'a wrong passphrase opened the backup'; fi
mv -f /root/passphrase.keep /etc/awg31-panel/backup-passphrase

step 'New backup passphrase re-encrypts the existing archives'
AWG31_BACKUP_PASSPHRASE='smoke NEW passphrase 2027' awg31 backup-encryption change
opens(){ gpg --batch --quiet --pinentry-mode loopback --passphrase "$1" -d "/var/backups/awg31-panel/full/$sealed" 2>/dev/null | tar tz 2>/dev/null | grep -qx manifest.json; }
opens 'smoke NEW passphrase 2027' || fail 'the archive does not open with the new passphrase'
if opens 'smoke test passphrase 2026'; then fail 'the archive still opens with the old passphrase'; fi
awg31 restore-check "$sealed"
if ls /var/backups/awg31-panel/full/ /etc/awg31-panel/ | grep -q '\.new$'; then fail 'temporary files left after the passphrase change'; fi

step 'Lasting changes from the panel ask for the panel password'
cat >/tmp/awg31-panel-call.py <<'PY'
import json, sys
sys.path.insert(0, '/opt/awg31-panel')
import awg31client
code, out, err = awg31client.call(sys.argv[1], sys.argv[2], 120)
print(code, (out or err).strip()[:200])
PY
chmod 644 /tmp/awg31-panel-call.py
panel_call(){ runuser -u awgpanel -- /opt/awg31-panel/.venv/bin/python3 /tmp/awg31-panel-call.py "$1" "$2"; }
panel_password="$(cat /root/awg31-initial-password.txt)"
for request in 'backup-encryption-set {"enabled": false}' 'backup-encryption-set {"off": true, "password": "wrong-password-0"}' \
               'backup-encryption-change {"passphrase": "smoke third passphrase 2028"}' 'telegram-disconnect {}' \
               'telegram-connect {"token": "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'; do
    panel_call ${request%% *} "${request#* }" | grep -q 'Incorrect panel password' || fail "the panel ran without its password: $request"
done
[[ -f /etc/awg31-panel/backup-passphrase ]] || fail 'encryption was switched off without the panel password'
# The same through sudo (the fallback path): SUDO_USER names the panel.
# The command fails on purpose: keep its output first, pipefail would count the failure.
sudo_reply="$(echo '{"off": true}' | runuser -u awgpanel -- sudo -n "$MGR" backup-encryption-set 2>&1 || :)"
grep -q 'Incorrect panel password' <<<"$sudo_reply" || fail "the sudo path ran without the panel password: $sudo_reply"
reply="$(PW="$panel_password" python3 -c 'import json,os; print(json.dumps({"passphrase": "smoke NEW passphrase 2027", "password": os.environ["PW"]}))')"
panel_call backup-encryption-change "$reply" | grep -q '^0 ' || fail 'the panel cannot change the passphrase with its password'
opens 'smoke NEW passphrase 2027' || fail 'the archive does not open after the change from the panel'

step 'Backups are uploaded over SFTP'
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
    id awgbackup >/dev/null 2>&1 || useradd -m -s /bin/bash awgbackup
    install -d -o awgbackup -g awgbackup -m 700 /home/awgbackup/.ssh /home/awgbackup/in
    AWG31_UNATTENDED=1 AWG31_REMOTE_HOST=127.0.0.1 AWG31_REMOTE_PORT=22 AWG31_REMOTE_USER=awgbackup AWG31_REMOTE_PATH=/home/awgbackup/in \
        awg31 backup-remote sftp </dev/null && fail 'the upload worked before the key was authorised' || :
    install -o awgbackup -g awgbackup -m 600 /etc/awg31-panel/backup-remote.key.pub /home/awgbackup/.ssh/authorized_keys
    restorecon -R /home/awgbackup 2>/dev/null || :
    awg31 backup-remote test
    [[ -f /home/awgbackup/in/awg31-connection-test.txt ]] || fail 'the SFTP test file did not arrive'
    reply="$("$MGR" backup-create)"
    sent="$(python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["uploaded"] is True, r; print(r["name"])' <<<"$reply")"
    cmp "/var/backups/awg31-panel/full/$sent" "/home/awgbackup/in/$sent" || fail 'the uploaded archive differs from the local one'
    grep -q "backup_uploaded.*$sent" /var/log/awg31-panel/audit.jsonl || fail 'the upload is not in the audit log'
    [[ "$(stat -c '%U %a' /etc/awg31-panel/backup-remote.key)" == 'root 600' ]] || fail 'the SFTP key is readable by others'
    if runuser -u awgpanel -- cat /etc/awg31-panel/backup-remote.json >/dev/null 2>&1; then fail 'the panel user can read the storage settings'; fi
    # A storage that stops accepting files must not break the backup itself.
    rm -f /home/awgbackup/.ssh/authorized_keys
    "$MGR" backup-create | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] and r["uploaded"] is False and r["upload_error"], r'
    grep -q 'backup_upload_failed' /var/log/awg31-panel/audit.jsonl || fail 'the failed upload is not in the audit log'
    awg31 backup-remote off
    userdel -r awgbackup >/dev/null 2>&1 || :
else
    [[ "${CI:-}" != true ]] || fail 'no SSH server: the SFTP upload was not checked'
    echo 'SKIPPED: no SSH server on this machine'
fi

step 'Backups are uploaded to S3-compatible storage'
# versitygw: an S3 gateway in one binary that checks SigV4 signatures and keeps
# objects as plain files (MinIO no longer publishes binaries or images).
s3_ok=0
# The GitHub API limits anonymous requests from shared addresses, so it is only the first try;
# the release page redirect (no such limit) gives the version for the usual asset names.
s3_url="$( { curl -fsSL --retry 2 ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
             https://api.github.com/repos/versity/versitygw/releases/latest 2>/dev/null || :; } \
          | grep -oiE '"browser_download_url": *"[^"]*linux[^"]*(x86_64|amd64)[^"]*\.tar\.gz"' | head -n1 | sed -E 's/.*"(https[^"]+)"$/\1/' || :)"
if [[ -z "$s3_url" ]]; then
    s3_tag="$(curl -fsSI --retry 3 https://github.com/versity/versitygw/releases/latest 2>/dev/null | tr -d '\r' \
              | sed -nE 's#^[Ll]ocation: .*/tag/(v?[0-9][0-9.]*)$#\1#p' | tail -n1 || :)"
    for name in "versitygw_${s3_tag}_Linux_x86_64.tar.gz" "versitygw_${s3_tag#v}_Linux_x86_64.tar.gz" \
                "versitygw_${s3_tag}_linux_amd64.tar.gz" "versitygw_${s3_tag#v}_linux_amd64.tar.gz"; do
        [[ -n "$s3_tag" ]] || break
        candidate="https://github.com/versity/versitygw/releases/download/$s3_tag/$name"
        if curl -fsSIL --retry 2 -o /dev/null "$candidate"; then s3_url="$candidate"; break; fi
    done
fi
echo "S3 test server: ${s3_url:-not found}"
if [[ -n "$s3_url" ]] && rm -rf /tmp/awg31-s3gw && mkdir -p /tmp/awg31-s3gw/data && curl -fsSL --retry 3 --max-time 180 "$s3_url" | tar xz -C /tmp/awg31-s3gw; then
    s3_bin="$(find /tmp/awg31-s3gw -type f -name versitygw | head -n1)"
    if [[ -n "$s3_bin" ]]; then
        chmod 755 "$s3_bin"
        "$s3_bin" --version || :
        nohup "$s3_bin" --access smokeaccess --secret smokesecret123 --port 127.0.0.1:19000 posix /tmp/awg31-s3gw/data >/tmp/awg31-s3gw.log 2>&1 &
        s3_pid=$!
        for attempt in $(seq 1 30); do
            curl --noproxy '*' -s -o /dev/null http://127.0.0.1:19000/ && s3_ok=1 && break
            sleep 1
        done
        [[ $s3_ok == 1 ]] || { tail -n 20 /tmp/awg31-s3gw.log; kill "$s3_pid" 2>/dev/null || :; }
    fi
fi
if [[ $s3_ok == 1 ]]; then
    # Create the bucket through the S3 API, signed by the console's own SigV4 code.
    python3 - <<'PY' || fail 'cannot create the test bucket'
import hashlib, importlib.util, urllib.request
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader('admin', '/usr/local/sbin/awg31admin.py')
admin = importlib.util.module_from_spec(importlib.util.spec_from_loader('admin', loader)); loader.exec_module(admin)
host, date, empty = '127.0.0.1:19000', datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'), hashlib.sha256(b'').hexdigest()
headers = {'Host': host, 'x-amz-content-sha256': empty, 'x-amz-date': date}
headers['Authorization'] = admin.s3_authorization('PUT', host, '/awg31-smoke', headers, empty, 'us-east-1', 'smokeaccess', 'smokesecret123', date)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
opener.open(urllib.request.Request('http://' + host + '/awg31-smoke', data=b'', method='PUT', headers=headers), timeout=20).read()
PY
    s3_setup(){ AWG31_UNATTENDED=1 AWG31_REMOTE_ENDPOINT=http://127.0.0.1:19000 AWG31_REMOTE_REGION=us-east-1 AWG31_REMOTE_BUCKET=awg31-smoke \
        AWG31_REMOTE_PREFIX=vpn/ AWG31_REMOTE_ACCESS_KEY=smokeaccess AWG31_REMOTE_SECRET_KEY="$1" awg31 backup-remote s3 </dev/null; }
    if s3_setup 'a-wrong-secret-key'; then fail 'the S3 server accepted a wrong secret key: the signature is not really checked'; fi
    s3_setup smokesecret123 || fail 'the S3 server refused a correctly signed upload'
    awg31 backup-remote status | grep -q 's3://awg31-smoke/vpn/' || fail 'status does not show the storage'
    if awg31 backup-remote status | grep -q smokesecret123; then fail 'status prints the secret key'; fi
    sent="$("$MGR" backup-create | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["uploaded"] is True, r; print(r["name"])')"
    cmp "/var/backups/awg31-panel/full/$sent" "/tmp/awg31-s3gw/data/awg31-smoke/vpn/$sent" || fail 'the object in the bucket differs from the local backup'
    awg31 backup-remote off
    kill "$s3_pid" 2>/dev/null || :
    rm -rf /tmp/awg31-s3gw
else
    [[ "${CI:-}" != true ]] || fail 'no S3 test server could be started: the S3 upload was not checked'
    echo 'SKIPPED: no S3 test server on this machine'
fi

step 'Logs: journals, connection history, handshake debug, support report'
echo '{"source":"panel","lines":50}' | "$MGR" logs-read | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["lines"], "the panel journal is empty"'
echo '{"source":"server:awg0","lines":20}' | "$MGR" logs-read >/dev/null || fail 'the awg-quick journal cannot be read'
if echo '{"source":"ssh"}' | "$MGR" logs-read >/dev/null 2>&1; then fail 'an unknown journal was read'; fi
echo '{"history":true,"retention_days":7,"masking":"full"}' | "$MGR" logging-set >/dev/null
[[ "$(stat -c %a /etc/awg31-panel/ip-mask.key)" == 600 ]] || fail 'the masking key is readable by others'
"$MGR" sample-all >/dev/null
echo '{"interface":"awg0","name":"ci-client"}' | "$MGR" sessions | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["history"] is True and isinstance(d["sessions"], list), d'
debug="$(echo '{"enable":true}' | "$MGR" handshake-debug 2>&1 || :)"
if [[ "$debug" == *'"enabled": true'* ]]; then
    grep -q 'amneziawg.*=p' /sys/kernel/debug/dynamic_debug/control || fail 'handshake debug is on but the kernel does not print'
    if ! systemctl is-active --quiet awg31-debug-off.timer; then
        systemctl status --no-pager awg31-debug-off.timer awg31-debug-off.service 2>&1 | head -20 || :
        systemctl list-timers --all --no-pager 2>&1 | head -20 || :
        fail 'nothing switches handshake debug off again'
    fi
    echo '{"enable":false}' | "$MGR" handshake-debug >/dev/null
    if grep -q 'amneziawg.*=p' /sys/kernel/debug/dynamic_debug/control; then fail 'handshake debug stayed on'; fi
    echo "handshake debug: on and off"
else
    echo "handshake debug not available on this kernel: $debug"
fi
"$MGR" support-report | python3 -c '
import base64, io, json, re, sys, tarfile
data = base64.b64decode(json.load(sys.stdin)["data"])
text = "".join(m.name + tarfile.open(fileobj=io.BytesIO(data)).extractfile(m).read().decode("utf-8", "replace")
               for m in tarfile.open(fileobj=io.BytesIO(data)).getmembers() if m.isfile())
key = re.search(r"PrivateKey\s*=\s*(\S+)", open("/etc/amnezia/amneziawg/awg0.conf").read()).group(1)
assert key not in text, "the server private key is in the support report"
assert "awg0.conf" in text and "journal-panel.txt" in text
print("support report:", len(data), "bytes, no private key")'
echo '{"history":false,"masking":"partial"}' | "$MGR" logging-set >/dev/null

step 'A new kernel without the module is noticed before the reboot'
bash /usr/local/libexec/awg31/scripts/kernel-check.sh >/dev/null || fail 'kernel check fails on a healthy system'
mkdir -p /lib/modules/99.0.0-awg31smoke/kernel
if bash /usr/local/libexec/awg31/scripts/kernel-check.sh >/dev/null 2>&1; then fail 'a kernel without the module was not noticed'; fi
grep -qx 'missing 99.0.0-awg31smoke' /var/lib/awg31-panel/next-kernel || fail 'the finding was not recorded'
echo '{"interface":"awg0"}' | "$MGR" diagnostics | python3 -c 'import json,sys; n=json.load(sys.stdin)["next_kernel"]; assert n == {"ok": False, "output": "99.0.0-awg31smoke"}, n'
rm -rf /lib/modules/99.0.0-awg31smoke
bash /usr/local/libexec/awg31/scripts/kernel-check.sh >/dev/null || fail 'kernel check did not recover'
echo '{"interface":"awg0"}' | "$MGR" diagnostics | python3 -c 'import json,sys; assert json.load(sys.stdin)["next_kernel"]["ok"] is True'

step 'Telegram bot: narrow sudo rule, commands, notifications'
TG=http://127.0.0.1:18443
python3 "$ROOT/tests/smoke/fake_telegram.py" 18443 &
TG_PID=$!
trap 'kill "$TG_PID" 2>/dev/null || :' EXIT
sleep 1
tg_calls(){ curl --noproxy '*' -fsS --max-time 10 "$TG/_calls"; }
tg_push(){ curl --noproxy '*' -fsS --max-time 10 -X POST --data "$1" "$TG/_push" >/dev/null; }
tg_wait(){ # tg_wait SECONDS PATTERN
    local i
    for ((i = 0; i < $1; i++)); do tg_calls | grep -q -- "$2" && return 0; sleep 1; done
    tg_calls | tail -c 1500; return 1
}
tg_text(){ printf '{"message":{"message_id":1,"text":"%s","from":{"id":%s},"chat":{"id":%s,"type":"private"}}}' "$1" "$2" "$2"; }
AWG31_TELEGRAM_API="$TG" AWG31_TELEGRAM_TOKEN="123456789:$(printf 'A%.0s' {1..35})" AWG31_TELEGRAM_ADMINS=4242 \
    AWG31_TELEGRAM_LANG=en awg31 telegram
systemctl is-active --quiet awg31-bot.service || fail 'bot service is not active'
[[ "$(stat -c '%U:%G %a' /etc/awg31-bot/telegram.json)" == 'root:awgbot 640' ]] || fail 'bot configuration has wrong owner or mode'
if runuser -u awgpanel -- cat /etc/awg31-bot/telegram.json >/dev/null 2>&1; then fail 'the panel user can read the bot token'; fi
if runuser -u awgbot -- cat /etc/awg31-panel/auth.json >/dev/null 2>&1; then fail 'the bot user can read the panel secrets'; fi
runuser -u awgbot -- sudo -n "$MGR" servers </dev/null >/dev/null || fail 'bot cannot run a permitted command'
if echo "{\"interface\":\"awg0\",\"token\":\"$SUB\"}" | runuser -u awgbot -- sudo -n "$MGR" sub-fetch >/dev/null 2>&1; then
    fail 'the bot user may read router subscriptions'
fi
id -nG awgbot | tr ' ' '\n' | grep -qx awg31ctl || fail 'awgbot is not in awg31ctl'
probe awgbot helper-only servers | grep -q '^0 ' || fail 'the bot user does not reach the helper'
for forbidden in server-delete backup-restore backup-export password-change settings; do
    probe awgbot helper-only "$forbidden" | grep -q 'Operation not permitted' || fail "the helper ran $forbidden for the bot"
done
for forbidden in server-delete backup-restore backup-export password-change settings session-revoke; do
    if echo '{"interface":"awg0","confirm":"awg0"}' | runuser -u awgbot -- sudo -n "$MGR" "$forbidden" >/dev/null 2>&1; then
        fail "bot user may run $forbidden"
    fi
done
[[ -f "$CONF" ]] || fail 'a forbidden command went through'
tg_wait 20 'bot is connected' || fail 'no test message after setup'
tg_push "$(tg_text '/add tg-client' 4242)"
tg_wait 40 'filename=\\"tg-client.conf\\"' || fail 'bot did not send the configuration file'
tg_wait 20 'filename=\\"tg-client-qr.png\\"' || fail 'bot did not send the QR code'
"$MGR" list <<<'{"interface":"awg0"}' | grep -q '"tg-client"' || fail 'client created by the bot is missing'
grep -q 'client_added.*awg0/tg-client (telegram 4242)' /var/log/awg31-panel/audit.jsonl || fail 'bot action is not in the audit log'
tg_push "$(tg_text '/add intruder' 666)"
tg_push "$(tg_text '/status' 4242)"
tg_wait 30 'Kernel module' || fail 'bot did not answer /status'
if "$MGR" list <<<'{"interface":"awg0"}' | grep -q intruder; then fail 'a stranger created a client'; fi
if tg_calls | grep -q '"chat_id": 666'; then fail 'the bot answered a stranger'; fi
# A client owner (Telegram ID stored on the client) sees their own status, read only.
echo '{"interface":"awg0","name":"tg-client","telegram_id":"777000111"}' | "$MGR" client-policy >/dev/null
"$MGR" list <<<'{"interface":"awg0"}' | grep -q '"telegram_id": "777000111"' || fail 'owner ID was not saved'
sleep 61    # the list of owners is cached for a minute
tg_push "$(tg_text '/start' 777000111)"
tg_wait 30 'Your VPN' || fail 'client owner got no status'
tg_push "$(tg_text '/add by-owner' 777000111)"
sleep 5
if "$MGR" list <<<'{"interface":"awg0"}' | grep -q by-owner; then fail 'a client owner created a client'; fi
# The configuration goes to the owner only after the administrator allows it for this client.
tg_press(){ printf '{"callback_query":{"id":"1","data":"%s","from":{"id":%s},"message":{"message_id":2,"chat":{"id":%s,"type":"private"}}}}' "$1" "$2" "$2"; }
owner_files(){ tg_calls | grep -o 'name=\\"chat_id\\"[^-]*777000111' | wc -l; }
tg_push "$(tg_press 'mc:awg0:tg-client' 777000111)"
sleep 6
[[ "$(owner_files)" == 0 ]] || fail 'the owner got a configuration without permission'
echo '{"interface":"awg0","name":"tg-client","owner_export":true}' | "$MGR" client-policy >/dev/null
tg_push "$(tg_press 'mc:awg0:tg-client' 777000111)"
for attempt in $(seq 1 30); do [[ "$(owner_files)" -ge 1 ]] && break; sleep 1; done
[[ "$(owner_files)" -ge 1 ]] || fail 'the owner did not get the configuration after it was allowed'
grep -q 'client_config_sent.*awg0/tg-client (owner 777000111)' /var/log/awg31-panel/audit.jsonl || fail 'owner download is not in the audit log'
echo '{"interface":"awg0","name":"tg-client","telegram_id":"777000222"}' | "$MGR" client-policy | grep -q '"owner_export": 0' || fail 'export permission passed to a new owner'
if echo '{"interface":"awg0","name":"tg-client","telegram_id":"@name"}' | "$MGR" client-policy >/dev/null 2>&1; then fail 'a non-numeric Telegram ID was accepted'; fi
curl --noproxy '*' -s -o /dev/null --max-time 10 -d 'password=wrong-password-456' http://127.0.0.1:18081/login || :
tg_wait 100 'Failed sign-in attempts' || fail 'no notification about a failed sign-in'
# An encrypted backup reaches the administrator as a file.
"$MGR" backup-create >/dev/null
tg_wait 100 'filename=\\"awg31-[0-9TZ-]*-[0-9a-f]*.tar.gz.gpg\\"' || fail 'the encrypted backup was not sent to Telegram'
# An invitation made in the panel turns the person who opens it into the owner.
tg_push "$(tg_text "/start $INVITE" 888000111)"
for attempt in $(seq 1 30); do "$MGR" list <<<'{"interface":"awg0"}' | grep -q '"telegram_id": "888000111"' && break; sleep 1; done
"$MGR" list <<<'{"interface":"awg0"}' | python3 -c 'import json,sys; c={x["name"]:x for x in json.load(sys.stdin)["clients"]}["team-03"]; assert c["telegram_id"]=="888000111" and c["owner_export"], c' \
  || fail 'the invitation did not make an owner'
tg_wait 30 'Invitation used' || fail 'administrators were not told about the used invitation'
grep -q 'client_invite_used.*awg0/team-03 (owner 888000111)' /var/log/awg31-panel/audit.jsonl || fail 'the used invitation is not in the audit log'
tg_push "$(tg_text "/start $INVITE" 888000222)"
tg_wait 30 'not valid' || fail 'a used invitation was accepted again'
awg31 telegram status

step 'Running the installer again updates in place'
keys_before="$(sha256sum "$CONF" | cut -d' ' -f1)"
bash "$ROOT/install.sh"
panel 18081 || fail 'panel is down after the update'
[[ "$(sha256sum "$CONF" | cut -d' ' -f1)" == "$keys_before" ]] || fail 'the update changed the VPN configuration'
systemctl is-active --quiet awg31-bot.service || fail 'bot is down after the update'
tg_push "$(tg_text '/servers' 4242)"
tg_wait 40 '"text": "<b>Servers</b>"' || fail 'bot does not answer after the update'

step 'Snapshots, rollback from the panel and from the console'
SNAP=/usr/local/libexec/awg31/scripts/awg31-snapshot.py
current="$(cat /opt/awg31-panel/VERSION)"
latest="$(python3 "$SNAP" list --json | python3 -c 'import json,sys; s=[x for x in json.load(sys.stdin) if x["usable"]]; print(s[0]["name"] if s else "")')"
[[ -n "$latest" ]] || fail 'the update did not leave a snapshot'
python3 "$SNAP" list --json | python3 -c "import json,sys; s=json.load(sys.stdin)[0]; assert s['version']=='$current' and s['reason']=='upgrade', s"
tar -tf "/var/backups/$latest/code.tar" | grep -qx 'opt/awg31-panel/web.py' || fail 'the snapshot lacks the panel'
if tar -tf "/var/backups/$latest/code.tar" | grep -q '\.venv/'; then fail 'the snapshot holds the virtualenv'; fi
# Only a newer release may be installed from the panel, and only with the password.
reply="$(PW="$panel_password" V="v$current" python3 -c 'import json,os; print(json.dumps({"action":"update","target":os.environ["V"],"password":os.environ["PW"]}))')"
panel_call update-start "$reply" | grep -q 'Only a newer release' || fail 'the panel offered to reinstall the same version'
panel_call update-start '{"action":"rollback","target":"'"$latest"'","password":"wrong-password-0"}' | grep -q 'Incorrect' \
  || fail 'a rollback started without the panel password'
reply="$(PW="$panel_password" N="$latest" python3 -c 'import json,os; print(json.dumps({"action":"rollback","target":os.environ["N"],"password":os.environ["PW"]}))')"
panel_call update-start "$reply" | grep -q '^0 ' || fail 'the panel could not start a rollback'
for attempt in $(seq 1 90); do
    state="$(panel_call update-status '{}' 2>/dev/null | sed -nE 's/.*"status": "([a-z]+)".*/\1/p' | head -n1)"
    [[ "$state" == ok || "$state" == failed ]] && break
    sleep 2
done
if [[ "$state" != ok ]]; then
    panel_call update-status '{}' | head -c 3000; echo
    systemctl status awg31-update.service --no-pager 2>&1 | tail -n 20 || :
    journalctl -u awg31-update.service --no-pager -n 60 2>&1 || :
    ls -la /run/awg31-update-run.* /var/log/awg31-panel/ 2>&1 || :
    cat /var/log/awg31-panel/update.log 2>&1 || :
    fail "the rollback from the panel ended as: ${state:-unknown}"
fi
grep -q 'Rolled back' /var/log/awg31-panel/update.log || fail 'the rollback log is empty'
grep -q 'panel_rolled_back' /var/log/awg31-panel/audit.jsonl || fail 'the rollback is not in the audit log'
panel 18081 || fail 'panel is down after the rollback'
[[ "$(sha256sum "$CONF" | cut -d' ' -f1)" == "$keys_before" ]] || fail 'the rollback changed the VPN configuration'
python3 "$SNAP" list | grep -q 'before rollback' || fail 'the state before the rollback was not saved'
# The console command goes back to the state before that rollback.
awg31 rollback --yes >/tmp/awg31-rollback.txt 2>&1 || { cat /tmp/awg31-rollback.txt; fail 'awg31 rollback failed'; }
panel 18081 || fail 'panel is down after the console rollback'
[[ "$(awg31 version)" == "$current" ]] || fail 'the console rollback changed the version unexpectedly'
runuser -u awgpanel -- sudo -n "$MGR" servers </dev/null >/dev/null || fail 'panel sudo permission broken after the rollback'
systemctl is-active --quiet awg31-helper.service awg31-bot.service || fail 'helper or bot is down after the rollback'
[[ "$(python3 "$SNAP" list --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" -le 5 ]] || fail 'more than five snapshots are kept'

step 'Uninstall with purge'
bash /usr/local/libexec/awg31/scripts/uninstall.sh --purge --yes
if ip link show awg0 >/dev/null 2>&1; then fail 'awg0 still exists'; fi
if systemctl is-active --quiet awg31-panel.service; then fail 'panel service is still running'; fi
if ss -H -ltn 'sport = :18081' | grep -q .; then fail 'something still listens on the panel port'; fi
if systemctl list-timers --all --no-legend | grep -q awg31; then fail 'timers left behind'; fi
if forward | grep -q awg0; then forward; fail 'firewall rules left behind'; fi
if systemctl is-active --quiet awg31-bot.service; then fail 'bot service is still running'; fi
if systemctl is-active --quiet awg31-helper.service; then fail 'control helper is still running'; fi
if getent group awg31ctl >/dev/null; then fail 'group awg31ctl left behind'; fi
if id awgbot >/dev/null 2>&1; then fail 'bot user left behind'; fi
for path in /opt/awg31-panel /etc/awg31-panel /var/lib/awg31-panel /usr/local/bin/awg31 /etc/sudoers.d/awg31-panel "$CONF" \
            /etc/awg31-bot /var/lib/awg31-bot /etc/sudoers.d/awg31-bot /etc/systemd/system/awg31-bot.service \
            /usr/local/sbin/awg31helper /etc/systemd/system/awg31-helper.service /run/awg31/control.sock; do
    [[ ! -e "$path" ]] || fail "left behind: $path"
done

step 'Fresh installation over stray files from a failed first attempt'
install -d /opt/awg31-panel
cp "$ROOT/src/web.py" /opt/awg31-panel/web.py
cp "$ROOT/src/awg31ctl" /usr/local/sbin/awg31ctl
# AWG31_SMOKE_NGINX=no skips the proxy part (Rocky with SELinux needs port 443 and an interactive consent).
WITH_NGINX="${AWG31_SMOKE_NGINX:-yes}"
if [[ "$WITH_NGINX" == yes ]]; then
    export AWG31_NGINX_CHOICE=1 AWG31_NGINX_HOST=203.0.113.10 AWG31_NGINX_HTTPS_PORT=8443 AWG31_NGINX_ALLOW='198.51.100.7, 192.0.2.0/24'
fi
AWG31_PANEL_PORT=18082 \
  AWG31_TELEGRAM_API="$TG" AWG31_TELEGRAM_TOKEN="123456789:$(printf 'B%.0s' {1..35})" AWG31_TELEGRAM_ADMINS='4242, 4343' \
  AWG31_TELEGRAM_NOTIFY=server,backups bash "$ROOT/install.sh"
panel 18082 || fail 'panel does not answer after reinstall'
awg show awg0 >/dev/null || fail 'awg0 is not up after reinstall'

step 'Telegram bot enabled by the unattended installer, then switched off'
systemctl is-active --quiet awg31-bot.service || fail 'the installer did not start the bot'
awg31 telegram status | tee /tmp/awg31-telegram-status
grep -q '4242, 4343' /tmp/awg31-telegram-status || fail 'administrators were not saved'
grep -q 'server, backups' /tmp/awg31-telegram-status || fail 'notification choice was not saved'
if grep -q BBBBB /tmp/awg31-telegram-status; then fail 'status prints the token'; fi
awg31 telegram off
if systemctl is-active --quiet awg31-bot.service; then fail 'bot still runs after telegram off'; fi
# Removing the bot's sudo rule also closes the helper to it.
probe awgbot helper-only servers | grep -q 'Operation not permitted' || fail 'the helper still serves the bot after telegram off'
[[ ! -e /etc/awg31-bot/telegram.json && ! -e /etc/sudoers.d/awg31-bot ]] || fail 'token or sudo rule left after telegram off'
if runuser -u awgbot -- sudo -n "$MGR" servers </dev/null >/dev/null 2>&1; then fail 'bot user keeps sudo after telegram off'; fi

if [[ "$WITH_NGINX" != yes ]]; then
    bash /usr/local/libexec/awg31/scripts/uninstall.sh --purge --yes
    printf '\nSMOKE TEST PASSED (without the Nginx part)\n'
    exit 0
fi

step 'Nginx HTTPS proxy: health, HSTS, allow list, sign-in limit'
https(){ curl --noproxy '*' -ksS --max-time 10 --resolve 203.0.113.10:8443:127.0.0.1 "$@"; }
nginx -t
https -f https://203.0.113.10:8443/health >/dev/null || fail 'HTTPS proxy does not answer'
https -D - -o /dev/null https://203.0.113.10:8443/login | tee /tmp/awg31-headers
grep -qi '^strict-transport-security: max-age=31536000' /tmp/awg31-headers || fail 'HSTS header missing'
grep -q 'allow 198.51.100.7;' /etc/nginx/conf.d/awg31-panel.conf || fail 'allow list missing in the site'
grep -q 'deny all;' /etc/nginx/conf.d/awg31-panel.conf || fail 'deny all missing in the site'
codes="$(for attempt in $(seq 1 14); do https -o /dev/null -w '%{http_code}\n' https://203.0.113.10:8443/login; done | sort | uniq -c)"
echo "$codes"
grep -q ' 429$' <<<"$codes" || fail 'sign-in requests are not rate limited'
grep -q ' 200$' <<<"$codes" || fail 'every sign-in request was rejected'
awg31 port 18083
# `nginx reload` hands over to new workers asynchronously: allow it a moment.
proxied=0
for attempt in $(seq 1 10); do
    if https -f https://203.0.113.10:8443/health >/dev/null 2>&1; then proxied=1; break; fi
    sleep 1
done
((proxied)) || fail 'HTTPS proxy lost the panel after the port change'
grep -q '127.0.0.1:18083;' /etc/nginx/conf.d/awg31-panel.conf || fail 'Nginx site still points to the old port'

bash /usr/local/libexec/awg31/scripts/uninstall.sh --purge --yes
[[ ! -e /etc/nginx/conf.d/awg31-panel.conf ]] || fail 'Nginx site left behind'
nginx -t

printf '\nSMOKE TEST PASSED\n'

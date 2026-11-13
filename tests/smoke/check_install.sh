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

step 'Unattended installation'
bash "$ROOT/install.sh"
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
assert opener.open(base + '/', timeout=30).status == 200
opener.open(base + '/logout', timeout=30)
try:
    final = opener.open(base + '/servers/awg0/clients', timeout=30).geturl()
except Exception as exc:
    final = str(exc)
assert '/login' in final, 'still signed in after logout: ' + final
print('panel checks passed')
PY
awg show awg0 | grep -c '^peer' | grep -qx 2 || fail 'expected two peers on awg0'

step 'Isolate clients, close private networks'
echo '{"interface":"awg0","client_to_client":"off","private_access":"off"}' | "$MGR" settings
forward
forward | grep -q -- '-i awg0 -o awg+ -j DROP' || fail 'isolation rule missing'
forward | grep -q -- '-d 10.0.0.0/8 -i awg0' || forward | grep -q -- '-d 10.0.0.0/8 .*-j DROP' || fail 'private network rule missing'
if forward | grep -q -- '-i awg0 -o awg0 -j ACCEPT'; then fail 'allow rule survived isolation'; fi
echo '{"interface":"awg0","client_to_client":"on","private_access":"on"}' | "$MGR" settings
if forward | grep -q -- '-o awg+ -j DROP'; then fail 'isolation rule survived'; fi

step 'Change the panel port'
awg31 port 18081
panel 18081 || fail 'panel does not answer on the new port'

step 'Backup and verification'
name="$("$MGR" backup-create | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
awg31 restore-check "$name"

step 'Running the installer again updates in place'
keys_before="$(sha256sum "$CONF" | cut -d' ' -f1)"
bash "$ROOT/install.sh"
panel 18081 || fail 'panel is down after the update'
[[ "$(sha256sum "$CONF" | cut -d' ' -f1)" == "$keys_before" ]] || fail 'the update changed the VPN configuration'

step 'Uninstall with purge'
bash /usr/local/libexec/awg31/scripts/uninstall.sh --purge --yes
if ip link show awg0 >/dev/null 2>&1; then fail 'awg0 still exists'; fi
if systemctl is-active --quiet awg31-panel.service; then fail 'panel service is still running'; fi
if ss -H -ltn 'sport = :18081' | grep -q .; then fail 'something still listens on the panel port'; fi
if systemctl list-timers --all --no-legend | grep -q awg31; then fail 'timers left behind'; fi
if forward | grep -q awg0; then forward; fail 'firewall rules left behind'; fi
for path in /opt/awg31-panel /etc/awg31-panel /var/lib/awg31-panel /usr/local/bin/awg31 /etc/sudoers.d/awg31-panel "$CONF"; do
    [[ ! -e "$path" ]] || fail "left behind: $path"
done

step 'Fresh installation over stray files from a failed first attempt'
install -d /opt/awg31-panel
cp "$ROOT/src/web.py" /opt/awg31-panel/web.py
cp "$ROOT/src/awg31ctl" /usr/local/sbin/awg31ctl
AWG31_PANEL_PORT=18082 AWG31_NGINX_CHOICE=1 AWG31_NGINX_HOST=203.0.113.10 AWG31_NGINX_HTTPS_PORT=8443 \
  AWG31_NGINX_ALLOW='198.51.100.7, 192.0.2.0/24' bash "$ROOT/install.sh"
panel 18082 || fail 'panel does not answer after reinstall'
awg show awg0 >/dev/null || fail 'awg0 is not up after reinstall'

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

#!/usr/bin/env bash
# Runs an update or a rollback started from the web panel, in its own transient
# systemd unit: the panel, the helper and the bot restart during the update,
# and this keeps going. Progress goes to a log the panel shows; the outcome to
# a small state file and to the audit log (the bot reports it).
#   update-run.sh update v1.2.3
#   update-run.sh rollback awg31-upgrade.NAME
set -uo pipefail
STATE="${AWG31_UPDATE_STATE:-/var/lib/awg31-panel/update-state.json}"
LOG="${AWG31_UPDATE_LOG:-/var/log/awg31-panel/update.log}"
VERSION_FILE="${AWG31_APP_VERSION:-/opt/awg31-panel/VERSION}"
MENU="${AWG31_MENU:-/usr/local/bin/awg31}"
MGR="${AWG31_MGR:-/usr/local/sbin/awg31mgr}"
SNAPSHOT="${AWG31_SNAPSHOT_TOOL:-/usr/local/libexec/awg31/scripts/awg31-snapshot.py}"
action="${1:-}" target="${2:-}"
case "$action" in
    update) [[ "$target" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version: $target" >&2; exit 2; } ;;
    rollback) [[ "$target" =~ ^awg31-upgrade\.[A-Za-z0-9_.-]{4,64}$ ]] || { echo "invalid snapshot: $target" >&2; exit 2; } ;;
    *) echo 'usage: update-run.sh update vX.Y.Z | rollback SNAPSHOT' >&2; exit 2 ;;
esac
umask 022
mkdir -p "$(dirname "$STATE")" "$(dirname "$LOG")"
from="$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || :)"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
state(){ # state STATUS CODE
    local finished=''
    [[ "$1" == running ]] || finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    python3 - "$STATE" "$1" "$action" "$target" "$from" "$started" "$finished" "$2" "$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || :)" <<'PY'
import json, os, sys
path, status, action, target, source, started, finished, code, now = sys.argv[1:]
tmp = path + '.tmp'
with open(tmp, 'w') as out:
    json.dump({'status': status, 'action': action, 'target': target, 'from': source, 'version': now,
               'started': started, 'finished': finished, 'code': int(code)}, out)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}
audit(){ printf '{"event":"%s","target":"%s"}' "$1" "$2" | "$MGR" audit >/dev/null 2>&1 || :; }
: > "$LOG"; chmod 640 "$LOG"
exec >>"$LOG" 2>&1
state running 0
echo "[$started] $action $target (installed: ${from:-unknown})"
if [[ "$action" == update ]]; then
    AWG31_UNATTENDED=1 "$MENU" update "$target" </dev/null
    code=$?
else
    python3 "$SNAPSHOT" restore "$target" </dev/null
    code=$?
fi
now="$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || :)"
if [[ $code -eq 0 ]]; then
    state ok 0
    [[ "$action" == update ]] && audit panel_updated "${from:-?} → ${now:-?}"
    echo "[$(date -u +%H:%M:%S)] done: ${from:-?} → ${now:-?}"
else
    state failed "$code"
    [[ "$action" == update ]] && audit panel_update_failed "$target (exit $code)"
    echo "[$(date -u +%H:%M:%S)] failed with exit code $code; installed now: ${now:-unknown}"
fi
exit "$code"

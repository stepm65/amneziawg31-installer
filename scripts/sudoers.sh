#!/usr/bin/env bash
# Single source of truth for the panel's sudo allowlist.
# Sourced by scripts/setup-wizard.sh, scripts/upgrade-core.sh and scripts/resume-panel.sh so
# the three installers can never drift apart again. Sourcing has no side effects.
#
# Every entry is one exact `awg31mgr <command>` pair: no wildcards, no arguments.
# Root-only operations (init, sample-all, backup-run, password-reset) are
# deliberately absent: they are started by systemd or from a root shell.
AWG31_SUDO_COMMANDS=(
  servers server-create server-start server-stop server-restart server-delete
  status list add download enable disable delete delete-batch settings
  client-network client-policy history host-history diagnostics
  profile-export profile-import
  backup-create backup-list backup-export backup-delete backup-policy
  backup-policy-set backup-check backup-restore
  audit audit-list password-change session-revoke obfuscation-generate
)

# The Telegram bot runs as its own user with a narrower list: it cannot delete
# a server, restore or download a backup, change settings or the panel password.
AWG31_BOT_SUDO_COMMANDS=(
  servers server-start server-stop server-restart
  list add download enable disable delete client-policy
  diagnostics backup-create backup-list audit audit-list
)

awg31_render_bot_sudoers() {
  local manager="${1:-/usr/local/sbin/awg31mgr}" line='' command
  for command in "${AWG31_BOT_SUDO_COMMANDS[@]}"; do
    line+="${line:+, }$manager $command"
  done
  printf 'awgbot ALL=(root) NOPASSWD: %s\n' "$line"
}

awg31_install_bot_sudoers() {
  local target="${1:-/etc/sudoers.d/awg31-bot}" candidate
  candidate="$(mktemp /etc/sudoers.d/.awg31-bot.XXXXXX)" || return 1
  if ! { awg31_render_bot_sudoers >"$candidate" && chmod 440 "$candidate" &&
         visudo -cf "$candidate" >/dev/null &&
         install -o root -g root -m 440 "$candidate" "$target"; }; then
    rm -f -- "$candidate"
    return 1
  fi
  rm -f -- "$candidate"
  visudo -cf "$target" >/dev/null
}

awg31_render_sudoers() {
  local manager="${1:-/usr/local/sbin/awg31mgr}" line='' command
  for command in "${AWG31_SUDO_COMMANDS[@]}"; do
    line+="${line:+, }$manager $command"
  done
  printf 'awgpanel ALL=(root) NOPASSWD: %s\n' "$line"
}

# Validate a candidate in an ignored (dot-prefixed) file, then install it.
awg31_install_sudoers() {
  local target="${1:-/etc/sudoers.d/awg31-panel}" candidate
  candidate="$(mktemp /etc/sudoers.d/.awg31-panel.XXXXXX)" || return 1
  if ! { awg31_render_sudoers >"$candidate" && chmod 440 "$candidate" &&
         visudo -cf "$candidate" >/dev/null &&
         install -o root -g root -m 440 "$candidate" "$target"; }; then
    rm -f -- "$candidate"
    return 1
  fi
  rm -f -- "$candidate"
  visudo -cf "$target" >/dev/null
}

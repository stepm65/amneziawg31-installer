# Security notes

- Never share client `.conf`, `vpn://` link, private key, preshared key or QR; all of them can grant VPN access.
- The web panel listens on `127.0.0.1` and must be exposed only via a properly secured HTTPS reverse proxy.
- Keep Secure Boot enabled when feasible; register DKMS key via MOK when needed.
- Validate systemd, firewall rules and SELinux policy on the intended target OS before deploying.
- Do not commit files from `/etc/amnezia`, `/var/lib/awg31-panel`, auth JSON, certificates, production logs or backups.
- The project has not been independently security-audited. Report vulnerabilities privately to the repository owner through GitHub (Security → Report a vulnerability) instead of a public issue.

## Control helper

- The panel and the bot do not start `sudo` for every call. They talk to `awg31-helper.service`, a root service on `/run/awg31/control.sock` (owner `root:awg31ctl`, mode 0660; only `awgpanel` and `awgbot` are in the group).
- The helper does not have a permission list of its own. On every request it reads `/etc/sudoers.d/awg31-panel` and `/etc/sudoers.d/awg31-bot` (only if owned by root and not writable by others) and allows exactly the `awg31mgr` operations listed there for the calling user. The caller is identified by the kernel (`SO_PEERCRED`). Console-only operations (`password-reset`, `totp-reset`, `backup-encryption-set`, `init`, `sample-all`, `backup-run`) are in no rule and are refused.
- A request carries only an operation name and the JSON that sudo would have received on stdin: no paths, arguments or environment. Requests are limited to 64 KiB and 150 seconds.
- If the helper is not running, the panel and the bot fall back to `sudo` with the same rules. A request that has already reached the helper is never repeated through sudo.

## Telegram bot

- The bot is a separate service running as the user `awgbot`. Its `sudo` rule (`/etc/sudoers.d/awg31-bot`) lists fewer commands than the panel's: it cannot delete or create a server, change settings, restore, download or delete a backup, or change the panel password. The limit is enforced by `sudo`, not by the bot's own code.
- `awgbot` cannot read the panel secrets (`/etc/awg31-panel`), and the panel user cannot read the bot token (`/etc/awg31-bot/telegram.json`, mode 0640 `root:awgbot`).
- Only the listed numeric Telegram IDs are administrators, in private chats only. A Telegram ID stored on a client gives that person one read-only status screen for that client: no actions, no other clients, and no configuration unless the administrator turns on the per-client export switch (off by default, reset when the owner changes, every download audited and reported). Requests from such owners are rate limited, and unknown users cost one cached lookup per minute at most. The bot uses long polling: no webhook and no inbound port.
- Client configurations sent by the bot contain private keys and are stored by Telegram. An administrator's Telegram account is therefore as sensitive as the panel password for client management.
- Backup archives are never sent to Telegram.

## Added in 0.10

- **Two-factor sign-in.** TOTP (RFC 6238). Turning it on or off needs the password and a valid code; a code is accepted once. Console recovery: `sudo awg31 totp-off` (root only, not reachable from the panel or the bot).
- **Backup encryption.** OpenPGP symmetric encryption (AES-256) with one passphrase stored in `/etc/awg31-panel/backup-passphrase` (root only; the panel user cannot read it). It can be set and removed only from the root console. The bot may fetch an archive only if it is encrypted.
- **Viewers** of the Telegram bot have no action buttons, and every action is refused for them in the handler as well.
- **Bot settings in the panel** edit administrators, viewers and notifications; the token is never returned to the panel.
- **Host protection.** A per-server switch drops what clients send to the server itself, except replies, ping and DNS.


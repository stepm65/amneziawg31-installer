# Security notes

- Never share client `.conf`, `vpn://` link, private key, preshared key or QR; all of them can grant VPN access.
- The web panel listens on `127.0.0.1` and must be exposed only via a properly secured HTTPS reverse proxy.
- Keep Secure Boot enabled when feasible; register DKMS key via MOK when needed.
- Validate systemd, firewall rules and SELinux policy on the intended target OS before deploying.
- Do not commit files from `/etc/amnezia`, `/var/lib/awg31-panel`, auth JSON, certificates, production logs or backups.
- The project has not been independently security-audited. Report vulnerabilities privately to the repository owner through GitHub (Security → Report a vulnerability) instead of a public issue.

## Control helper

- The panel and the bot do not start `sudo` for every call. They talk to `awg31-helper.service`, a root service on `/run/awg31/control.sock` (owner `root:awg31ctl`, mode 0660; only `awgpanel` and `awgbot` are in the group).
- The helper does not have a permission list of its own. On every request it reads `/etc/sudoers.d/awg31-panel` and `/etc/sudoers.d/awg31-bot` (only if owned by root and not writable by others) and allows exactly the `awg31mgr` operations listed there for the calling user. The caller is identified by the kernel (`SO_PEERCRED`). Console-only operations (`password-reset`, `totp-reset`, `backup-encryption-change`, `backup-remote-set`, `backup-remote-test`, `init`, `sample-all`, `backup-run`) are in no rule and are refused. Enabling/disabling backup encryption is available to an authenticated panel administrator, but the passphrase remains root-only.
- A request carries only an operation name and the JSON that sudo would have received on stdin: no paths, arguments or environment. Requests are limited to 64 KiB and 150 seconds.
- If the helper is not running, the panel and the bot fall back to `sudo` with the same rules. A request that has already reached the helper is never repeated through sudo.

## Telegram bot

- The bot is a separate service running as the user `awgbot`. Its `sudo` rule (`/etc/sudoers.d/awg31-bot`) lists fewer commands than the panel's: it cannot delete or create a server, change settings, restore, download or delete a backup, or change the panel password. The limit is enforced by `sudo`, not by the bot's own code.
- `awgbot` cannot read the panel secrets (`/etc/awg31-panel`), and the panel user cannot read the bot token (`/etc/awg31-bot/telegram.json`, mode 0640 `root:awgbot`).
- Only the listed numeric Telegram IDs are administrators, in private chats only. A Telegram ID stored on a client gives that person one read-only status screen for that client: no actions, no other clients, and no configuration unless the administrator turns on the per-client export switch (off by default, reset when the owner changes, every download audited and reported). Requests from such owners are rate limited, and unknown users cost one cached lookup per minute at most. The bot uses long polling: no webhook and no inbound port.
- Client configurations sent by the bot contain private keys and are stored by Telegram. An administrator's Telegram account is therefore as sensitive as the panel password for client management.
- Backup archives are never sent to Telegram.

## Panel password for lasting changes (0.12.5)

A valid panel session is not enough for changes that outlive it. The panel password is asked again for: connecting or disconnecting the Telegram bot, changing the bot's administrators or viewers, enabling, disabling or changing backup encryption. Replacing the TOTP key needs a code of the current key as well. The controller recognises panel requests by the caller the kernel reports to the control helper (`SO_PEERCRED`) or by `SUDO_USER` on the sudo path; a request cannot claim to come from the console. The root console is not asked.

## Logs and client addresses (0.14)

- The journal viewer reads a fixed list of systemd units and the kernel journal (only AmneziaWG lines) through `awg31mgr logs-read`; the source, level, line count and search text are checked, and no other `journalctl` arguments can be passed.
- Public IP addresses are masked when they are written (connection history, audit log, and so the bot's notifications) and when journal lines are shown. Full masking stores an HMAC-SHA-256 label made with a random per-server key in `/etc/awg31-panel/ip-mask.key` (root, 0600): the same address gets the same label, and the label cannot be turned back into the address without the key. Changing the masking does not rewrite entries already stored.
- Connection history is off by default; entries older than the retention period are deleted every minute, and a deleted client's history is deleted with it.
- Handshake debug writes to `/sys/kernel/debug/dynamic_debug/control` and schedules a systemd timer that switches it off after 15 minutes, so it cannot be left on by accident.
- The support report removes keys (`[key]`), Telegram tokens (`[token]`), `PrivateKey`/`PresharedKey`/`PublicKey`/`HeaderProtectionKey`/`Endpoint` lines and public addresses (always fully masked). It is generated on request and not stored on the server.

## Moving clients and owner delivery (0.18)

- `awg31mgr client-move` copies the whole client record, keys included, between two servers' databases as root. The two steps it uses (`client-export`, `client-import`) are in no sudo list; the panel may run only `client-move`, the bot not even that. If removing the client from the old server fails, it is removed from the new one again, so one key is never active on two servers.
- After a rotation, a masking profile or a move, the bot sends the new configuration only to owners whose client allows it (the same switch as for the bot's Config button), never to administrators' own clients, routers with a subscription or switched-off clients.
- The bot's unit adds `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `ProtectHostname`, `ProtectControlGroups` and `SystemCallArchitectures=native`. `NoNewPrivileges` and the kernel module/tunable protections are left out on purpose: they would also bind the root `awg31mgr` that the bot reaches through sudo when the control helper is down.
- The packet check no longer holds the controller lock while it listens.

## Router subscriptions, rotation and the packet check (0.17)

- A subscription link carries a 256-bit random token; the database keeps only `sha256("awg31-sub:" + token)`, and the panel shows the link once. Issuing a new link or switching the subscription off invalidates the old one at once. The link returns the client's private key, so the panel offers it only when an Nginx HTTPS site exists; for a self-signed certificate the router script pins the certificate's public key.
- `/sub/` is the only path that answers without a session. Nginx admits every address there (the panel's allow list does not apply) but limits it to 30 requests a minute per address; the panel adds its own limit and makes an address wait 15 minutes after 10 unknown tokens. The panel trusts `X-Real-IP` only from 127.0.0.1, i.e. from Nginx. A switched-off client gets 403 and no configuration. Fetch time and the (masked) address are recorded.
- The panel user may create, revoke and fetch subscriptions; the bot user may not. The bot may run the packet check and the port/obfuscation change, as the administrator could from the server screen.
- Rotation and masking profiles save a copy of the server configuration and state first (`/var/backups/awg31-panel/settings`). Only ufw and firewalld are changed for the new port; nothing else in the host firewall is touched.
- The packet check opens an `AF_PACKET` socket as root for 5–30 seconds, reads only UDP headers to and from the server port and returns counts, sizes and masked sender addresses; no payload is stored.
- `/etc/sysctl.d/96-awg31-network.conf` sets loose reverse-path filtering, refuses ICMP redirects and source routing, stops sending redirects and enables SYN cookies. It is removed on uninstall.

## Added in 0.10

- **Two-factor sign-in.** TOTP (RFC 6238). Turning it on or off needs the password and a valid code; replacing the key needs the password, a code of the current key and a code of the new one. A code is accepted once. Console recovery: `sudo awg31 totp-off` (root only, not reachable from the panel or the bot).
- **Backup encryption.** OpenPGP symmetric encryption (AES-256) with one passphrase stored in `/etc/awg31-panel/backup-passphrase` (root only; the panel user cannot read it). From the panel encryption can be enabled, removed or given a new passphrase (16–200 characters, existing archives are re-encrypted); the panel can never read the passphrase. The bot may fetch an archive only if it is encrypted.
- **Viewers** of the Telegram bot have no action buttons, and every action is refused for them in the handler as well.
- **Bot settings in the panel** edit administrators, viewers and notifications; an already configured bot's token is never returned to the panel. Connecting a new token requires selecting an administrator who sent `/start` in a private chat; their `/start` is not authorization by itself. The discovery helper is root-owned and uses only the standard library; provisioning, unit and sudoers definitions follow `scripts/sudoers.sh`. Between discovery and explicit confirmation the token is kept only in `/etc/awg31-bot/telegram-pending.json` (mode 0600, `root:root`) for at most 15 minutes. The browser receives a random one-time setup ID, never this pending token. Cancellation, disconnection, successful setup, service failure or a new attempt removes the pending file.
- **Host protection.** A per-server switch drops what clients send to the server itself, except replies, ping and DNS.
- **Remote backup storage.** Only encrypted archives are uploaded. S3 keys (`/etc/awg31-panel/backup-remote.json`) and the SFTP private key are readable by root only and are set from the root console; the panel sees only the storage address. SFTP pins the host key at the first connection.

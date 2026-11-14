# Security notes

- Never share client `.conf`, `vpn://` link, private key, preshared key or QR; all of them can grant VPN access.
- The web panel listens on `127.0.0.1` and must be exposed only via a properly secured HTTPS reverse proxy.
- Keep Secure Boot enabled when feasible; register DKMS key via MOK when needed.
- Validate systemd, firewall rules and SELinux policy on the intended target OS before deploying.
- Do not commit files from `/etc/amnezia`, `/var/lib/awg31-panel`, auth JSON, certificates, production logs or backups.
- The project has not been independently security-audited. Report vulnerabilities privately to the repository owner through GitHub (Security → Report a vulnerability) instead of a public issue.

## Telegram bot

- The bot is a separate service running as the user `awgbot`. Its `sudo` rule (`/etc/sudoers.d/awg31-bot`) lists fewer commands than the panel's: it cannot delete or create a server, change settings, restore, download or delete a backup, or change the panel password. The limit is enforced by `sudo`, not by the bot's own code.
- `awgbot` cannot read the panel secrets (`/etc/awg31-panel`), and the panel user cannot read the bot token (`/etc/awg31-bot/telegram.json`, mode 0640 `root:awgbot`).
- Only the listed numeric Telegram IDs are served, in private chats only. The bot uses long polling: no webhook and no inbound port.
- Client configurations sent by the bot contain private keys and are stored by Telegram. An administrator's Telegram account is therefore as sensitive as the panel password for client management.
- Backup archives are never sent to Telegram.

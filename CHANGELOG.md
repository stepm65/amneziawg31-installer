# Changelog

What is new in each release. The release script puts the section of its version into the GitHub release text.
Русский: [CHANGELOG.ru.md](CHANGELOG.ru.md).

## [0.29.0] — 2026-11-28

- **Changelog in releases:** this file and its Russian version; the GitHub release text is built from the section of its version.
- **Signed releases:** a GitHub build provenance attestation is published for the release archive. Check it with `gh attestation verify awg31-console-vX.Y.Z.tar.gz --repo stepm65/amneziawg31-installer`; the installer does it itself with `AWG31_ATTESTATION=require`.
- **“What to do if…” guide** ([docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)): the module after a kernel change, a forgotten password or name, a lost TOTP or passkey, a blocked port or IP, moving to a new server, a failed update and more.

## [0.28.0] — 2026-11-28

- **Client access schedule:** days, from–to time and a time zone; outside the window the client switches off by itself and comes back. Windows over midnight.
- **Access requests in the bot** (optional): a stranger presses “Ask for access”, an administrator Grant or Refuse; granting makes a client from a template and makes the person its owner.
- **Message to owners** from the bot (📣 Message owners) and from the panel, with an optional “My connections” button.

## [0.27.0] — 2026-11-28

- **Scheduled backup checks** (weekly or every backup): the restore validation plus a byte-for-byte compare of the copy in the remote storage; a bot notice on failure; `sudo awg31 backup-verify`.
- **Configurable traffic history retention** (servers 32 days, clients 62, 7 to 730); weekly database compaction, a Compact now button, `sudo awg31 db-vacuum`.
- **Prometheus metrics** behind a token: servers, clients, traffic, backups; Maintenance → Monitoring.

## [0.26.0] — 2026-11-28

- Your own panel sign-in name: the setup wizard asks for it with the password (`AWG31_ADMIN_NAME`); accounts can be renamed; `sudo awg31 reset-password` shows and changes the name.

## [0.25.0] — 2026-11-28

- Passkey sign-in (WebAuthn): the device's fingerprint, face or PIN instead of a password and code. No new dependencies.

## [0.24.0] — 2026-11-28

- Several panel accounts with the roles administrator and viewer; the account name in the audit log and bot notices.
- A list of active sessions where any can be ended; Log out ends only the current session.

## [0.23.0] — 2026-11-28

- Deleting rollback snapshots (panel and `awg31 rollback delete`).
- A client traffic chart for 24 hours, 7 and 30 days.
- A one-time configuration link for somebody without Telegram.

## [0.22.0–0.22.1] — 2026-11-28

- A setup wizard on whiptail screens: language, one settings screen, checks before installing, a progress bar with a log; the server domain in the wizard.

## [0.21.0] — 2026-11-28

- Importing clients from wg-easy, 3x-ui, AmneziaVPN and any `.conf`: in the panel with a preview and with `sudo awg31 import`.

## [0.20.0] — 2026-11-28

- Owners with several devices and shared limits (traffic, term, device count), adding a device oneself in the bot.

## [0.19.7–0.19.8] — 2026-11-27

- Clear units on traffic charts; an optional server domain in client configurations instead of the IP.

## [0.19.0–0.19.6] — 2026-11-22

- Client groups and filters, a blocking signal, new configurations for owners after settings changes; a new look of the console; separate download and upload speed limits.

## [0.18.0] — 2026-11-22

- New configurations for owners after parameter changes, moving a client to another server, random subnets, Steam and Custom profiles.

## [0.17.0] — 2026-11-22

- Router subscriptions over HTTPS, port and obfuscation rotation by button and schedule, masking profiles, an incoming packet check, MSS clamping, protective sysctls.

## [0.16.0] — 2026-11-20

- A snapshot before every update and `awg31 rollback`, updating and rolling back from the panel, browser checks of every page under the CSP.

## [0.15.0] — 2026-11-20

- Bot invitations by one-time link, client key replacement, TOTP recovery codes, actions on selected clients, CSV export.

Earlier releases are in the commit history.

# What to do if…

Short recipes for common trouble. Every command runs on the server itself as root (`sudo`). Русский: [TROUBLESHOOTING.ru.md](TROUBLESHOOTING.ru.md).

If nothing helps, make a **support report** (Maintenance → Logs → Support report). Keys, tokens and public addresses are replaced in it, but look through it before you send it.

## The panel does not open

1. `sudo awg31 status` shows whether the panel and the VPN servers run.
2. `sudo awg31 restart-panel` restarts only the panel (the VPN is not touched). Then `sudo awg31 logs` shows its journal.
3. The panel listens on `127.0.0.1` only. Without HTTPS, use an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 root@SERVER`, then open `http://localhost:8080` (use your panel port).
4. Another program took the port: `sudo awg31 port NEW_PORT`.
5. For HTTPS access run `sudo awg31 nginx`. If the site has an address allow list, check that your address is on it.

## Forgotten password or sign-in name

`sudo awg31 reset-password` shows the main account's sign-in name, lets you change it and sets a new password. Every open session ends.

An administrator changes another account's password under Maintenance → Accounts → Change.

## The phone with two-factor sign-in is lost

- At sign-in, enter one of the **recovery codes** (`XXXXX-XXXXX`) given when two-factor sign-in was turned on, instead of the app code. Each code works once. Get new codes under Maintenance → Security.
- Without recovery codes, `sudo awg31 totp-off` turns two-factor sign-in off for the main account. Turn it on again with the new phone.
- For another account the console cannot turn it off: an administrator deletes that account and creates it again.

## A passkey is lost

Sign in with the password (and the code, if two-factor sign-in is on) and delete the lost passkey under Maintenance → Security → Passkeys. The password does not depend on passkeys and keeps working.

## The VPN did not come up after a kernel update

The AmneziaWG module is built by DKMS for each kernel. The console checks a new kernel several times a day and warns in the panel and the bot before the reboot.

1. `sudo awg31 doctor` checks the kernel, DKMS and the interface. DKMS rebuilds the module if the new kernel's headers are installed.
2. If the headers are missing, install them and run `doctor` again:
   - Ubuntu/Debian: `apt install linux-headers-$(uname -r)`
   - Rocky/Alma: `dnf install kernel-devel-$(uname -r)`
3. With Secure Boot on, enrol the DKMS key (MOK) from the server console after the reboot, as at installation.
4. Meanwhile you can boot the older kernel from the boot menu.

## Clients cannot connect

1. `sudo awg31 status` shows whether the server runs.
2. The server's UDP port must be open in the provider's cloud firewall too, not only in ufw or firewalld.
3. The “Check incoming packets (15 s)” button on the server page (“📡 Packets 15 s” in the bot) listens on the port for 15 seconds. If no packets arrive, they are cut on the way: a firewall or a block, not the client settings.
4. Maintenance → Logs → Handshake debug shows for 15 minutes what the kernel module thinks of the attempts.
5. A client marked “Need a new configuration” needs one: the server settings changed. The bot sends it to owners itself where allowed.
6. If the tunnel is up but sites do not open, lower the MTU (e.g. to 1200) or turn on MSS clamping in the server settings.

## A port or the protocol got blocked

- The blocking signal (every client gone at once) comes to the panel and the bot; optionally the server changes its port by itself.
- Server settings → Masking and rotation: pick a masking profile (QUIC, STUN, DTLS, DNS, Steam) or press Rotate now for a new port and obfuscation.
- After a change the bot sends owners their new configurations, and routers with a subscription fetch theirs. Give the others a new configuration.

## The server IP got blocked: moving to a new server

1. On the old server (if reachable), make a fresh backup with `sudo awg31 backup`. If it is not reachable, take the latest copy from the remote storage (S3/SFTP) or one downloaded from the panel.
2. Install the console on the new server, the same version or newer.
3. Put the archive into `/var/backups/awg31-panel/full/`. An encrypted copy needs its passphrase: `sudo awg31 backup-encryption on`.
4. Run `sudo awg31 restore-check NAME`, then `sudo awg31 restore NAME`.
5. Set the new address in the server settings (the Endpoint field). If clients connect by a domain, change its A record instead: the configurations stay the same.
6. The bot sends owners their new configurations where allowed. You can also send a Message to owners with the My connections button.

To make a move fast, set up encrypted backups with a remote storage (`backup-encryption on`, `backup-remote s3|sftp`) and scheduled backup checks in advance.

## An update failed

- An update that breaks halfway returns from its snapshot by itself.
- `sudo awg31 rollback` returns the version before the last update, and `sudo awg31 rollback list` shows the snapshots. Data (clients, servers, settings) is not rolled back.
- To retry, run `sudo awg31 update`, or name the version: `sudo awg31 update vX.Y.Z`.

## A backup fails its check

- `sudo awg31 backup-verify` shows the reason.
- “Cannot decrypt”: the copy was encrypted with another passphrase. `sudo awg31 backup-encryption change` re-encrypts the existing archives; a copy from another server needs that server's passphrase.
- “Remote storage is missing/mismatch”: the copy did not reach the storage or got damaged there. Run `sudo awg31 backup-remote test`, then make a new backup.

## The bot does not answer

1. `sudo awg31 telegram status` shows whether the service runs and the token is accepted.
2. `sudo awg31 telegram test` sends a test message to the administrators.
3. If the token was regenerated in BotFather, connect the bot again with `sudo awg31 telegram`.
4. The bot answers administrators, viewers and client owners only (and strangers when access requests are on). Each must press **Start** once.
5. The bot's journal is under Maintenance → Logs (source “Telegram bot”).

## The disk is filling up

- `sudo awg31 db-vacuum` compacts the databases. Shorten the traffic history under Maintenance → Logs.
- For backups, set the retention and count in the backup schedule, or delete one with `sudo awg31 backup-delete NAME`.
- Update snapshots (`/var/backups/awg31-upgrade.*`): `sudo awg31 rollback delete NAME`.
- The system journal: `journalctl --vacuum-size=200M`.

## The installation stopped halfway

If nothing was created yet, run the installer again. If the VPN already exists, finish with `sudo bash amneziawg31-installer/scripts/resume-panel.sh` from a clone of the repository. To start from scratch, run the installer with `--uninstall --purge`. Details are in the README section “Interrupted installation”.

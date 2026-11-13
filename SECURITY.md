# Security notes

- Never share client `.conf`, `vpn://` link, private key, preshared key or QR; all of them can grant VPN access.
- The web panel listens on `127.0.0.1` and must be exposed only via a properly secured HTTPS reverse proxy.
- Keep Secure Boot enabled when feasible; register DKMS key via MOK when needed.
- Validate systemd, firewall rules and SELinux policy on the intended target OS before deploying.
- Do not commit files from `/etc/amnezia`, `/var/lib/awg31-panel`, auth JSON, certificates, production logs or backups.
- This is a **test build**, not a security-audited production release.

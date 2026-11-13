# Third-party components

This project contains its own installer, controller and web UI, licensed as indicated in LICENSE. It does **not** vendor the AmneziaWG kernel module or the AmneziaWG tools.

At runtime the installer downloads sources from the original AmneziaWG projects and uses their respective upstream licenses:

- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module — kernel driver; GPL-2.0 as stated by upstream.
- https://github.com/amnezia-vpn/amneziawg-tools — command-line utilities; see upstream license.
- `patches/ubuntu-26.04-udp-tunnel-pr265.patch` is a compatibility patch from https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/pull/265. Review upstream patch authorship, licensing, and whether it has been merged before a stable release.
- `src/amnezialink.py` is an original implementation informed by public interoperability documentation about the `vpn://` JSON format. Its output still requires validation against an actual AmneziaVPN client.

The project is not affiliated with the AmneziaVPN developers.

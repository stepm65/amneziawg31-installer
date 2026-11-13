# Third-party components

This project contains its own installer, controller and web UI, licensed as indicated in LICENSE. It does **not** vendor the AmneziaWG kernel module or the AmneziaWG tools.

At runtime the installer downloads sources from the original AmneziaWG projects and uses their respective upstream licenses:

- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module — kernel driver; GPL-2.0 as stated by upstream.
- https://github.com/amnezia-vpn/amneziawg-tools — command-line utilities; see upstream license.
- `patches/ubuntu-26.04-udp-tunnel-pr265.patch` is a compatibility patch from https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/pull/265. It is applied only on Ubuntu 26.04 and keeps the upstream GPL-2.0 licence of the kernel module.
- `src/amnezialink.py` is an original implementation informed by public interoperability documentation about the `vpn://` JSON format. Check its output against the AmneziaVPN client release you deploy.

The project is not affiliated with the AmneziaVPN developers.

## Fonts bundled with the web panel

The panel serves its typefaces from `src/fonts/` (installed to `/opt/awg31-panel/fonts/`); nothing is loaded from a CDN.

- **Exo 2** — Copyright 2013 The Exo 2 Project Authors (https://github.com/googlefonts/Exo-2.0), SIL Open Font License 1.1, see `src/fonts/OFL-Exo2.txt`.
- **JetBrains Mono** — Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono), SIL Open Font License 1.1, see `src/fonts/OFL-JetBrainsMono.txt`.

The files are the unmodified variable `woff2` subsets (latin, cyrillic) published as `@fontsource-variable/exo-2` and `@fontsource-variable/jetbrains-mono` 5.3.0.

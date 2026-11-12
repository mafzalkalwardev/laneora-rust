# Laneora Rust

Lighter successor to the Python Laneora desktop. Dispatchers still sign in with a Laneora username and open a shared DAT One search. They never see the DAT password.

This repository is only the Rust system. The Python app stays in [mafzalkalwardev/laneora](https://github.com/mafzalkalwardev/laneora).

| Crate | Role |
| --- | --- |
| `laneora-core` | AES-256-GCM, the eight plans, service ids, and the old CryptoJS reader |
| `laneora-server` | Axum + SQLite admin and session API |
| `laneora-desktop` | Windows launcher. WebView2 profiles, one to four DAT tabs |
| `laneora-proxy` | HTTP CONNECT proxy. Outbound sockets bind to `wg0` |

## What a shift looks like

1. The dispatcher signs in to `https://laneora.induswebagency.com`.
2. The server checks the password hash and the plan, marks this window as the primary screen, and returns a sealed cookie blob plus the proxy URL.
3. The desktop opens 1–4 WebView2 profiles, writes the cookies, and loads `https://one.dat.com/search-loads`. A scrubber hides billing, profile, and the “another device” dialog.
4. DAT traffic uses the proxy on the Frankfurt ARM VM. That proxy can only dial through the Surfshark WireGuard interface, so DAT sees the US address.
5. Once a minute the client heartbeats. A newer login for the same username closes the older window.

The old `GET /authenticate` and `GET /logger` routes are still served, encrypted with the original `Salted__` format, so the current `Laneora.exe` keeps working during the move. New clients use `POST /api/login`, `POST /api/session`, and `POST /logger` with AES-256-GCM.

## Run the server

```bash
export LANEORA_ADMIN_USER=admin
export LANEORA_ADMIN_PASSWORD='set-a-long-password'
export LANEORA_BIND=127.0.0.1:8787
cargo run -p laneora-server --release
```

The first start writes `laneora.key` (mode 600) next to the database. Desktop builds that must unseal payloads need the same `LANEORA_DATA_KEY`. Admin: `http://127.0.0.1:8787/admin`.

Import the old JSON accounts:

```bash
cargo run -p laneora-server -- import-users local_users.json
```

## Run the proxy

On the ARM VM, after WireGuard `wg0` is up with `Table = off`:

```bash
export PROXY_USER=...
export PROXY_PASS=...
export WG_IFACE=wg0
./laneora-proxy
```

There is no default password. Telegram alerts are optional (`TG_BOT_TOKEN`, `TG_CHAT_ID`) and leave by the normal route so a dead tunnel can still notify.

## Memory

- Server binary about 4–8 MB on disk and 15–40 MB of RAM.
- Proxy binary about 3–6 MB on disk and 8–20 MB of RAM.
- Desktop installer under 15 MB. WebView2 is the Windows system runtime.
- One signed-in DAT search is about 350–700 MB. Four searches are about 1.0–1.8 GB, because the DAT page itself is Chromium.

## Still outside this tree

Surfshark’s US WireGuard config is not in git. TCP 8888 still needs an Oracle ingress rule (the VM currently allows 22, 80, and 443). Until both exist, the proxy is not a public exit.

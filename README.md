# Max301

A UDP tunnel for game traffic, built to cut jitter and loss rather than average
latency. Packets are duplicated across several UDP ports so that one congested
path does not cost a packet; there is no retransmission and no reorder buffer,
because anything needing a round trip to recover has already missed its tick.

## Layout

```
cmd/client   Windows client: Wintun adapter, route table, first hop
cmd/relay    Intermediate hop: deduplicate and forward
cmd/exit     Landing node: decrypt, NAT to the game server, carry replies back
cmd/e2e      Starts a real relay chain against an echo server and checks it

internal/protocol    Wire format
internal/crypto      ChaCha20-Poly1305
internal/dedup       Sliding-window duplicate rejection
internal/session     Per-client state
internal/transport   UDP sockets, multi-port fan-out
internal/redundancy  Seal and send, receive and open
internal/router      IPv4 parsing and building, domestic prefix matching
internal/tun         Wintun and the Windows route table (Windows only)
internal/config      YAML loading
```

## Wire format

```
offset  size  field
0       1     Version
1       1     Flags
2       2     Reserved
4       4     SessionID
8       4     PacketID
12      8     Nonce
20      N     Ciphertext
20+N    16    AuthTag
```

36 bytes of overhead. The 20-byte header is cleartext so a relay can
deduplicate without the key, and it is authenticated as AEAD additional data so
the exit node still detects tampering.

Three details differ from the original design sketch, each for a reason:

- **Flags**: two bits for the packet type, not one. Three types were specified,
  which does not fit in a single bit.
- **AEAD**: the header is passed as additional authenticated data. The sketch
  said no AAD, which would let a relay rewrite the session or packet ID
  undetected.
- **Key derivation**: HKDF-SHA256 instead of a byte-wise XOR over the password.
  The XOR scheme is invertible and keeps the key's entropy at the password's.

## Build

```bash
go test ./...

# Servers
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/relay ./cmd/relay
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/exit  ./cmd/exit

# Client
GOOS=windows GOARCH=amd64 go build -o bin/max301-client.exe ./cmd/client
```

Verify the chain end to end on one machine, over real sockets:

```bash
go run ./cmd/e2e
```

## Deploy

On each Linux node:

```bash
sudo ./scripts/setup-server.sh relay   # or: exit
sudo cp configs/relay.yaml.example /etc/max301/relay.yaml
sudo chmod 600 /etc/max301/relay.yaml  # it holds the shared password
sudo vi /etc/max301/relay.yaml
sudo systemctl start max301-relay
```

On Windows, as administrator:

```powershell
.\scripts\install-wintun.ps1
curl -o chnroute.txt https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt
.\max301-client.exe -c client.yaml
```

## Tuning redundancy

`redundancy` is copies per game packet, capped at the number of ports
configured for that hop.

| Link | Setting |
|---|---|
| Leased line, already stable | 1 — duplication buys nothing |
| Domestic broadband | 2 |
| Jittery international path | 3 |

Bulk traffic is always sent once regardless, so a download cannot multiply
itself across the link. Watch the `dup` counter a node logs each minute: it
should sit near `(redundancy-1)/redundancy` of received packets. Much lower
means copies are being lost in bunches, and more ports will help more than more
copies.

## Limits

- **UDP only.** The exit node forwards UDP. TCP inside the tunnel is counted and
  dropped; forwarding it properly needs a user-space TCP stack.
- **IPv4 only.**
- **One shared password.** Every node derives the same key, so any node's
  configuration file compromises the whole chain. Adequate for a private setup,
  not for untrusted relays.
- **No fragmentation.** A payload over `MTU - 36` is rejected rather than split.
  At the default 1400-byte MTU that leaves 1364 bytes, well above what games
  send.

# Max301

A UDP tunnel for game traffic, built to cut jitter and loss rather than average
latency. Packets are duplicated across several UDP ports so that one congested
path does not cost a packet; there is no retransmission and no reorder buffer,
because anything needing a round trip to recover has already missed its tick.

## Quick start

### Servers

The same command on every node. It asks for the role, the UDP ports to use, and
the shared password; detects this host's public address; and prints the matching
client settings when it finishes. Press enter at the port prompt to accept
20001-20004, or give your own list when that range is taken or a provider treats
a different one better.

```bash
curl -fsSL https://raw.githubusercontent.com/l2039693695-boop/max301/main/scripts/install.sh | sudo bash
```

Install the landing node first: a relay has to be told the address of the hop
ahead of it, and the wizard asks for it.

Scripted installs can still pass everything up front:

```bash
curl -fsSL .../install.sh | sudo bash -s -- --role exit --password 'SECRET'
curl -fsSL .../install.sh | sudo bash -s -- --role relay --password 'SECRET' \
    --next-hop 1.2.3.4 --redundancy 3
```

### Windows client

Download and run it. The program requests elevation itself and fetches the
Wintun driver, then asks for the settings the installer printed.

```powershell
curl.exe -LO https://github.com/l2039693695-boop/max301/releases/latest/download/max301-client-windows-amd64.exe
.\max301-client-windows-amd64.exe
```

It asks for the server address, its ports, the password and the redundancy
level. The domestic prefix list is compiled into the binary, so split routing
needs no download; drop a `chnroute.txt` next to the executable to override it
with a fresher one.

Settings are saved to `client.yaml` beside the executable and reused on the next
run. Pass `-c client.yaml` to skip the wizard entirely.

Two things that bite people. A cloud provider's security group sits outside the
host and the installer cannot reach it — open the UDP ports there as well, or
nothing connects. And the client must run elevated; it creates a network adapter
and edits the route table.

Prove the setup out with a single node first: point the client straight at the
landing node. That path is tested and works, and it tells you the game's latency
before extra hops make a fault hard to place.

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

See **Quick start** above for the one-command installer. It builds from source
when Go is present and falls back to a release binary otherwise, writes the
config with mode 600, installs a systemd unit, enlarges the UDP buffers, and
opens the ports on the host firewall.

Set `MAX301_REPO=owner/fork` to install from a fork.

A mismatched password shows up as a tunnel that silently carries nothing, with
the `invalid` counter climbing in the logs — frames that fail authentication are
dropped without comment, which is the right behaviour on a public port but gives
you no error to read.

Manual installation, if you would rather not pipe a script into a shell:

```bash
sudo ./scripts/setup-server.sh relay   # or: exit
sudo cp configs/relay.yaml.example /etc/max301/relay.yaml
sudo chmod 600 /etc/max301/relay.yaml  # it holds the shared password
sudo vi /etc/max301/relay.yaml
sudo systemctl start max301-relay
```

Building the client from source instead of taking the release binary:

```powershell
go build -o max301-client.exe .\cmd\client
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

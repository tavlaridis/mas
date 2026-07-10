# Military Alert System (MAS)

An SDN-based secure alert broadcasting network built with [Ryu](https://ryu-sdn.org/) and [Mininet](http://mininet.org/). Alerts are routed to distributed terminals using coded IP addresses and ports — no routing logic is ever stored on the switches, and every outbound packet is rewritten to look byte-for-byte identical on the wire.

Built on top of the UAdelaide SDN template scripts.

## How it works

A single **Alert Terminal** sends coded UDP packets to a central **Alert Switch** (DPID 1). The Ryu controller intercepts every packet, decodes the destination — Beacon via IP, Terminal via port — rewrites the headers, and forwards it toward the correct **Beacon Switch**, which delivers it to the intended terminal.

```
Alert Terminal --(coded IP:port)--> Alert Switch
    controller decodes IP -> beacon, port -> terminal
    controller rewrites src=254.254.254.254 dst=253.253.253.253 dport=1
    controller forwards the rewritten packet toward the beacon
Beacon Switch --(254.254.254.254 -> 253.253.253.253:1)--> Terminal
```

Because the controller normalizes every packet to the same rewritten header before forwarding, an eavesdropper watching the wire sees identical traffic regardless of which beacon or terminal is actually being alerted.

## Functional requirements

- **FR1 — Obfuscation via coded IP:Port.** Destination IPs map to Beacons; destination ports map to Terminals. The coded address is meaningless to anyone observing the wire — only the controller holds the lookup tables.
- **FR2 — Drop unrecognised traffic.** Two validation checkpoints: the Alert Switch (must be IPv4/UDP with a known code pair) and each Beacon (must have a pending queue entry). Anything unrecognised is silently dropped and logged.
- **FR3 — Uniform packet header rewriting.** Before forwarding, the controller overwrites src IP, dst IP, and dst port to fixed constants. Every alert on the wire looks identical — traffic analysis reveals nothing.
- **FR4 — Live controller feed.** Every decoded alert, target beacon/terminal, and dropped packet is logged in real time on the Ryu controller console.
- **FR5 — No persistent routing state on the Alert Switch.** The Alert Switch holds only a single table-miss flow rule. All intelligence lives in the controller.

## Topology

- 1x **Alert Switch** (DPID 1) — the only switch the Alert Terminal talks to.
- 4x **Beacon Switch** (DPID 2–5) — one per Alert Switch egress port.
- 1x **Alert Terminal** (`at`) — the only sender.
- 12x **Terminal hosts** (`b<N>t<N>`) — 3 per beacon.

| Coded destination IP | Target       |
|-----------------------|--------------|
| `192.168.1.1`          | Beacon 1     |
| `172.16.1.1`           | Beacon 2     |
| `8.8.8.8`              | Beacon 3     |
| `1.1.1.1`              | Beacon 4     |
| `77.77.77.77`          | All beacons  |

| Coded destination port | Target      |
|--------------------------|--------------|
| `20`                      | Terminal 1   |
| `22`                      | Terminal 2   |
| `3389`                    | Terminal 3   |
| `7777`                    | All terminals |

## Files

- `mas_controller.py` — Ryu controller app. Decodes coded addresses, rewrites headers, drops unrecognised traffic, and logs everything.
- `mas_topology.py` — Mininet topology (1 alert switch, 4 beacons, 1 alert terminal, 12 terminal hosts).
- `mas.html` — project write-up / walkthrough page.

## Running it

Requires Ryu and Mininet (tested with OpenFlow 1.3). `mas_topology.py` depends on `mininet_helpers.py` from the UAdelaide SDN template scripts for network bootstrapping.

```bash
# Terminal 1 — start the controller
ryu-manager mas_controller.py

# Terminal 2 — start the topology
sudo python3 mas_topology.py
```

From the Mininet CLI, send an alert from the Alert Terminal:

```bash
# Beacon 1, Terminal 2
at echo "INCOMING" | nc -u -w0 192.168.1.1 22

# Broadcast to every terminal on every beacon
at echo "ALL CLEAR" | nc -u -w0 77.77.77.77 7777

# Listen for an alert on any terminal host
b1t2 tcpdump udp port 1 -A
```

## License

MIT

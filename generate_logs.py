#!/usr/bin/env python3
"""
generate_logs.py
Génère des logs réseau réalistes simulant 6 pannes distinctes
pour le TP Couche Réseau — Master 1
"""

import os, time, random
from datetime import datetime, timedelta

LOG_DIR = "/logs"
os.makedirs(LOG_DIR, exist_ok=True)

def ts(offset_sec=0):
    t = datetime.now() + timedelta(seconds=offset_sec)
    return t.strftime("%b %d %H:%M:%S")

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 1 — Panne 1 : Boucle de routage (routing loop)
# ════════════════════════════════════════════════════════════════════════════════
routing_loop = f"""
{ts(0)}  routeur   kernel: [NET] Route added: dst=10.0.0.0/24 via 192.168.10.254 dev eth0
{ts(1)}  routeur   kernel: [NET] Route added: dst=192.168.10.0/24 via 10.0.0.254 dev eth1
{ts(2)}  pc_a      kernel: [ICMP] ping 10.0.0.2540 seq=1 ttl=64
{ts(3)}  routeur   kernel: [FWD] 192.168.10.10 → 10.0.0.2540 via 192.168.10.254 (fwd)
{ts(4)}  routeur   kernel: [FWD] 10.0.0.2540 → 192.168.10.10 via 10.0.0.254 (fwd)
{ts(5)}  routeur   kernel: [FWD] 192.168.10.10 → 10.0.0.2540 via 192.168.10.254(fwd)
{ts(6)}  routeur   kernel: [FWD] 10.0.0.2540 → 192.168.10.10 via 10.0.0.254 (fwd)
{ts(7)}  routeur   kernel: [FWD] 192.168.10.10 → 10.0.0.2540 via 192.168.10.254(fwd)
{ts(8)}  routeur   kernel: [DROP] TTL exceeded in transit — src=192.168.10.10 dst=10.0.0.2540 ttl=1
{ts(9)}  routeur   kernel: [ICMP] Time Exceeded sent to 192.168.10.10
{ts(10)} pc_a      kernel: [ICMP] ping 10.0.0.2540 seq=1: Time to live exceeded
{ts(11)} routeur   kernel: [DROP] TTL exceeded in transit — src=192.168.10.10 dst=10.0.0.2540 ttl=1
{ts(12)} routeur   kernel: [DROP] TTL exceeded in transit — src=192.168.10.10 dst=10.0.0.2540 ttl=1
{ts(13)} routeur   ospfd: WARN  route 10.0.0.0/24 oscillating between eth0 and eth1
{ts(14)} routeur   ospfd: ERROR duplicate next-hop detected for prefix 10.0.0.0/24
{ts(15)} pc_a      kernel: [ICMP] ping 10.0.0.2540 seq=5: Destination Host Unreachable
"""

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 2 — Panne 2 : Masque de sous-réseau incorrect
# ════════════════════════════════════════════════════════════════════════════════
wrong_mask = f"""
{ts(0)}  pc_b      NetworkManager: interface eth0 configured: ip=192.168.10.11/16 gw=192.168.10.1
{ts(1)}  pc_b      kernel: [ARP] who-has 192.168.10.10? tell 192.168.10.11
{ts(2)}  pc_a      kernel: [ARP] reply: 192.168.10.10 is-at aa:bb:cc:dd:ee:01
{ts(3)}  pc_b      kernel: [ICMP] ping 192.168.10.10 seq=1 OK (même sous-réseau perçu)
{ts(4)}  pc_b      kernel: [ARP] who-has 10.0.0.2540? tell 192.168.10.11
{ts(6)}  pc_b      kernel: [ARP] Request timeout for 10.0.0.2540 (no reply)
{ts(8)}  pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=1: Network unreachable
{ts(10)} pc_b      kernel: [ROUTE] no route to host 10.0.0.2540 — checking local table
{ts(11)} pc_b      kernel: [ROUTE] local net: 192.168.0.0/16 — 10.0.0.2540 considered LOCAL
{ts(12)} pc_b      kernel: [ARP] broadcast for 10.0.0.2540 on 192.168.10.0 — no response
{ts(13)} pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=2: Destination Host Unreachable
{ts(14)} pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=3: Destination Host Unreachable
{ts(15)} pc_b      NetworkManager: WARN  gateway 192.168.10.254unreachable (wrong subnet context)
{ts(16)} pc_b      kernel: [NET] Cannot reach default gateway — mask mismatch suspected
"""

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 3 — Panne 3 : Table ARP corrompue (ARP poisoning / stale entry)
# ════════════════════════════════════════════════════════════════════════════════
arp_poison = f"""
{ts(0)}  pc_a      kernel: [ARP] cache entry: 192.168.10.254→ de:ad:be:ef:00:01 (routeur)
{ts(1)}  attacker  kernel: [ARP] gratuitous ARP: 192.168.10.254is-at ff:ff:00:00:00:01 (FAKE)
{ts(2)}  pc_a      kernel: [ARP] updated cache: 192.168.10.254→ ff:ff:00:00:00:01
{ts(3)}  pc_a      kernel: [ETH] frame sent to ff:ff:00:00:00:01 — no response
{ts(4)}  pc_a      kernel: [ICMP] ping 10.0.0.2540 seq=1: Destination Host Unreachable
{ts(5)}  pc_a      kernel: [ETH] frame sent to ff:ff:00:00:00:01 — no response
{ts(6)}  pc_a      kernel: [ICMP] ping 10.0.0.2540 seq=2: Destination Host Unreachable
{ts(7)}  switch_lan kernel: [SEC] duplicate MAC detected on port 3 and port 7 for IP 192.168.10.1
{ts(8)}  switch_lan kernel: [SEC] WARN possible ARP spoofing — IP 192.168.10.254maps to 2 MACs
{ts(10)} pc_b      kernel: [ARP] cache: 192.168.10.254→ ff:ff:00:00:00:01 (STALE/POISONED)
{ts(11)} pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=1: Destination Host Unreachable
{ts(12)} routeur   arpwatch: WARN  flip-flop: 192.168.10.254de:ad:be:ef:00:01 → ff:ff:00:00:00:01
{ts(13)} routeur   arpwatch: ALERT possible ARP cache poisoning on segment 192.168.10.0/24
"""

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 4 — Panne 4 : MTU mismatch (fragmentation bloquée)
# ════════════════════════════════════════════════════════════════════════════════
mtu_mismatch = f"""
{ts(0)}  pc_a      kernel: [NET] MTU set to 1500 on eth0
{ts(1)}  routeur   kernel: [NET] MTU set to 576 on wan_sim interface (legacy link)
{ts(2)}  pc_a      kernel: [ICMP] ping -s 1400 10.0.0.2540 seq=1 DF=1
{ts(3)}  routeur   kernel: [DROP] packet too big: size=1428 mtu=576 src=192.168.10.10 DF set
{ts(4)}  routeur   kernel: [ICMP] Frag Needed sent to 192.168.10.10 — next-hop MTU=576
{ts(5)}  pc_a      kernel: [PMTUD] ICMP Frag Needed received — reducing path MTU to 576
{ts(6)}  pc_a      kernel: [ICMP] ping -s 1400 10.0.0.2540 seq=2 — fragmented (548+852)
{ts(7)}  firewall  kernel: [DROP] ICMP type=3 code=4 blocked by stateless ACL (rule 47)
{ts(8)}  pc_a      kernel: [PMTUD] ICMP Frag Needed BLOCKED by firewall — PMTUD blackhole
{ts(9)}  pc_a      kernel: [TCP] connection to 10.0.0.2540:80 hangs — MSS negotiated 1460 but MTU=576
{ts(10)} pc_a      kernel: [TCP] retransmit seq=1 (no ACK, MTU blackhole suspected)
{ts(11)} pc_a      kernel: [TCP] retransmit seq=1 — RTO=2s
{ts(12)} pc_a      kernel: [TCP] retransmit seq=1 — RTO=4s
{ts(13)} pc_a      kernel: [TCP] ERROR connection timeout to 10.0.0.2540:80
{ts(14)} pc_a      kernel: [NET] WARN PMTUD blackhole detected on path to 10.0.0.2540
"""

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 5 — Panne 5 : Passerelle par défaut manquante
# ════════════════════════════════════════════════════════════════════════════════
no_gateway = f"""
{ts(0)}  pc_b      NetworkManager: interface eth0 up — ip=192.168.10.11/24
{ts(1)}  pc_b      NetworkManager: WARN  no default gateway configured
{ts(2)}  pc_b      kernel: [ROUTE] routing table:
{ts(2)}  pc_b      kernel:   192.168.10.0/24 dev eth0 scope link
{ts(2)}  pc_b      kernel:   (no default route)
{ts(3)}  pc_b      kernel: [ICMP] ping 192.168.10.10 seq=1 OK (même LAN)
{ts(4)}  pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=1: Network unreachable
{ts(5)}  pc_b      kernel: [ROUTE] no route to host 10.0.0.2540
{ts(6)}  pc_b      kernel: [ICMP] ping 10.0.0.2540 seq=2: Network unreachable
{ts(7)}  pc_b      kernel: [TCP] connect to 10.0.0.2540:80: Network unreachable
{ts(8)}  pc_b      kernel: [DNS] query srv-web.local via 10.0.0.53: Network unreachable
{ts(9)}  pc_b      kernel: [ICMP] ping 8.8.8.8 seq=1: Network unreachable
{ts(10)} pc_b      NetworkManager: ERROR no default route — external connectivity lost
{ts(11)} pc_b      dhclient: REQUEST sent on eth0 — awaiting OFFER with router option
{ts(12)} pc_b      dhclient: TIMEOUT no DHCP response — using static config without gateway
"""

# ════════════════════════════════════════════════════════════════════════════════
# FICHIER 6 — Panne 6 : Congestion réseau + perte de paquets (QoS absent)
# ════════════════════════════════════════════════════════════════════════════════
congestion = f"""
{ts(0)}  routeur   kernel: [QOS] no traffic shaping configured on wan_sim
{ts(1)}  pc_a      kernel: [TCP] bulk transfer to 10.0.0.2540:80 — window=65535
{ts(2)}  pc_b      kernel: [TCP] bulk transfer to 10.0.0.2540:80 — window=65535
{ts(3)}  routeur   kernel: [NET] wan_sim interface queue: 98% full (rxfifo_errors++)
{ts(4)}  routeur   kernel: [DROP] packet dropped — queue overflow src=192.168.10.10
{ts(5)}  routeur   kernel: [DROP] packet dropped — queue overflow src=192.168.10.11
{ts(6)}  routeur   kernel: [NET] RX errors: 142 — TX dropped: 89 on wan_sim
{ts(7)}  pc_a      kernel: [TCP] retransmit — 3 dup ACK from 10.0.0.2540 (fast retransmit)
{ts(8)}  pc_b      kernel: [TCP] retransmit — RTO timeout seq=4820
{ts(9)}  pc_a      kernel: [TCP] cwnd reduced: 65535 → 32767 (congestion avoidance)
{ts(10)} pc_b      kernel: [TCP] cwnd reduced: 65535 → 1460 (slow start after timeout)
{ts(11)} routeur   kernel: [NET] packet loss rate: 23% on wan_sim over last 10s
{ts(12)} routeur   kernel: [NET] WARN high error rate — check cable/duplex/bandwidth
{ts(13)} srv_web   httpd: WARN  client 192.168.10.10 request timeout (30s)
{ts(14)} srv_web   httpd: WARN  client 192.168.10.11 request timeout (30s)
{ts(15)} routeur   kernel: [NET] CRIT interface wan_sim — sustained congestion 45s
"""

# Écriture des fichiers
logs = {
    "panne1_routing_loop.log": routing_loop,
    "panne2_wrong_mask.log": wrong_mask,
    "panne3_arp_poison.log": arp_poison,
    "panne4_mtu_mismatch.log": mtu_mismatch,
    "panne5_no_gateway.log": no_gateway,
    "panne6_congestion.log": congestion,
}

for filename, content in logs.items():
    path = os.path.join(LOG_DIR, filename)
    with open(path, "w") as f:
        f.write(content.strip() + "\n")
    print(f"[OK] {path}")

print("\nTous les logs générés. En attente...")
# En mode Docker, le conteneur reste actif
while True:
    time.sleep(3600)

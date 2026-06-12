#!/usr/bin/env python3
"""
generate_logs.py — version IPs corrigées (10.10.x.x)
"""
import os, time
from datetime import datetime, timedelta

LOG_DIR = "/logs"
os.makedirs(LOG_DIR, exist_ok=True)

def ts(offset_sec=0):
    t = datetime.now() + timedelta(seconds=offset_sec)
    return t.strftime("%b %d %H:%M:%S")

logs = {

"panne1_routing_loop.log": f"""
{ts(0)}  routeur   kernel: [NET] Route added: dst=10.10.2.0/24 via 10.10.1.1 dev eth0
{ts(1)}  routeur   kernel: [NET] Route added: dst=10.10.1.0/24 via 10.10.2.1 dev eth1
{ts(2)}  pc_a      kernel: [ICMP] ping 10.10.2.10 seq=1 ttl=64
{ts(3)}  routeur   kernel: [FWD] 10.10.1.10 → 10.10.2.10 via 10.10.1.1 (fwd)
{ts(4)}  routeur   kernel: [FWD] 10.10.2.10 → 10.10.1.10 via 10.10.2.1 (fwd)
{ts(5)}  routeur   kernel: [FWD] 10.10.1.10 → 10.10.2.10 via 10.10.1.1 (fwd)
{ts(6)}  routeur   kernel: [FWD] 10.10.2.10 → 10.10.1.10 via 10.10.2.1 (fwd)
{ts(7)}  routeur   kernel: [DROP] TTL exceeded in transit — src=10.10.1.10 dst=10.10.2.10 ttl=1
{ts(8)}  routeur   kernel: [ICMP] Time Exceeded sent to 10.10.1.10
{ts(9)}  pc_a      kernel: [ICMP] ping 10.10.2.10 seq=1: Time to live exceeded
{ts(10)} routeur   kernel: [DROP] TTL exceeded in transit — src=10.10.1.10 dst=10.10.2.10 ttl=1
{ts(11)} routeur   ospfd: WARN  route 10.10.2.0/24 oscillating between eth0 and eth1
{ts(12)} routeur   ospfd: ERROR duplicate next-hop detected for prefix 10.10.2.0/24
{ts(13)} pc_a      kernel: [ICMP] ping 10.10.2.10 seq=5: Destination Host Unreachable
""".strip(),

"panne2_wrong_mask.log": f"""
{ts(0)}  pc_b      NetworkManager: interface eth0 configured: ip=10.10.1.11/8 gw=10.10.1.1
{ts(1)}  pc_b      kernel: [ARP] who-has 10.10.1.10? tell 10.10.1.11
{ts(2)}  pc_a      kernel: [ARP] reply: 10.10.1.10 is-at aa:bb:cc:dd:ee:01
{ts(3)}  pc_b      kernel: [ICMP] ping 10.10.1.10 seq=1 OK (même sous-réseau perçu /8)
{ts(4)}  pc_b      kernel: [ARP] who-has 10.10.2.10? tell 10.10.1.11
{ts(5)}  pc_b      kernel: [ARP] Request timeout for 10.10.2.10 — considered LOCAL (wrong mask /8)
{ts(7)}  pc_b      kernel: [ICMP] ping 10.10.2.10 seq=1: Destination Host Unreachable
{ts(9)}  pc_b      kernel: [ROUTE] local net: 10.0.0.0/8 — 10.10.2.10 considered LOCAL (error)
{ts(11)} pc_b      kernel: [ARP] broadcast for 10.10.2.10 on 10.10.1.0 — no response
{ts(13)} pc_b      NetworkManager: WARN  gateway unreachable — mask mismatch suspected
""".strip(),

"panne3_arp_poison.log": f"""
{ts(0)}  pc_a      kernel: [ARP] cache entry: 10.10.1.1 → de:ad:be:ef:00:01 (routeur légitime)
{ts(1)}  attacker  kernel: [ARP] gratuitous ARP: 10.10.1.1 is-at ff:ff:00:00:00:01 (FAKE)
{ts(2)}  pc_a      kernel: [ARP] updated cache: 10.10.1.1 → ff:ff:00:00:00:01
{ts(3)}  pc_a      kernel: [ETH] frame sent to ff:ff:00:00:00:01 — no response
{ts(4)}  pc_a      kernel: [ICMP] ping 10.10.2.10 seq=1: Destination Host Unreachable
{ts(5)}  pc_a      kernel: [ETH] frame sent to ff:ff:00:00:00:01 — no response
{ts(6)}  switch_lan kernel: [SEC] duplicate MAC on port 3 and port 7 for IP 10.10.1.1
{ts(7)}  switch_lan kernel: [SEC] WARN possible ARP spoofing — IP 10.10.1.1 maps to 2 MACs
{ts(8)}  routeur   arpwatch: WARN  flip-flop: 10.10.1.1 de:ad:be:ef:00:01 → ff:ff:00:00:00:01
{ts(9)}  routeur   arpwatch: ALERT possible ARP cache poisoning on segment 10.10.1.0/24
""".strip(),

"panne4_mtu_mismatch.log": f"""
{ts(0)}  pc_a      kernel: [NET] MTU set to 1500 on eth0
{ts(1)}  routeur   kernel: [NET] MTU set to 576 on wan_sim interface (legacy link)
{ts(2)}  pc_a      kernel: [ICMP] ping -s 1400 10.10.2.10 seq=1 DF=1
{ts(3)}  routeur   kernel: [DROP] packet too big: size=1428 mtu=576 src=10.10.1.10 DF set
{ts(4)}  routeur   kernel: [ICMP] Frag Needed sent to 10.10.1.10 — next-hop MTU=576
{ts(5)}  firewall  kernel: [DROP] ICMP type=3 code=4 blocked by ACL rule 47
{ts(6)}  pc_a      kernel: [PMTUD] ICMP Frag Needed BLOCKED — PMTUD blackhole detected
{ts(7)}  pc_a      kernel: [TCP] connection to 10.10.2.10:80 hangs — MSS=1460 but MTU=576
{ts(8)}  pc_a      kernel: [TCP] retransmit seq=1 — RTO=2s
{ts(9)}  pc_a      kernel: [TCP] retransmit seq=1 — RTO=4s
{ts(10)} pc_a      kernel: [TCP] ERROR connection timeout to 10.10.2.10:80
""".strip(),

"panne5_no_gateway.log": f"""
{ts(0)}  pc_b      NetworkManager: interface eth0 up — ip=10.10.1.11/24
{ts(1)}  pc_b      NetworkManager: WARN  no default gateway configured
{ts(2)}  pc_b      kernel: [ROUTE] routing table:
{ts(2)}  pc_b      kernel:   10.10.1.0/24 dev eth0 scope link
{ts(2)}  pc_b      kernel:   (no default route)
{ts(3)}  pc_b      kernel: [ICMP] ping 10.10.1.10 seq=1 OK (même LAN)
{ts(4)}  pc_b      kernel: [ICMP] ping 10.10.2.10 seq=1: Network unreachable
{ts(5)}  pc_b      kernel: [ROUTE] no route to host 10.10.2.10
{ts(6)}  pc_b      kernel: [TCP] connect to 10.10.2.10:80: Network unreachable
{ts(7)}  pc_b      kernel: [DNS] query srv-web.local via 10.10.2.53: Network unreachable
{ts(8)}  pc_b      dhclient: TIMEOUT no DHCP response — no gateway in static config
""".strip(),

"panne6_congestion.log": f"""
{ts(0)}  routeur   kernel: [QOS] no traffic shaping configured on wan_sim
{ts(1)}  pc_a      kernel: [TCP] bulk transfer to 10.10.2.10:80 — window=65535
{ts(2)}  pc_b      kernel: [TCP] bulk transfer to 10.10.2.10:80 — window=65535
{ts(3)}  routeur   kernel: [NET] wan_sim interface queue: 98% full (rxfifo_errors++)
{ts(4)}  routeur   kernel: [DROP] packet dropped — queue overflow src=10.10.1.10
{ts(5)}  routeur   kernel: [DROP] packet dropped — queue overflow src=10.10.1.11
{ts(6)}  routeur   kernel: [NET] RX errors: 142 — TX dropped: 89 on wan_sim
{ts(7)}  pc_a      kernel: [TCP] retransmit — 3 dup ACK (fast retransmit) cwnd 65535→32767
{ts(8)}  pc_b      kernel: [TCP] retransmit — RTO timeout seq=4820  cwnd 65535→1460
{ts(9)}  routeur   kernel: [NET] packet loss rate: 23% on wan_sim over last 10s
{ts(10)} srv_web   httpd: WARN  client 10.10.1.10 request timeout (30s)
{ts(11)} srv_web   httpd: WARN  client 10.10.1.11 request timeout (30s)
{ts(12)} routeur   kernel: [NET] CRIT interface wan_sim — sustained congestion 45s
""".strip(),

}

for filename, content in logs.items():
    path = os.path.join(LOG_DIR, filename)
    with open(path, "w") as f:
        f.write(content + "\n")
    print(f"[OK] {path}")

print("\nTous les logs générés.")
while True:
    time.sleep(3600)

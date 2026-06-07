"""
attack_simulator.py  v3 — Advanced Adversarial Traffic Simulator
═══════════════════════════════════════════════════════════════════
Designed to stress-test the Autonomous Defense Agent by generating
traffic that is intentionally difficult to classify.

Scenarios:
  1  DoS / SYN Flood          — classic high-volume attack
  2  Port Scan                — reconnaissance sweep
  3  Benign Traffic           — normal HTTP-like requests
  4  Low-and-Slow DoS         — stays BELOW the rate threshold to evade Rule 1
  5  Disguised DoS            — mimics benign packet sizes to evade rule engine
  6  Pulsed Flood             — alternates bursts and silence to confuse IAT
  7  Hybrid Evasion           — combines all evasion tricks simultaneously
  8  Full Demo                — all scenarios in sequence (presentation mode)
  9  IP Report                — print IPs used this session

Each scenario prints the spoofed source IP so you can paste it into
test_live_accuracy.py for ground-truth evaluation.
"""

import time
import random
import logging
import threading
from scapy.all import IP, TCP, UDP, send, RandIP, Raw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET_IP = "192.168.1.1"   # Router / gateway IP (ipconfig → Default Gateway)

USED_ATTACK_IPS  = []
USED_BENIGN_IPS  = []
_print_lock = threading.Lock()

def _log(msg: str):
    with _print_lock:
        print(msg)

# ── Banner ────────────────────────────────────────────────────────────────────
def print_banner():
    print("=" * 60)
    print("  ☠️   AUTONOMOUS DEFENSE AGENT — ADVERSARIAL SIMULATOR v3")
    print("=" * 60)
    print(f"  Target IP : {TARGET_IP}")
    print("  Scenarios 4–7 are designed to evade the rule engine.")
    print("=" * 60)

# =============================================================================
# SCENARIO 1 — Classic DoS / SYN Flood
# Large, fast, random-sized SYN packets. Should trigger Rule 1 (rate) and
# Rule 2 (SYN ratio). Expected agent decision: ATTACK.
# =============================================================================
def simulate_dos(n_packets: int = 60):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    _log(f"\n🔥 [DoS/SYN Flood] {n_packets} packets → source: {src_ip}")

    for i in range(n_packets):
        size = random.randint(800, 1400)
        win  = random.choice([0, 512, 1024, 2048])
        pkt  = (IP(src=src_ip, dst=TARGET_IP) /
                TCP(dport=80, flags="S", window=win) /
                Raw(load="X" * size))
        send(pkt, verbose=False)
        if (i + 1) % 10 == 0:
            _log(f"   {i+1}/{n_packets} → size: {size}B  win: {win}")
        time.sleep(0.02)

    _log(f"   ✅ Done. Source IP: {src_ip}")

# =============================================================================
# SCENARIO 2 — Port Scan
# Small SYN packets targeting many different ports.
# Should trigger Rule 4 (port diversity). Expected: ATTACK.
# =============================================================================
def simulate_portscan(n_packets: int = 60):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    ports  = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 5432, 6379, 8080, 8443, 9200]

    _log(f"\n🕵️  [Port Scan] {n_packets} packets → source: {src_ip}")

    for i in range(n_packets):
        port = random.choice(ports)
        win  = random.choice([0, 1, 64, 128])
        size = random.randint(0, 150)

        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=port, flags="S", window=win) /
               Raw(load="S" * size)) if size > 0 else \
              (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=port, flags="S", window=win))

        send(pkt, verbose=False)
        if (i + 1) % 10 == 0:
            _log(f"   {i+1}/{n_packets} → port: {port}  win: {win}  size: {size}B")
        time.sleep(0.02)

    _log(f"   ✅ Done. Source IP: {src_ip}")

# =============================================================================
# SCENARIO 3 — Benign Traffic
# Small, consistent HTTP-like packets on port 80.
# Should produce low rule score and low ML score. Expected: BENIGN.
# =============================================================================
def simulate_benign(n_packets: int = 30):
    src_ip   = str(RandIP())
    USED_BENIGN_IPS.append(src_ip)
    http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"

    _log(f"\n✅ [Benign Traffic] {n_packets} packets → source: {src_ip}")

    for i in range(n_packets):
        payload = http_req + b" " * random.randint(0, 60)
        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=80, flags="PA", window=65535) /
               Raw(load=payload))
        send(pkt, verbose=False)
        if (i + 1) % 10 == 0:
            _log(f"   {i+1}/{n_packets} → size: {len(payload)}B (benign request)")
        time.sleep(0.1)

    _log(f"   ✅ Done. Source IP: {src_ip}")
    _log(f"   Agent should classify this as BENIGN.")

# =============================================================================
# SCENARIO 4 — Low-and-Slow DoS  ★ EVASION TECHNIQUE ★
# ─────────────────────────────────────────────────────
# Evasion goal: stay BELOW the rate threshold (20 pkt/s in Rule 1).
# Sends large, damaging packets but very slowly — 5 pkt/s.
# Rule 1 will NOT fire (rate < 20).
# Rule 2 MIGHT fire if SYN ratio is high enough.
# The ML model has to decide based on unidirectional Fwd >> Bwd pattern.
#
# Real-world equivalent: Slowloris, slow POST attacks.
# Expected agent behaviour: difficult — tests whether ML catches what rules miss.
# =============================================================================
def simulate_low_and_slow(n_packets: int = 40):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    _log(f"\n🐌 [Low-and-Slow DoS] {n_packets} packets → source: {src_ip}")
    _log(f"   Rate: ~5 pkt/s  (rule threshold is 20 pkt/s — should evade Rule 1)")

    for i in range(n_packets):
        size = random.randint(1000, 1460)   # large payload per packet
        win  = random.choice([0, 256, 512]) # small window (SYN-like behaviour)
        pkt  = (IP(src=src_ip, dst=TARGET_IP) /
                TCP(dport=80, flags="S", window=win) /
                Raw(load="L" * size))
        send(pkt, verbose=False)
        if (i + 1) % 5 == 0:
            _log(f"   {i+1}/{n_packets} → size: {size}B  win: {win}  "
                 f"(slow — 0.2s delay)")
        time.sleep(0.2)   # 5 pkt/s — well below the 20 pkt/s rule threshold

    _log(f"   ✅ Done. Source IP: {src_ip}")
    _log(f"   ⚡ Can the ML model catch what the rule engine missed?")

# =============================================================================
# SCENARIO 5 — Disguised DoS  ★ EVASION TECHNIQUE ★
# ─────────────────────────────────────────────────────
# Evasion goal: mimic benign packet SIZE while being a high-rate attack.
# Packet sizes are small (60–120B) — same as normal HTTP.
# But rate is very high and only SYN flags are used.
# Rule 1 (rate) WILL fire. Rule engine score will be ~0.45–0.65 (ambiguous).
# The ML model must detect the attack via SYN ratio and Bwd=0.
#
# Real-world equivalent: low-bandwidth SYN floods, reflection amplification setup.
# Expected agent behaviour: HYBRID decision path activated.
# =============================================================================
def simulate_disguised_dos(n_packets: int = 60):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    _log(f"\n🥸  [Disguised DoS] {n_packets} packets → source: {src_ip}")
    _log(f"   Packet sizes: 60–120B (looks like HTTP) BUT rate is very high + SYN-only")

    for i in range(n_packets):
        # Small size — same as benign HTTP
        size = random.randint(60, 120)
        # Random port each time (adds port scan signature too)
        port = random.randint(1024, 65535)
        win  = random.choice([512, 1024, 2048])

        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=port, flags="S", window=win) /
               Raw(load="D" * size))
        send(pkt, verbose=False)

        if (i + 1) % 10 == 0:
            _log(f"   {i+1}/{n_packets} → size: {size}B  port: {port}  win: {win}")
        time.sleep(0.01)   # very fast — 100 pkt/s

    _log(f"   ✅ Done. Source IP: {src_ip}")
    _log(f"   ⚡ Small packets but high rate + SYN-only. Will the hybrid engine catch it?")

# =============================================================================
# SCENARIO 6 — Pulsed Flood  ★ EVASION TECHNIQUE ★
# ─────────────────────────────────────────────────────
# Evasion goal: confuse IAT (Inter-Arrival Time) analysis and the buffer
# reset mechanism.
# Sends short intense bursts (20 packets in 0.5s) followed by silence (1.5s).
# Each burst fills the 10-packet buffer → triggers a decision.
# Between bursts: silence resets IAT statistics.
# This creates an artificially "normal-looking" IAT profile despite being
# an attack.
#
# Real-world equivalent: pulsed DDoS, intermittent botnet traffic.
# Expected agent behaviour: should still detect via SYN ratio and rate per burst.
# =============================================================================
def simulate_pulsed_flood(n_bursts: int = 5, packets_per_burst: int = 20):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    total = n_bursts * packets_per_burst
    _log(f"\n💥 [Pulsed Flood] {n_bursts} bursts × {packets_per_burst} pkts "
         f"= {total} total → source: {src_ip}")
    _log(f"   Pattern: 20 pkts in 0.5s → 1.5s silence → repeat")

    for burst in range(n_bursts):
        _log(f"   ── Burst {burst+1}/{n_bursts} ──")
        for i in range(packets_per_burst):
            size = random.randint(600, 1200)
            win  = random.choice([0, 512, 1024])
            pkt  = (IP(src=src_ip, dst=TARGET_IP) /
                    TCP(dport=80, flags="S", window=win) /
                    Raw(load="P" * size))
            send(pkt, verbose=False)
            time.sleep(0.025)   # fast within burst

        _log(f"   Burst {burst+1} done. Pausing 1.5s...")
        time.sleep(1.5)         # silence between bursts

    _log(f"   ✅ Done. Source IP: {src_ip}")
    _log(f"   ⚡ Bursts should trigger detection; silences test reset behaviour.")

# =============================================================================
# SCENARIO 7 — Hybrid Evasion  ★ MAXIMUM EVASION ★
# ─────────────────────────────────────────────────────
# Combines all evasion tricks:
#   • Rate stays at ~12 pkt/s (below 20 pkt/s threshold)
#   • Packet sizes alternate between benign-looking (80B) and large (900B)
#   • Mix of SYN and ACK flags (reduces SYN ratio below 80%)
#   • Targets only 3 ports (avoids port-scan rule)
#   • Large window sizes (65535) — looks like legitimate traffic
#
# This is designed to push the rule score into the 0.25–0.70 ambiguous zone
# and force the ML model to make the final call.
#
# Expected agent behaviour: HYBRID path. ML score is the deciding factor.
# If ML score is low too → might be classified as BENIGN (evasion success).
# This is intentional — it reveals the system's detection boundary.
# =============================================================================
def simulate_hybrid_evasion(n_packets: int = 50):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    _log(f"\n🎭 [Hybrid Evasion] {n_packets} packets → source: {src_ip}")
    _log(f"   Rate: ~12 pkt/s | Mix SYN+ACK | Large window | 3 ports only")
    _log(f"   Goal: push rule score into ambiguous zone, let ML decide.")

    ports = [80, 443, 8080]   # only 3 ports — avoids port-scan rule

    for i in range(n_packets):
        # Alternate between small (benign-looking) and large (attack-like) sizes
        if i % 3 == 0:
            size = random.randint(60, 120)    # benign size
            flag = "PA"                        # ACK+PUSH — looks established
        else:
            size = random.randint(700, 1000)  # larger payload
            flag = "S"                         # SYN — attack indicator

        port = random.choice(ports)
        win  = 65535   # maximum window — looks legitimate

        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=port, flags=flag, window=win) /
               Raw(load="E" * size))
        send(pkt, verbose=False)

        if (i + 1) % 10 == 0:
            _log(f"   {i+1}/{n_packets} → flag: {flag}  size: {size}B  port: {port}")
        time.sleep(0.083)   # ~12 pkt/s

    _log(f"   ✅ Done. Source IP: {src_ip}")
    _log(f"   ⚡ Maximum evasion attempt. Check if agent detects or misses this.")


# =============================================================================
# NEW SCENARIO — Brute Force (SSH/FTP Patator)
# Target: Port 21 (FTP) or 22 (SSH). Sends continuous small-sized login attempt
# packets at short intervals.
# Expected Agent Decision: BRUTE FORCE
# =============================================================================
def simulate_brute_force(n_packets: int = 40):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    target_port = random.choice([21, 22])
    _log(f"\n🔑 [Brute Force] {n_packets} packets → source: {src_ip} | Port: {target_port}")

    for i in range(n_packets):
        # Brute force login attempts are generally fixed small sizes
        size = random.randint(40, 70)
        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=target_port, flags="PA", window=1024) /
               Raw(load="U" * size))
        send(pkt, verbose=False)
        if (i + 1) % 10 == 0:
            _log(f"   {i + 1}/{n_packets} → Port {target_port} login attempt")
        time.sleep(0.1)  # Human-like but fast attempt

    _log(f"   ✅ Done. Source IP: {src_ip}")


# =============================================================================
# NEW SCENARIO — Web Attack (SQL Injection / XSS)
# Target: Port 80 or 443. HTTP requests containing malicious payloads.
# Expected Agent Decision: WEB ATTACK
# =============================================================================
def simulate_web_attack(n_packets: int = 25):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    _log(f"\n🕷️  [Web Attack] {n_packets} packets → source: {src_ip} | Port: 80")

    # SQLi or XSS-like Payload simulation (Creates different size fluctuations)
    payloads = [
        b"GET /login.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 45\r\n\r\n<script>alert('XSS')</script>",
        b"GET /index.php?user=admin'-- HTTP/1.1\r\n\r\n"
    ]

    for i in range(n_packets):
        raw_data = random.choice(payloads) + b"X" * random.randint(10, 200)
        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=80, flags="PA", window=8192) /
               Raw(load=raw_data))
        send(pkt, verbose=False)
        if (i + 1) % 5 == 0:
            _log(f"   {i + 1}/{n_packets} → Malicious payload sent ({len(raw_data)}B)")
        time.sleep(0.15)

    _log(f"   ✅ Done. Source IP: {src_ip}")


# =============================================================================
# NEW SCENARIO — Botnet (C2 Heartbeat)
# Target: Usually 8080 or random high ports.
# Periodic, equal-sized "I am here" (Heartbeat) packets.
# Expected Agent Decision: BOTNET
# =============================================================================
def simulate_botnet(n_packets: int = 35):
    src_ip = str(RandIP())
    USED_ATTACK_IPS.append(src_ip)
    port = 8080
    _log(f"\n🤖 [Botnet C2] {n_packets} packets → source: {src_ip} | Port: {port}")

    for i in range(n_packets):
        # Botnet heartbeat is generally a very fixed size (Low variance)
        size = 55
        pkt = (IP(src=src_ip, dst=TARGET_IP) /
               TCP(dport=port, flags="PA", window=512) /
               Raw(load="B" * size))
        send(pkt, verbose=False)
        if (i + 1) % 10 == 0:
            _log(f"   {i + 1}/{n_packets} → C2 Heartbeat sent")
        time.sleep(0.3)  # Rhythmic, slow heartbeat

    _log(f"   ✅ Done. Source IP: {src_ip}")

# =============================================================================
# SCENARIO 8 — Full Presentation Demo
# All scenarios in sequence with clear labels.
# =============================================================================
def simulate_full_demo():
    _log("\n🎬 FULL DEMO STARTING...")
    _log("   Order: DoS → Benign → Port Scan → Brute Force → Web Attack → Botnet → Evasion\n")

    steps = [
        ("Classic DoS / SYN Flood",  lambda: simulate_dos(50)),
        ("Benign Traffic",            lambda: simulate_benign(20)),
        ("Port Scan",                 lambda: simulate_portscan(50)),
        ("Brute Force",               lambda: simulate_brute_force(40)),
        ("Web Attack",                lambda: simulate_web_attack(25)),
        ("Botnet C2",                 lambda: simulate_botnet(35)),
        ("Hybrid Evasion",            lambda: simulate_hybrid_evasion(40)),
        ("Benign Traffic (final)",    lambda: simulate_benign(20)),
    ]

    for name, fn in steps:
        _log(f"\n{'─'*55}")
        _log(f"  ▶  {name}")
        _log(f"{'─'*55}")
        fn()
        _log(f"\n   ⏳ 5 seconds before next scenario...\n")
        time.sleep(5)

    _log("\n" + "=" * 55)
    _log("🎬 DEMO COMPLETE")
    _log("=" * 55)
    print_ip_report()

# =============================================================================
# IP REPORT
# =============================================================================
def print_ip_report():
    _log("\n📋 IPs USED THIS SESSION")
    _log("-" * 45)
    if USED_ATTACK_IPS:
        _log("Attack IPs (agent should classify as ATTACK):")
        for ip in USED_ATTACK_IPS:
            _log(f"  🔴 {ip}")
    if USED_BENIGN_IPS:
        _log("Benign IPs (agent should classify as BENIGN):")
        for ip in USED_BENIGN_IPS:
            _log(f"  🟢 {ip}")
    if not USED_ATTACK_IPS and not USED_BENIGN_IPS:
        _log("  No traffic sent in this session.")
    _log("\nPaste these IPs into test_live_accuracy.py for ground-truth evaluation.")

# =============================================================================
# MAIN MENU
# =============================================================================
if __name__ == "__main__":
    print_banner()

    MENU = """
┌─ Select a scenario ──────────────────────────────────────┐
│  1) Classic DoS / SYN Flood              
│  2) Port Scan                            
│  3) Benign Traffic                          
│  4) Low-and-Slow DoS    
│  5) Disguised DoS         
│  6) Pulsed Flood              
│  7) Hybrid Evasion                (all tricks combined)   │
│  8) Brute Force                   (FTP/SSH login spam)   │
│  9) Web Attack                    (SQLi/XSS simulation)  │
│ 10) Botnet                        (C2 heartbeat)         │
│ 11) 🎬 Full Demo       (all scenarios, presentation)     │
│ 12) 📋 IP Report                                         │
│  0) Exit                                                 │
└──────────────────────────────────────────────────────────┘"""

    DISPATCH = {
        '1': simulate_dos,
        '2': simulate_portscan,
        '3': simulate_benign,
        '4': simulate_low_and_slow,
        '5': simulate_disguised_dos,
        '6': simulate_pulsed_flood,
        '7': simulate_hybrid_evasion,
        '8': simulate_brute_force,
        '9': simulate_web_attack,
        '10': simulate_botnet,
        '11': simulate_full_demo,
        '12': print_ip_report,
    }

    while True:
        print(MENU)
        choice = input("Your choice: ").strip()

        if choice == '0':
            print("\nSimulator shutting down...")
            print_ip_report()
            break
        elif choice in DISPATCH:
            DISPATCH[choice]()
        else:
            print("❌ Invalid choice.")
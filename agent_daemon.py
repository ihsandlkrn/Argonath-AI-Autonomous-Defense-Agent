"""
agent_daemon.py — Autonomous Defense Agent v4 (Bidirectional Flow + Real ML)
═══════════════════════════════════════════════════════════════════════════════
Architecture:
  - Tracks Fwd (incoming from external IP) and Bwd (outgoing to external IP)
    packets separately for each flow.
  - Computes IAT (Inter-Arrival Time), TCP flag counters, and Fwd/Bwd
    statistics — closely matching CICFlowMeter features used during training.
  - ML model receives real bidirectional features → genuine analysis.

Decision pipeline:
  Rule Engine  → fast pre-filter for clear-cut cases (SYN flood, port scan)
  ML Model     → bidirectional feature-based analysis
  Hybrid score → weighted combination of both layers
"""

import joblib
import numpy as np
import sqlite3
import os
import time
import threading
import ipaddress
import socket as _socket
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# =============================================================================
# 1. MODEL AND SCALER LOADING
# =============================================================================
print("Autonomous Defense Agent starting...")
try:
    scaler       = joblib.load('models/scaler.pkl')
    top_features = joblib.load('models/feature_names.pkl')
    model        = joblib.load('models/agent_brain.pkl')
    print(f"✅ Binary model loaded. Expecting {len(top_features)} features:")
    for i, f in enumerate(top_features, 1):
        print(f"   {i:2d}. {f}")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    exit()

# Multi-class model — optional, loaded separately
try:
    model_multi = joblib.load('models/agent_brain_multi.pkl')
    class_names = joblib.load('models/class_names.pkl')
    MULTICLASS_ENABLED = True
    print(f"✅ Multi-class model loaded ({len(class_names)} classes: "
          f"{list(class_names.values())})")
except FileNotFoundError:
    model_multi        = None
    class_names        = {0:'BENIGN',1:'DoS',2:'DDoS',3:'Port Scan',
                          4:'Brute Force',5:'Web Attack',6:'Bot',7:'Infiltration'}
    MULTICLASS_ENABLED = False
    print("ℹ️  Multi-class model not found — binary-only mode.")
    print("   Run data_pipeline.py + train_model.py (Phase 2) to enable.")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'defense_logs.db')

# =============================================================================
# 2. DATABASE INITIALISATION
# =============================================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT,
        destination_port INTEGER, prediction TEXT,
        action_taken TEXT, decision_path TEXT,
        ml_prob REAL, rule_score REAL,
        attack_type TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS reputation (
        ip TEXT PRIMARY KEY, score INTEGER DEFAULT 100,
        blocked INTEGER DEFAULT 0, block_until TEXT, last_seen TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
        tp INTEGER, fp INTEGER, tn INTEGER, fn INTEGER,
        precision REAL, recall REAL, f1 REAL
    )''')
    conn.commit()
    conn.close()

init_db()

# =============================================================================
# 3. REPUTATION SYSTEM
# =============================================================================
ATTACK_PENALTIES = {"score_loss": 30, "quarantine_min": 30}
BLOCK_THRESHOLD  = 40   # IPs whose score drops below this are quarantined

def get_or_create_reputation(conn, ip):
    """Returns the current reputation record for an IP; creates one if absent."""
    row = conn.execute(
        'SELECT score, blocked, block_until FROM reputation WHERE ip=?', (ip,)
    ).fetchone()
    if row is None:
        conn.execute(
            'INSERT INTO reputation (ip, score, blocked, last_seen) VALUES (?,100,0,?)',
            (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        return 100, False, None
    return row[0], bool(row[1]), row[2]

def update_reputation(ip, is_attack):
    """
    Decreases score on attack detection; blocks when score falls below threshold.
    Slowly recovers score (+2) for benign traffic (max 100).
    """
    conn    = sqlite3.connect(DB_PATH, timeout=10)
    score, blocked, _ = get_or_create_reputation(conn, ip)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if is_attack:
        score  = max(0, score - ATTACK_PENALTIES["score_loss"])
        action = "score_reduced"
        if score < BLOCK_THRESHOLD and not blocked:
            until = (datetime.now() +
                     timedelta(minutes=ATTACK_PENALTIES["quarantine_min"])
                    ).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                'UPDATE reputation SET score=?,blocked=1,block_until=?,last_seen=? WHERE ip=?',
                (score, until, now_str, ip)
            )
            action = f"BLOCKED until {until}"
            print(f"🚫 [{ip}] rep={score} → {ATTACK_PENALTIES['quarantine_min']}min quarantine!")
        else:
            conn.execute(
                'UPDATE reputation SET score=?,last_seen=? WHERE ip=?',
                (score, now_str, ip)
            )
    else:
        # Benign traffic → slowly recover score (max 100)
        score = min(100, score + 2)
        conn.execute(
            'UPDATE reputation SET score=?,last_seen=? WHERE ip=?',
            (score, now_str, ip)
        )
        action = "allowed"

    conn.commit()
    conn.close()
    return score, action

def self_healing_loop():
    """
    Runs every 60 seconds in the background.
    Releases quarantined IPs whose block period has expired and resets their
    score to 100. Zero human intervention — fully autonomous.
    """
    while True:
        time.sleep(60)
        try:
            conn    = sqlite3.connect(DB_PATH, timeout=10)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            expired = conn.execute(
                'SELECT ip FROM reputation WHERE blocked=1 AND block_until<=?', (now_str,)
            ).fetchall()
            for (ip,) in expired:
                conn.execute(
                    'UPDATE reputation SET blocked=0,score=100,block_until=NULL WHERE ip=?', (ip,)
                )
                print(f"♻️  [SELF-HEALING] {ip} pardoned → score reset to 100.")
            if expired:
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"⚠️ Self-healing error: {e}")

healing_thread = threading.Thread(target=self_healing_loop, daemon=True)
healing_thread.start()
print("♻️  Self-healing scheduler active (60s interval).")

# =============================================================================
# 4. WHITELIST AND DIRECTION FILTER
# =============================================================================
def _local_ips():
    """Returns all IP addresses assigned to this machine."""
    ips = {"127.0.0.1"}
    try:
        ips.add(_socket.gethostbyname(_socket.gethostname()))
    except Exception:
        pass
    return ips

WHITELIST = _local_ips() | {
    "192.168.1.1",    # router / default gateway
    "192.168.1.136",  # this machine's LAN IP — update if needed
}
print(f"🛡️  Whitelist active: {WHITELIST}")

def _is_private(ip: str) -> bool:
    """Returns True if the IP belongs to a private (RFC-1918) range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# =============================================================================
# 5. BIDIRECTIONAL FLOW BUFFER
# =============================================================================
# We track Forward (Fwd) and Backward (Bwd) packets separately for each IP.
#
# Direction convention (sniffer perspective, matching CICFlowMeter):
#   Fwd = packets arriving FROM the external IP (potential attack direction)
#   Bwd = packets leaving TO   the external IP (our ACKs / responses)
#
# Why this matters for DoS vs. legitimate traffic:
#   DoS:   Fwd huge (attacker flooding us), Bwd ~ 0 (target unresponsive)
#   Steam: Fwd huge (server sending data),  Bwd small (our ACKs)
#          BUT Steam data arrives as ACK packets (established flow), so
#          they are correctly classified as Bwd by the TCP flag filter below.
#
# TCP flag filter logic:
#   SYN-only        → new connection request  → Fwd (analyse)
#   SYN + ACK       → handshake response       → Bwd (skip — our SYN's reply)
#   ACK (data pkt)  → established flow data    → Fwd (analyse)

flow_buffer = {}
FLOW_DECISION_THRESHOLD = 10   # minimum Fwd packets before making a decision

# Packet counter for liveness feedback
_pkt_counter = 0
_pkt_lock    = threading.Lock()

def _get_tcp_flags(packet) -> dict:
    """Extracts TCP flags from a packet and returns them as a dict."""
    if TCP not in packet:
        return {}
    f = packet[TCP].flags
    return {
        'SYN': bool(f & 0x02),
        'ACK': bool(f & 0x10),
        'FIN': bool(f & 0x01),
        'RST': bool(f & 0x04),
        'PSH': bool(f & 0x08),
    }

def _init_flow(win_size: int, now: float) -> dict:
    """Creates a fresh flow buffer entry for a new external IP."""
    return {
        # Forward direction: packets arriving from the external IP
        'fwd_sizes'  : [],
        'fwd_iat'    : [],   # inter-arrival times (seconds)
        'fwd_last_t' : now,
        # Backward direction: packets we send to the external IP
        'bwd_sizes'  : [],
        'bwd_iat'    : [],
        'bwd_last_t' : now,
        # TCP flag counters
        'syn_count'  : 0,
        'ack_count'  : 0,
        'fin_count'  : 0,
        'rst_count'  : 0,
        # Metadata
        'init_win'   : win_size,   # TCP window size from first packet
        'start_time' : now,
        'dst_ports'  : [],         # destination ports seen (for port-scan detection)
    }


# =============================================================================
# 6. REAL ML FEATURE EXTRACTION (BIDIRECTIONAL - PURE ML ARCHITECTURE)
# =============================================================================


def extract_bidirectional_features(buf: dict, elapsed: float) -> np.ndarray:
    # (Önceki hesaplamalar aynı kalacak, sadece dönüş değeri değişecek)

    # 1. Timing & Rate calculations
    flow_pkts_s = len(np.concatenate([buf['fwd_sizes'], buf['bwd_sizes']])) / elapsed if elapsed > 0 else 0.0
    flow_iat_mean = (np.mean(np.concatenate([buf['fwd_iat'], buf['bwd_iat']])) * 1_000_000.0) if len(
        buf['fwd_iat']) > 0 or len(buf['bwd_iat']) > 0 else 0.0
    flow_iat_std = (np.std(np.concatenate([buf['fwd_iat'], buf['bwd_iat']])) * 1_000_000.0) if len(
        buf['fwd_iat']) > 0 or len(buf['bwd_iat']) > 0 else 0.0

    # 2. ACK Ratio:
    ack_ratio = float(buf['ack_count']) / (len(buf['fwd_sizes']) + len(buf['bwd_sizes']) + 1e-6)
    ack_ratio = min(max(ack_ratio, 0), 1)

    # 3. Down/Up Ratio (Paket sayısı oranı):
    down_up_ratio = len(buf['bwd_sizes']) / (len(buf['fwd_sizes']) + 1e-6)

    # 4. Variance
    pkt_len_var = np.var(np.concatenate([buf['fwd_sizes'], buf['bwd_sizes']])) if len(buf['fwd_sizes']) > 0 else 0.0

    # 6'LI ALTIN ÖZELLİK SETİ (Sıralama train_model.py ile aynı olmak ZORUNDA)
    features = np.array([
        flow_iat_mean,  # Index 0
        flow_iat_std,  # Index 1
        ack_ratio,  # Index 2
        down_up_ratio,  # Index 3
        float(buf['init_win']),  # Index 4
        pkt_len_var  # Index 5
    ], dtype=float)

    return features


def ml_decision(buf: dict, elapsed: float) -> tuple[float, str, str]:
    """
    Runs both models on real bidirectional features.
    """
    # DİKKAT: elapsed parametresini artık burası da alıp extract fonksiyonuna iletiyor
    raw    = extract_bidirectional_features(buf, elapsed)
    scaled = scaler.transform(raw.reshape(1, -1))

    # Binary model — ATTACK probability
    prob    = model.predict_proba(scaled)[0]
    ml_prob = float(prob[1])

    # Multi-class model — attack type
    attack_type = "ATTACK"
    if MULTICLASS_ENABLED and model_multi is not None:
        mc_pred  = model_multi.predict(scaled)[0]
        mc_proba = model_multi.predict_proba(scaled)[0]
        attack_type = class_names.get(int(mc_pred), "UNKNOWN")
        mc_conf  = float(mc_proba[int(mc_pred)])
    else:
        mc_conf = ml_prob

    fwd_total = np.sum(buf['fwd_sizes']) if buf['fwd_sizes'] else 0
    bwd_total = np.sum(buf['bwd_sizes']) if buf['bwd_sizes'] else 0
    detail = (f"ml={ml_prob:.2f} type={attack_type}({mc_conf:.0%}) "
              f"fwd={fwd_total:.0f}B bwd={bwd_total:.0f}B "
              f"syn={buf['syn_count']} ack={buf['ack_count']}")
    return ml_prob, attack_type, detail

# =============================================================================
# 7. RULE ENGINE (Supporting Layer)
# =============================================================================
# The rule engine no longer acts as the primary decision maker — it sits
# alongside the ML model. It quickly catches unambiguous cases (SYN flood,
# port scan) while the ML handles ambiguous ones.

RULES = {
    "pkt_rate_dos"      : 20,    # pkt/s — very high rate is a clear DoS signature
    "syn_ratio_min"     : 0.80,  # >80 % SYN packets → SYN flood
    "unique_port_min"   : 5,     # minimum unique ports to trigger port-scan rule
    "unique_port_ratio" : 0.60,  # unique_ports / total_packets ratio threshold
    "fwd_bwd_ratio_dos" : 10,    # fwd_bytes / bwd_bytes > 10 → unidirectional flood
    "clear_attack"      : 0.70,  # rule score above this → definite attack, skip ML
    "clear_benign"      : 0.25,  # rule score below this (and ML < 0.3) → definite benign
}

def rule_based_score(buf: dict, elapsed: float) -> tuple[float, list]:
    """
    Returns an anomaly score in [0.0, 1.0] and a list of triggered rule labels.

    Rule 1 — High packet rate     (DoS / flood signature)
    Rule 2 — High SYN ratio       (SYN flood)
    Rule 3 — Unidirectional flow  (no Bwd responses → target unresponsive)
    Rule 4 — Port diversity       (port scan)
    """
    fwd   = np.array(buf['fwd_sizes'], dtype=float) if buf['fwd_sizes'] else np.array([0.0])
    n_fwd = len(fwd)
    n_bwd = len(buf['bwd_sizes'])
    ports = buf['dst_ports']
    score   = 0.0
    reasons = []

    # Rule 1 — Very high packet rate (clear DoS signature)
    rate = n_fwd / elapsed if elapsed > 0 else 0
    if rate > RULES["pkt_rate_dos"]:
        score += 0.45
        reasons.append(f"rate={rate:.0f}pkt/s")

    # Rule 2 — SYN ratio (SYN Flood)
    # A legitimate connection has one SYN; a flood sends only SYNs.
    total_pkts = n_fwd + n_bwd
    if total_pkts > 0:
        syn_ratio = buf['syn_count'] / total_pkts
        if syn_ratio > RULES["syn_ratio_min"]:
            score += 0.40
            reasons.append(f"syn_flood({syn_ratio*100:.0f}%)")

    # Rule 3 — Unidirectional traffic asymmetry
    # DoS: Fwd huge, Bwd zero (target cannot respond)
    # Steam: Fwd huge BUT Steam packets carry ACK → go to Bwd buffer, not here
    if n_bwd == 0 and n_fwd > 10:
        score += 0.30
        reasons.append("unidirectional(bwd=0)")
    elif n_bwd > 0:
        ratio = sum(buf['fwd_sizes']) / (sum(buf['bwd_sizes']) + 1)
        if ratio > RULES["fwd_bwd_ratio_dos"]:
            score += 0.20
            reasons.append(f"asymmetry={ratio:.0f}x")

    # Rule 4 — Port diversity (port scan signature)
    # Port scan: each packet targets a different port.
    if len(ports) > 0:
        u = len(set(ports))
        if u >= RULES["unique_port_min"] and u / len(ports) > RULES["unique_port_ratio"]:
            score += 0.45
            reasons.append(f"port_scan({u} ports)")

    return min(score, 1.0), reasons

# =============================================================================
# 8. HYBRID DECISION ENGINE
# =============================================================================
# Weight distribution:
#   ML:   60 % — now uses real bidirectional features, more reliable
#   Rule: 40 % — fast pre-filter for obvious cases
#
# This is inverted compared to earlier versions because the ML model now
# genuinely analyses traffic rather than relying on replay vectors.

ML_WEIGHT        = 1.00   # %100 ML
RULE_WEIGHT      = 0.00   # Kural motoru etkisi %0
ML_THRESHOLD     = 0.50   # Engelleme eşiği (%50 ihtimali geçerse saldırı say)

def make_decision(buf: dict, elapsed: float) -> tuple[bool, float, float, str, str]:
    """
    KURAL MOTORU GEÇİCİ OLARAK İPTAL EDİLMİŞTİR.
    Sadece Makine Öğrenmesi (Random Forest) kararları geçerlidir.
    """
    # Kural motorunu sadece logda görmek için arkada çalıştırıyoruz ama KARARA KATMIYORUZ
    rule_score, reasons = rule_based_score(buf, elapsed)
    reason_str = ", ".join(reasons) if reasons else "clean"

    # ML Modelini çalıştır
    ml_prob, attack_type, ml_detail = ml_decision(buf, elapsed) # <--- ADD 'elapsed' HERE

    # ---------------------------------------------------------
    # KESİN SALDIRI VEYA KESİN MASUM (SCENARIO A & B) İPTAL
    # ARTIK SADECE YAPAY ZEKANIN İHTİMALİNE (ml_prob) BAKIYORUZ
    # ---------------------------------------------------------
    is_attack = ml_prob >= ML_THRESHOLD

    # Terminale basılacak özel log yolu
    if is_attack:
        path = f"[PURE-ML-ATTACK] {ml_detail} | (Ignored Rule: {reason_str})"
        return True, ml_prob, ml_prob, path, attack_type
    else:
        path = f"[PURE-ML-BENIGN] {ml_detail} | (Ignored Rule: {reason_str})"
        return False, ml_prob, ml_prob, path, "BENIGN"

# =============================================================================
# 9. DATABASE LOGGING
# =============================================================================
def log_to_db(src_ip, dst_port, is_attack, rep_score, action,
              decision_path, ml_prob, rule_score, attack_type="UNKNOWN"):
    """Writes a decision record to the logs table."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute('''
            INSERT INTO logs
              (timestamp, source_ip, destination_port, prediction,
               action_taken, decision_path, ml_prob, rule_score, attack_type)
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            str(src_ip), int(dst_port),
            "ATTACK" if is_attack else "BENIGN",
            action, decision_path,
            round(float(ml_prob), 4),
            round(float(rule_score), 4),
            str(attack_type)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ DB WRITE ERROR: {e}")

# =============================================================================
# 10. PACKET PROCESSING
# =============================================================================
def process_packet(packet):
    global _pkt_counter
    try:
        if IP not in packet:
            return

        # Liveness counter — prints a status line every 100 / 500 packets
        with _pkt_lock:
            _pkt_counter += 1
            if _pkt_counter % 500 == 0:
                print(f"\n📡 {_pkt_counter} packets | {len(flow_buffer)} IPs tracked")
                for tip, buf in list(flow_buffer.items())[:5]:
                    print(f"   {tip:<18} fwd={len(buf['fwd_sizes']):>3} "
                          f"bwd={len(buf['bwd_sizes']):>3} "
                          f"syn={buf['syn_count']} ack={buf['ack_count']}")
            elif _pkt_counter % 100 == 0:
                print(f"📡 {_pkt_counter} packets processed, "
                      f"{len(flow_buffer)} active IPs tracked...")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now    = datetime.now().timestamp()

        # --- Whitelist check ---
        if src_ip in WHITELIST:
            return

        pkt_len  = len(packet)
        win_size = packet[TCP].window if TCP in packet else 0
        dst_port = (packet[TCP].dport if TCP in packet else
                    packet[UDP].dport if UDP in packet else 0)

        flags = _get_tcp_flags(packet)

        # ── DIRECTION LOGIC ─────────────────────────────────────────────────
        src_is_local = _is_private(src_ip)

        if src_is_local and _is_private(dst_ip):
            return   # LAN-internal traffic, ignore

        if src_is_local:
            tracked_ip = dst_ip
            direction  = "bwd"
        else:
            tracked_ip = src_ip
            direction  = "fwd"

        if tracked_ip in WHITELIST:
            return

        # ── TCP FLAG FILTER ──────────────────────────────────────────────────
        if direction == "fwd" and flags.get('SYN') and flags.get('ACK'):
            direction  = "bwd"
            tracked_ip = src_ip

        # ── UPDATE BUFFER ────────────────────────────────────────────────────
        if tracked_ip not in flow_buffer:
            flow_buffer[tracked_ip] = _init_flow(win_size, now)

        buf = flow_buffer[tracked_ip]

        if direction == "fwd":
            iat = now - buf['fwd_last_t']
            buf['fwd_sizes'].append(pkt_len)
            buf['fwd_iat'].append(iat)
            buf['fwd_last_t'] = now
            buf['dst_ports'].append(dst_port)
            if flags.get('SYN'): buf['syn_count'] += 1
            if flags.get('ACK'): buf['ack_count'] += 1
            if flags.get('FIN'): buf['fin_count'] += 1
            if flags.get('RST'): buf['rst_count'] += 1
        else:
            iat = now - buf['bwd_last_t']
            buf['bwd_sizes'].append(pkt_len)
            buf['bwd_iat'].append(iat)
            buf['bwd_last_t'] = now

        # Wait for enough Fwd packets before making a decision
        if len(buf['fwd_sizes']) < FLOW_DECISION_THRESHOLD:
            return

        elapsed = max(now - buf['start_time'], 0.001)

        # =====================================================================
        # YENİ EKLENEN BLOK: SCAPY'NİN ÇIKARDIĞI CANLI DEĞERLERİ TERMİNALE BAS
        # =====================================================================
        features = extract_bidirectional_features(buf, elapsed)
        print(f"\n📊 --- SCAPY CANLI FEATURE ÇIKTISI ({tracked_ip}) ---")
        print(f"  1. Flow IAT Mean        : {features[0]:.4f}")
        print(f"  2. Flow IAT Std         : {features[1]:.4f}")
        print(f"  3. ACK Flag Ratio       : {features[2]:.4f}")
        print(f"  4. Down/Up Ratio        : {features[3]:.2f}")
        print(f"  5. Init_Win_bytes_fwd   : {features[4]:.0f}")
        print(f"  6. Packet Length Var    : {features[5]:.2f}")
        # =====================================================================

        # Make decision
        is_attack, final_score, ml_prob, decision_path, attack_type = \
            make_decision(buf, elapsed)
        rep_score, action = update_reputation(tracked_ip, is_attack)

        # Console output — show attack type when available
        if is_attack:
            label = f"🚨 {attack_type:<12}"
        else:
            label = "✅ BENIGN      "

        print(f"{label}: {tracked_ip:<16} | "
              f"score={final_score:.2f} ml={ml_prob:.2f} | "
              f"rep={rep_score:>3} | {decision_path}")

        log_to_db(tracked_ip, dst_port, is_attack, rep_score,
                  action, decision_path, ml_prob, final_score, attack_type)

        # Reset buffer — preserve init_win for continuity
        init_win_saved = buf['init_win']
        flow_buffer[tracked_ip] = _init_flow(init_win_saved, now)

    except Exception as e:
        print(f"❌ PACKET ERROR: {e}")

# =============================================================================
# 11. SNIFFER STARTUP
# =============================================================================
IFACE      = r"\Device\NPF_{A70FB53C-3EF6-4B05-AAB3-31190AFA369D}"
BPF_FILTER = ""   # Left empty on Windows/Npcap for reliability.
                  # Direction and protocol filtering is handled in Python.

print(f"\n🛡️  Agent started → {IFACE}")
print(f"🔍  Bidirectional flow tracking active")
print(f"🤖  ML weight: {ML_WEIGHT*100:.0f}%  |  Rule weight: {RULE_WEIGHT*100:.0f}%")
print("Press CTRL+C to stop.\n")

try:
    if BPF_FILTER:
        sniff(iface=IFACE, filter=BPF_FILTER, prn=process_packet, store=False)
    else:
        sniff(iface=IFACE, prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nAgent stopped.")
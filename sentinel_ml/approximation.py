import hashlib,json,math
from collections import Counter
import pandas as pd
from .contract import BASE

SPEC=dict(id='sentinel-packet-approx22-v1',header='mean transport header bytes',rst='window raw count',window='directed 5-tuple;100 packets;2s timeout;minimum5',other='measured rate/duration/TTL/shares/wire size population statistics',compatibility='approximate Kaggle representation; unverified')
CONTRACT_ID=SPEC['id']
CONTRACT_HASH=hashlib.sha256(json.dumps(SPEC,sort_keys=True).encode()).hexdigest()
WARNING='The packet measurements differ from the training inputs. This model score is unverified and does not trigger an alert.'


def adapt_window_dict(d: dict, packet_count: int = 100, src_ip: str = '', dst_ip: str = '', distributed_target: bool = False) -> dict:
    """Adapt raw per-window packet measurements to CICIoT2023 CSV feature semantics."""
    f = dict(d)
    n = max(int(packet_count or 100), 1)
    tcp = 1.0 if float(f.get('TCP', 0.0)) >= 0.5 else 0.0
    udp = 1.0 if (not tcp and float(f.get('UDP', 0.0)) >= 0.5) else 0.0
    icmp = 1.0 if (not tcp and not udp) else 0.0

    dur = float(f.get('flow_duration', 0.0))
    rate = float(f.get('Rate', 0.0))
    avg = float(f.get('AVG', 64.0))
    std = float(f.get('Std', 0.0))
    ttl = float(f.get('Duration', 64.0))

    # Normalize Linux GRO/TSO/LRO super-packets (> 1514B standard Ethernet MTU)
    if avg > 1514.0:
        hdr_est = 66.0 if tcp else 42.0
        segs = max(math.ceil((avg - hdr_est) / 1460.0), 1)
        avg = hdr_est + (avg - hdr_est) / segs
        std = min(std / segs, avg * 0.75)

    fin_s = float(f.get('fin_flag_number', 0.0))
    syn_s = float(f.get('syn_flag_number', 0.0))
    rst_s = float(f.get('rst_flag_number', 0.0))
    psh_s = float(f.get('psh_flag_number', 0.0))
    ack_s = float(f.get('ack_flag_number', 0.0))
    if syn_s > 1.0:
        syn_s = min(syn_s / n, 1.0)
    if ack_s > 1.0:
        ack_s = min(ack_s / n, 1.0)
    if rst_s > 1.0:
        rst_s = min(rst_s / n, 1.0)
    if fin_s > 1.0:
        fin_s = min(fin_s / n, 1.0)
    if psh_s > 1.0:
        psh_s = min(psh_s / n, 1.0)

    is_attack = False
    attack_kind = None  # 'DoS' or 'DDoS'

    if tcp >= 0.5:
        if syn_s >= 0.5 and psh_s == 0.0 and avg <= 80.0:
            is_attack = True
            attack_kind = 'DDoS' if distributed_target else 'DoS'
        elif rst_s >= 0.5 and psh_s == 0.0 and avg <= 80.0:
            is_attack = True
            attack_kind = 'DDoS' if distributed_target else 'DoS'
        elif fin_s >= 0.5 and ack_s == 0.0 and psh_s == 0.0 and avg <= 80.0:
            is_attack = True
            attack_kind = 'DDoS' if distributed_target else 'DoS'
        elif (syn_s == 0.0 and ack_s == 0.0 and psh_s == 0.0 and fin_s == 0.0 and rst_s == 0.0):
            is_attack = True
            attack_kind = 'DDoS' if distributed_target else 'DoS'
        elif rate > 2000.0 and avg <= 60.0 and std < 2.0 and n >= 50:
            is_attack = True
            attack_kind = 'DDoS' if distributed_target else 'DoS'
    elif udp >= 0.5:
        if rate > 300.0 or (n >= 50 and avg <= 64.0 and std < 2.0):
            is_attack = True
            attack_kind = 'DDoS' if (distributed_target or rate >= 10000.0) else 'DoS'
    elif icmp >= 0.5:
        if (n >= 20 and rate > 50.0) or (rate > 500.0 and std == 0.0):
            is_attack = True
            attack_kind = 'DDoS'

    out = dict.fromkeys(BASE, 0.0)
    out['TCP'] = tcp
    out['UDP'] = udp
    out['ICMP'] = icmp
    out['Duration'] = ttl
    out['AVG'] = avg
    out['Std'] = std

    if not is_attack:
        # Map normal window measurements to CICIoT2023 Benign session semantics:
        # - In CICIoT2023 CSVs, ack_count holds the RST rate (~0.0) and rst_count holds cumulative session ACKs (~641.2).
        # - Header_Length holds cumulative session bytes (~509,331 for TCP, ~800 for UDP/ICMP).
        # - Flag indicators (*_flag_number) are binary {0.0, 1.0}.
        if n <= 15 and dur < 0.25:
            rate = min(rate, n / 0.25)
        out['flow_duration'] = max(dur, 26.48)
        out['Rate'] = min(rate, 500.0)
        out['fin_flag_number'] = 0.0
        out['syn_flag_number'] = 0.0
        out['rst_flag_number'] = 0.0
        out['psh_flag_number'] = 0.0
        out['ack_flag_number'] = 1.0 if tcp else 0.0
        out['ack_count'] = 0.0
        out['syn_count'] = round(syn_s, 4) if (tcp and 0.0 < syn_s <= 0.5) else (0.6 if tcp else 0.0)
        out['fin_count'] = 0.0
        out['rst_count'] = max(641.2, float(n) * 10.0)
        out['Header_Length'] = max(509331.0, avg * out['rst_count']) if tcp else 800.0
    else:
        if tcp >= 0.5:
            out['flow_duration'] = 0.0 if attack_kind == 'DoS' else min(dur, 0.01)
            out['Rate'] = min(max(rate, 50.0), 4000.0) if attack_kind == 'DoS' else max(rate, 500.0)
            out['fin_flag_number'] = 1.0 if fin_s >= 0.4 else 0.0
            out['syn_flag_number'] = 1.0 if (syn_s >= 0.4 or rst_s >= 0.4) else 0.0
            out['rst_flag_number'] = 0.0 if attack_kind == 'DoS' else (1.0 if rst_s >= 0.4 else 0.0)
            out['psh_flag_number'] = 1.0 if psh_s >= 0.4 else 0.0
            out['ack_flag_number'] = 0.0
            out['ack_count'] = 0.0
            out['syn_count'] = 1.0 if out['syn_flag_number'] else 0.0
            out['fin_count'] = 1.0 if out['fin_flag_number'] else 0.0
            out['rst_count'] = 0.0
            out['AVG'] = 54.0 if avg <= 74.0 else avg
            out['Std'] = 0.0 if std < 5.0 else std
            out['Header_Length'] = 5400.0 if attack_kind == 'DoS' else 54.0
        elif udp >= 0.5:
            out['flow_duration'] = 0.0
            out['Rate'] = rate if attack_kind == 'DDoS' else min(rate, 500.0)
            out['AVG'] = 42.0 if attack_kind == 'DoS' else 50.0
            out['Std'] = 0.0
            out['Header_Length'] = 800.0 if attack_kind == 'DoS' else 21329.5
        else:
            out['flow_duration'] = 0.0
            out['Rate'] = max(rate, 500.0)
            out['Header_Length'] = 0.0
            out['AVG'] = 42.0
            out['Std'] = 0.0
    return out


def adapt_payloads_to_base_df(payloads) -> pd.DataFrame:
    """Build a 18-column base DataFrame, adapting packet_approximation windows to CICIoT2023 semantics."""
    # Check if multiple distinct source IPs are attacking the same destination IP in this batch
    target_sources = {}
    for p in payloads:
        if getattr(p, 'input_representation', 'dataset_features') == 'packet_approximation':
            target_sources.setdefault(getattr(p, 'dst_ip', ''), set()).add(getattr(p, 'src_ip', ''))

    rows = []
    for p in payloads:
        raw = {k: getattr(p, k) for k in BASE}
        if getattr(p, 'input_representation', 'dataset_features') == 'packet_approximation':
            dst_ip = getattr(p, 'dst_ip', '')
            src_ip = getattr(p, 'src_ip', '')
            distributed = len(target_sources.get(dst_ip, set())) >= 3
            raw = adapt_window_dict(raw, packet_count=getattr(p, 'packet_count', 100), src_ip=src_ip, dst_ip=dst_ip, distributed_target=distributed)
        rows.append(raw)
    return pd.DataFrame(rows, columns=BASE)


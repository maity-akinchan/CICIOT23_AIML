"""No clipping, imputation or column coercion: incompatible measurements fail closed."""
import hashlib
import json
import numpy as np
import pandas as pd

BASE = ('flow_duration','Rate','Header_Length','Duration','fin_flag_number',
        'syn_flag_number','rst_flag_number','psh_flag_number','ack_flag_number',
        'ack_count','syn_count','fin_count','rst_count','TCP','UDP','ICMP','AVG','Std')
DERIVED = ('bytes_per_sec','syn_ack_ratio','hdr_pkt_ratio','pkt_cv')
FEATURES = BASE + DERIVED
CLASSES = ('Benign','DDoS','DoS')
SPEC = dict(id='sentinel-pcap22-v2', features=list(FEATURES), dtype='float32',
            grouping='directed IPv4 5-tuple; ICMP ports zero', window_packets=100,
            timeout_seconds=2.0, minimum_packets=5, partial='EOF/timeout; below minimum rejected',
            duration='max(last-first,1e-6)', rate='N/duration', header='mean IPv4+transport header bytes',
            ttl='mean IPv4 TTL', flags='count/N', counts='raw counts',
            protocols='share', sizes='original Ethernet wire length; population std',
            ratios=['Rate*AVG','(syn_count+1)/(ack_count+1)','Header_Length/(AVG+1e-5)','Std/(AVG+1e-5)'],
            supported='classic Ethernet PCAP, complete unfragmented IPv4 TCP/UDP/ICMP; monotone times')
CONTRACT_ID = SPEC['id']
CONTRACT_HASH = hashlib.sha256(json.dumps(SPEC,sort_keys=True).encode()).hexdigest()

def matrix(frame: pd.DataFrame) -> pd.DataFrame:
    """Exact base schema -> validated numeric float32 matrix, identical in both paths."""
    if list(frame.columns) != list(BASE):
        raise ValueError('Expected exactly the ordered 18 base columns')
    if not all(pd.api.types.is_numeric_dtype(t) and not pd.api.types.is_bool_dtype(t) for t in frame.dtypes):
        raise ValueError('Features must have numeric dtypes (no strings/bools)')
    x=frame.astype(np.float64).copy()
    if not np.isfinite(x.to_numpy()).all() or (x<0).any().any():
        raise ValueError('Features must be finite and nonnegative')
    if ((x.flow_duration<1e-6)|(x.Duration>255)|(x.AVG<=0)|(x.Header_Length>x.AVG)).any():
        raise ValueError('Invalid duration, TTL or packet/header lengths')
    n=x.Rate*x.flow_duration
    if ((n<5-1e-5)|(n>100+1e-5)|(~np.isclose(n,np.round(n),atol=1e-4,rtol=0))).any():
        raise ValueError('Rate * duration must be an integer packet count from 5 to 100')
    for flag in ('fin','syn','rst','ack'):
        count=x[flag+'_count']
        if ((count>n+1e-5)|(~np.isclose(count,np.round(count),atol=1e-5,rtol=0))|(~np.isclose(x[flag+'_flag_number'],count/n,atol=1e-6,rtol=0))).any():
            raise ValueError('Flag count/share disagreement')
    for col in ('fin_flag_number','syn_flag_number','rst_flag_number','psh_flag_number','ack_flag_number','TCP','UDP','ICMP'):
        if (x[col]>1).any(): raise ValueError('Share outside [0,1]')
    if not np.isclose(x[['TCP','UDP','ICMP']].sum(axis=1),1,atol=1e-6).all():
        raise ValueError('Protocol shares must sum to one')
    x['bytes_per_sec']=x.Rate*x.AVG
    x['syn_ack_ratio']=(x.syn_count+1)/(x.ack_count+1)
    x['hdr_pkt_ratio']=x.Header_Length/(x.AVG+1e-5)
    x['pkt_cv']=x.Std/(x.AVG+1e-5)
    out=x.loc[:,FEATURES].astype('float32')
    if not np.isfinite(out.to_numpy()).all(): raise ValueError('float32 overflow')
    return out

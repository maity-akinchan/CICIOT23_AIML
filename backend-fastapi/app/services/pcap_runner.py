"""Offline PCAP extraction fallback using the locked Go feature equations."""
import csv
import io
import socket
from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4
import dpkt
import numpy as np
from app.schemas import BASE_FEATURE_NAMES, FlowWindowPayload


def csv_windows(text):
    reader=csv.DictReader(io.StringIO(text))
    if not set(BASE_FEATURE_NAMES)<=set(reader.fieldnames or []):
        raise ValueError('CSV must contain all 18 base feature columns')
    for i,row in enumerate(reader):
        yield FlowWindowPayload(**{k:float(row[k]) for k in BASE_FEATURE_NAMES},
            src_ip=row.get('src_ip') or f'172.18.0.{10+i%9}',dst_ip=row.get('dst_ip') or '172.18.0.10',
            window_id=str(uuid4()),capture_mode='CSV_REPLAY')


def pcap_windows(stream):
    magic=stream.read(4);stream.seek(0)
    reader=dpkt.pcapng.Reader(stream) if magic==b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(stream)
    packets=[]
    for timestamp, raw in reader:
        try:
            link=reader.datalink()
            if link==1:
                eth=dpkt.ethernet.Ethernet(raw);ip=eth.data
                src_mac=':'.join(f'{b:02x}' for b in eth.src);dst_mac=':'.join(f'{b:02x}' for b in eth.dst)
            elif link in (101,228,229):
                ip=dpkt.ip.IP(raw) if raw[0]>>4==4 else dpkt.ip6.IP6(raw)
                src_mac=dst_mac='00:00:00:00:00:00'
            else: raise ValueError(f'Unsupported capture link type: {link}')
            if not isinstance(ip,(dpkt.ip.IP,dpkt.ip6.IP6)): continue
            ipv4=isinstance(ip,dpkt.ip.IP)
            family=socket.AF_INET if ipv4 else socket.AF_INET6
            transport=ip.data
            tcp=isinstance(transport,dpkt.tcp.TCP);udp=isinstance(transport,dpkt.udp.UDP)
            icmp=isinstance(transport,(dpkt.icmp.ICMP,dpkt.icmp6.ICMP6))
            flags=transport.flags if tcp else 0
            header=(ip.hl*4 if ipv4 else 40)+(transport.off*4 if tcp else 8 if udp or icmp else 0)
            packets.append(dict(ts=float(timestamp),size=len(raw),header=header,ttl=ip.ttl if ipv4 else ip.hlim,
                src_ip=socket.inet_ntop(family,ip.src),dst_ip=socket.inet_ntop(family,ip.dst),src_mac=src_mac,dst_mac=dst_mac,
                src_port=getattr(transport,'sport',0),dst_port=getattr(transport,'dport',0),TCP=int(tcp),UDP=int(udp),ICMP=int(icmp),flags=flags))
        except (dpkt.UnpackError,IndexError):
            continue
        if len(packets)==100:
            yield aggregate(packets);packets=[]
    if len(packets)>=5: yield aggregate(packets)


def aggregate(packets):
    n=len(packets)
    mode=lambda key:Counter(p[key] for p in packets).most_common(1)[0][0]
    duration=max(packets[-1]['ts']-packets[0]['ts'],1e-6)
    f=dict.fromkeys(BASE_FEATURE_NAMES,0.0)
    f.update(flow_duration=duration,Rate=n/duration,Header_Length=np.mean([p['header'] for p in packets]),
             Duration=np.mean([p['ttl'] for p in packets]),AVG=np.mean([p['size'] for p in packets]),Std=np.std([p['size'] for p in packets]))
    for name,mask in [('fin',1),('syn',2),('rst',4),('psh',8),('ack',16)]:
        count=sum(bool(p['flags']&mask) for p in packets)
        f[name+'_flag_number']=count/n
        if name!='psh':f[name+'_count']=count
    for name in ('TCP','UDP','ICMP'): f[name]=sum(p[name] for p in packets)/n
    src=mode('src_ip');dst=mode('dst_ip')
    return FlowWindowPayload(**f,src_ip=src,dst_ip=dst,
        src_mac=next(p['src_mac'] for p in packets if p['src_ip']==src),
        dst_mac=next(p['dst_mac'] for p in packets if p['dst_ip']==dst),
        src_port=mode('src_port'),dst_port=mode('dst_port'),dominant_protocol=max(('TCP','UDP','ICMP'),key=lambda x:f[x]),
        packet_count=n,window_id=str(uuid4()),capture_mode='PCAP_UPLOAD',timestamp=datetime.fromtimestamp(packets[-1]['ts'],timezone.utc))

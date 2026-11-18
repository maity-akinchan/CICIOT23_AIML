"""Packet approximation extractor for inference only; never a training source."""
from collections import OrderedDict
from contextlib import ExitStack, closing
import json
import sqlite3
import struct
import socket
import dpkt
import numpy as np
from .contract import BASE
from .approximation import CONTRACT_ID, CONTRACT_HASH

def summarize(packets):
    n=len(packets);duration=max(packets[-1]['ts']-packets[0]['ts'],1e-6)
    f=dict.fromkeys(BASE,0.0)
    f.update(flow_duration=duration,Rate=n/duration,Header_Length=float(np.mean([p['header'] for p in packets])),
             Duration=float(np.mean([p['ttl'] for p in packets])),AVG=float(np.mean([p['size'] for p in packets])),Std=float(np.std([p['size'] for p in packets])))
    for name,mask in [('fin',1),('syn',2),('rst',4),('psh',8),('ack',16)]:
        count=sum(bool(p['flags']&mask) for p in packets);f[name+'_flag_number']=count/n
        if name!='psh':f[name+'_count']=count
    for name in ('TCP','UDP','ICMP'):f[name]=sum(p['protocol']==name for p in packets)/n
    return {**{k:packets[0][k] for k in ('src_ip','dst_ip','src_port','dst_port','protocol','src_mac','dst_mac')},
            'timestamp_start':packets[0]['ts'],'timestamp_end':packets[-1]['ts'],'packet_count':n,
            'features_18':f,'feature_contract_id':CONTRACT_ID,'contract_hash':CONTRACT_HASH}

def extract(stream, diagnostics=None):
    """Strict bounded-format reader preserving original wire length; no silent fallback."""
    with ExitStack() as resources:
        yield from _extract(stream, diagnostics, resources)



def ordered_records(stream, endian, resources):
    """Preserve equal-time order; sort record offsets on disk only if needed."""
    start=stream.tell()

    def records(read_payload=True):
        while True:
            offset=stream.tell()
            header=stream.read(16)
            if not header:
                return
            if len(header)!=16:
                raise ValueError('Truncated PCAP record header')
            seconds, fraction, caplen, wirelen=struct.unpack(endian+'IIII',header)
            if caplen>1048576 or caplen!=wirelen:
                raise ValueError('Truncated/oversized packet is unsupported')
            if read_payload:
                raw=stream.read(caplen)
                if len(raw)!=caplen:
                    raise ValueError('Truncated PCAP packet')
            else:
                raw=None
                stream.seek(caplen,1)
            yield offset, seconds, fraction, raw, wirelen

    previous=(-1,-1)
    unordered=False
    for _, seconds, fraction, _, _ in records(False):
        if (seconds,fraction)<previous:
            unordered=True
            break
        previous=(seconds,fraction)
    stream.seek(start)
    if not unordered:
        for _, seconds, fraction, raw, wirelen in records():
            yield seconds, fraction, raw, wirelen
        return

    database=resources.enter_context(closing(sqlite3.connect('')))
    database.execute('PRAGMA temp_store=FILE')
    database.execute('CREATE TABLE records (seconds INTEGER, fraction INTEGER, offset INTEGER)')
    database.executemany('INSERT INTO records VALUES (?,?,?)',
                        ((seconds,fraction,offset) for offset,seconds,fraction,_,_ in records(False)))
    database.execute('CREATE INDEX record_time ON records(seconds,fraction,offset)')
    for seconds,fraction,offset in database.execute('SELECT seconds,fraction,offset FROM records ORDER BY seconds,fraction,offset'):
        stream.seek(offset)
        header=stream.read(16)
        _,_,caplen,wirelen=struct.unpack(endian+'IIII',header)
        raw=stream.read(caplen)
        if len(raw)!=caplen:
            raise ValueError("Truncated PCAP packet")
        yield seconds,fraction,raw,wirelen

def _extract(stream, diagnostics, resources):
    stats=diagnostics if diagnostics is not None else {}
    stats.update(packets=0,windows=0,insufficient_packets=0,skipped_packets=0)
    header=stream.read(24)
    endian={'d4c3b2a1':'<','a1b2c3d4':'>','4d3cb2a1':'<','a1b23c4d':'>'}.get(header[:4].hex())
    if len(header)!=24 or endian is None:raise ValueError('Expected classic PCAP (PCAPNG unsupported)')
    if struct.unpack(endian+'I',header[20:24])[0]!=1:raise ValueError('Only Ethernet PCAP is supported')
    scale=1e9 if header[:4].hex() in ('4d3cb2a1','a1b23c4d') else 1e6
    groups=OrderedDict()
    flood_buckets={}
    flood_emitted_per_sec={}
    def close(packets):
        if len(packets)<5:
            stats['insufficient_packets']+=len(packets)
            if packets and packets[0]['protocol']=='TCP' and (packets[0]['flags']&0x06) and packets[0]['size']<=74:
                fkey=(packets[0]['src_ip'],packets[0]['dst_ip'],'TCP')
                bucket=flood_buckets.setdefault(fkey,[])
                if bucket and packets[0]['ts']-bucket[0]['ts']>=2.0:
                    bucket.clear()
                bucket.extend(packets)
                if len(bucket)>=100:
                    sec_bucket=int(packets[-1]['ts'])
                    cnt=flood_emitted_per_sec.get((fkey,sec_bucket),0)
                    batch=bucket[:100]
                    del bucket[:100]
                    if cnt<25:
                        flood_emitted_per_sec[(fkey,sec_bucket)]=cnt+1
                        stats['windows']+=1
                        return summarize(batch)
            return None
        stats['windows']+=1;return summarize(packets)
    for seconds,frac,raw,wirelen in ordered_records(stream,endian,resources):
        ts=seconds+frac/scale
        stats['packets']+=1
        while groups:
            oldest=next(iter(groups))
            if ts-groups[oldest][0]['ts']<2:
                break
            row=close(groups.pop(oldest))
            if row:yield row
        try:eth=dpkt.ethernet.Ethernet(raw)
        except dpkt.UnpackError as exc:raise ValueError('Malformed Ethernet packet') from exc
        ip=eth.data
        # dpkt unwraps VLAN tags into eth.data; use the decoded payload type.
        if not isinstance(ip,dpkt.ip.IP):
            stats['skipped_packets']+=1
            continue
        if ip.offset or ip.mf:
            stats['skipped_packets']+=1
            continue
        t=ip.data
        if isinstance(t,dpkt.tcp.TCP):protocol='TCP';transport=t.off*4
        elif isinstance(t,dpkt.udp.UDP):protocol='UDP';transport=8
        elif isinstance(t,dpkt.icmp.ICMP):protocol='ICMP';transport=8
        else:
            stats['skipped_packets']+=1
            continue
        if ip.hl*4+transport>len(ip):raise ValueError('Incomplete packet headers')
        src=socket.inet_ntoa(ip.src);dst=socket.inet_ntoa(ip.dst)
        sport=getattr(t,'sport',0);dport=getattr(t,'dport',0)
        key=(src,dst,protocol,sport,dport)
        p=dict(ts=ts,size=wirelen,header=transport,ttl=ip.ttl,src_ip=src,dst_ip=dst,src_port=sport,dst_port=dport,
               protocol=protocol,flags=t.flags if protocol=='TCP' else 0,src_mac=eth.src.hex(':'),dst_mac=eth.dst.hex(':'))
        packets=groups.setdefault(key,[])
        packets.append(p)
        if len(packets)==100:
            row=close(groups.pop(key))
            if row:yield row
    for packets in list(groups.values()):
        row=close(packets)
        if row:yield row

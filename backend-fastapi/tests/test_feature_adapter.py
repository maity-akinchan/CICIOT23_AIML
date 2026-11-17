import io
import socket
import dpkt
import pytest
from app.services.pcap_runner import pcap_windows

def test_syn_capture_math():
    buffer=io.BytesIO()
    writer=dpkt.pcap.Writer(buffer)
    for i in range(100):
        tcp=dpkt.tcp.TCP(sport=1234,dport=80,flags=dpkt.tcp.TH_SYN,off=5)
        ip=dpkt.ip.IP(src=socket.inet_aton('172.18.0.50'),dst=socket.inet_aton('172.18.0.10'),p=6,ttl=64,data=tcp)
        ip.len=len(ip)
        eth=dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=dpkt.ethernet.ETH_TYPE_IP,data=ip)
        writer.writepkt(bytes(eth),ts=i*.0001)
    buffer.seek(0)
    rows=list(pcap_windows(buffer))
    assert len(rows)==1
    row=rows[0]
    assert row.flow_duration==pytest.approx(.0099,abs=1e-5)
    assert row.Rate==pytest.approx(100/.0099,abs=1e-5)
    assert row.AVG==54
    assert row.Header_Length==20  # TCP header only; Ethernet and IPv4 excluded
    assert row.input_representation=='packet_approximation'
    assert row.Duration==64
    assert row.syn_count==100
    assert row.ack_count==0
    assert row.Std==0

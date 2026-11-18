import socket
from pathlib import Path
import dpkt
from fastapi.testclient import TestClient
from app.main import app


def test_large_upload_and_enrollment(monkeypatch,tmp_path):
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/large.db')
    monkeypatch.delenv('SENTINEL_AUTH_DISABLED',raising=False)
    monkeypatch.setenv('SENTINEL_OPERATOR_TOKEN','operator-upload-test')
    headers={'Authorization':'Bearer operator-upload-test'}
    path=tmp_path/'large.pcap'
    with path.open('wb') as stream:
        writer=dpkt.pcap.Writer(stream)
        tcp=dpkt.tcp.TCP(sport=1234,dport=80,flags=2,off=5,data=b'x'*60000)
        ip=dpkt.ip.IP(src=socket.inet_aton('192.0.2.1'),dst=socket.inet_aton('192.0.2.2'),p=6,ttl=64,data=tcp);ip.len=len(ip)
        packet=bytes(dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=2048,data=ip))
        for i in range(600):writer.writepkt(packet,ts=i*.0001)
    assert path.stat().st_size>32*1024*1024
    with TestClient(app) as client:
        with path.open('rb') as stream:
            result=client.post('/api/v1/pcap/upload',headers=headers,files={'file':('large.pcap',stream)})
        assert result.status_code==200,result.text
        assert result.json()['processed_windows']==6
        before=client.get('/api/v1/flows',headers=headers).json()['total']
        with path.open('ab') as stream:stream.write(b'invalid-record')
        with path.open('rb') as stream:
            bad=client.post('/api/v1/pcap/upload',headers=headers,files={'file':('large.pcap',stream)})
        assert bad.status_code==422
        assert client.get('/api/v1/flows',headers=headers).json()['total']==before
        assert client.get('/api/v1/captures',headers=headers).json()['total']==1
        code=client.post('/api/v1/services/enrollments',headers=headers,json={'collector_id':'device-one'}).json()['code']
        token=client.post('/api/v1/services/enroll',json={'code':code})
        assert token.status_code==200,token.text
        assert token.json()['collector_id']=='device-one'
        assert client.post('/api/v1/services/enroll',json={'code':code}).status_code==401
        device={'Authorization':'Bearer '+token.json()['token']}
        assert client.post('/api/v1/services/verify',headers=device,json={'collector_id':'device-one'}).status_code==200
        assert client.get('/api/v1/flows',headers=device).status_code==403
        assert client.get('/api/v1/install.sh').status_code==200


def test_upload_crosses_batch_boundary(monkeypatch,tmp_path):
    from test_pipeline import capture
    from app.services.pcap_runner import pcap_windows
    from app.routers import pcap
    from uuid import uuid4
    monkeypatch.setenv('SENTINEL_AUTH_DISABLED','1')
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/batches.db')
    path=tmp_path/'small.pcap';capture(path)
    with path.open('rb') as stream:sample=next(pcap_windows(stream))
    def windows(_, diagnostics):
        for i in range(513):
            yield sample.model_copy(update={'window_id':str(uuid4())},deep=True)
    monkeypatch.setattr(pcap,'pcap_windows',windows)
    with TestClient(app) as client:
        r=client.post('/api/v1/pcap/upload',files={'file':('small.pcap',path.read_bytes())})
        assert r.status_code==200,r.text
        assert r.json()['processed_windows']==513
        assert client.get('/api/v1/flows').json()['total']==513


def test_upload_preserves_interleaved_overflow_windows(monkeypatch, tmp_path):
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/flows.db')
    monkeypatch.setenv('SENTINEL_AUTH_DISABLED', '1')
    path = tmp_path/'interleaved.pcap'
    with path.open('wb') as stream:
        writer = dpkt.pcap.Writer(stream)
        def packet(port):
            udp = dpkt.udp.UDP(sport=port, dport=53)
            ip = dpkt.ip.IP(src=b'\xc0\x00\x02\x01', dst=b'\xc0\x00\x02\x02', p=17, data=udp)
            return bytes(dpkt.ethernet.Ethernet(type=2048, data=ip))
        for port in range(1, 4099):
            writer.writepkt(packet(port), ts=1)
        for port in (1, 4097, 4098):
            for _ in range(4):
                writer.writepkt(packet(port), ts=1.5)
        writer.writepkt(packet(1), ts=3)
    with TestClient(app) as client, path.open('rb') as stream:
        result = client.post('/api/v1/pcap/upload', files={'file': (path.name, stream)})
        assert result.status_code == 200, result.text
        assert result.json()['processed_windows'] == 3
        assert result.json()['coverage'] == dict(packets=4111, windows=3, insufficient_packets=4096, skipped_packets=0)


def test_upload_mixed_ethernet_protocols(monkeypatch, tmp_path):
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/mixed.db')
    monkeypatch.setenv('SENTINEL_AUTH_DISABLED', '1')
    path = tmp_path / 'mixed.pcap'
    with path.open('wb') as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=0x86dd, data=bytes(40))), ts=1)
        writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=0x88cc, data=b'abc')), ts=1.1)
        udp = dpkt.udp.UDP(sport=1, dport=53)
        ip = dpkt.ip.IP(src=b'\xc0\x00\x02\x01', dst=b'\xc0\x00\x02\x02', p=17, data=udp)
        packet = bytes(dpkt.ethernet.Ethernet(type=2048, data=ip))
        for i in range(5):
            writer.writepkt(packet, ts=1.2 + i * .01)
    with TestClient(app) as client, path.open('rb') as stream:
        result = client.post('/api/v1/pcap/upload', files={'file': (path.name, stream)})
    assert result.status_code == 200, result.text
    assert result.json()['processed_windows'] == 1
    assert result.json()['coverage']['skipped_packets'] == 2

"""Application adapter around the packet approximation extractor."""
from datetime import datetime,timezone
from uuid import uuid4
from sentinel_ml.capture import extract
from app.schemas import FlowWindowPayload

def pcap_windows(stream, diagnostics=None):
    for row in extract(stream, diagnostics):
        yield FlowWindowPayload(input_representation='packet_approximation',**row['features_18'],**{k:row[k] for k in ('src_ip','dst_ip','src_port','dst_port','src_mac','dst_mac','packet_count')},
            dominant_protocol=row['protocol'],timestamp=datetime.fromtimestamp(row['timestamp_end'],timezone.utc),
            capture_mode='PCAP_UPLOAD',window_id=str(uuid4()))

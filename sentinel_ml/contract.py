"""Shared feature names and class vocabulary; preprocessing is in csv_contract."""
BASE = ('flow_duration','Rate','Header_Length','Duration','fin_flag_number',
        'syn_flag_number','rst_flag_number','psh_flag_number','ack_flag_number',
        'ack_count','syn_count','fin_count','rst_count','TCP','UDP','ICMP','AVG','Std')
DERIVED = ('bytes_per_sec','syn_ack_ratio','hdr_pkt_ratio','pkt_cv')
FEATURES = BASE + DERIVED
CLASSES = ('Benign','DDoS','DoS')

import type { FeatureName22, TrafficClass, DeviceHealthStatus } from '../types/telemetry';

export interface FeatureMeta {
  index: number;
  key: FeatureName22;
  label: string;
  shortLabel: string;
  unit: string;
  origin: 'Base (Go)' | 'Derived (Python)';
  explanation: string;
  format: (val: number) => string;
}

const fmtDec = (digits = 2) => (v: number) =>
  Number.isFinite(v) ? v.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits === 0 ? 0 : Math.min(digits, 2) }) : '0';

const fmtPctRatio = (v: number) =>
  Number.isFinite(v) ? `${(v * 100).toFixed(0)}%` : '0%';

/**
 * Locked 22-Feature Plain-English Dictionary (Indices 0..21)
 */
export const FEATURE_METADATA: Record<FeatureName22, FeatureMeta> = {
  flow_duration: {
    index: 1,
    key: 'flow_duration',
    label: 'Duration (sec)',
    shortLabel: 'Duration',
    unit: 'sec',
    origin: 'Base (Go)',
    explanation: 'Time elapsed between the first and 100th packet in the window.',
    format: (v) => `${v < 0.01 ? v.toFixed(4) : v.toFixed(3)}s`,
  },
  Rate: {
    index: 2,
    key: 'Rate',
    label: 'Packet Rate (pkt/s)',
    shortLabel: 'Packet Rate',
    unit: 'pkt/s',
    origin: 'Base (Go)',
    explanation: 'Speed of incoming packets per second. Sudden spikes indicate flood attacks.',
    format: (v) => `${Math.round(v).toLocaleString()} pkt/s`,
  },
  Header_Length: {
    index: 3,
    key: 'Header_Length',
    label: 'Header Size (bytes)',
    shortLabel: 'Header Size',
    unit: 'bytes',
    origin: 'Base (Go)',
    explanation: 'Average network + transport header size in bytes.',
    format: (v) => `${v.toFixed(1)} B`,
  },
  Duration: {
    index: 4,
    key: 'Duration',
    label: 'TTL (Hop Count)',
    shortLabel: 'TTL (Hops)',
    unit: 'hops',
    origin: 'Base (Go)',
    explanation: 'Average packet Time-To-Live (hop limit) across the network.',
    format: (v) => `${v.toFixed(0)} hops`,
  },
  fin_flag_number: {
    index: 5,
    key: 'fin_flag_number',
    label: 'FIN Flags (Closed Connections)',
    shortLabel: 'FIN Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Share of packets closing a TCP connection.',
    format: fmtPctRatio,
  },
  syn_flag_number: {
    index: 6,
    key: 'syn_flag_number',
    label: 'SYN Flags (New Connection Requests)',
    shortLabel: 'SYN Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Share of packets requesting a new TCP connection. Near 100% during SYN floods.',
    format: fmtPctRatio,
  },
  rst_flag_number: {
    index: 7,
    key: 'rst_flag_number',
    label: 'RST Flags (Dropped Connections)',
    shortLabel: 'RST Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Share of packets abruptly resetting connections.',
    format: fmtPctRatio,
  },
  psh_flag_number: {
    index: 8,
    key: 'psh_flag_number',
    label: 'PSH Flags (Push Data)',
    shortLabel: 'PSH Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Share of packets pushing active application data.',
    format: fmtPctRatio,
  },
  ack_flag_number: {
    index: 9,
    key: 'ack_flag_number',
    label: 'ACK Flags (Confirmed Packets)',
    shortLabel: 'ACK Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Share of packets confirming legitimate two-way traffic.',
    format: fmtPctRatio,
  },
  ack_count: {
    index: 10,
    key: 'ack_count',
    label: 'ACK Count (Confirmed)',
    shortLabel: 'ACK Count',
    unit: 'packets',
    origin: 'Base (Go)',
    explanation: 'Number of confirmed ACK packets out of 100 packets.',
    format: (v) => `${Math.round(v)}`,
  },
  syn_count: {
    index: 11,
    key: 'syn_count',
    label: 'SYN Count (New Requests)',
    shortLabel: 'SYN Count',
    unit: 'packets',
    origin: 'Base (Go)',
    explanation: 'Number of new SYN connection requests out of 100 packets.',
    format: (v) => `${Math.round(v)}`,
  },
  fin_count: {
    index: 12,
    key: 'fin_count',
    label: 'FIN Count (Closed)',
    shortLabel: 'FIN Count',
    unit: 'packets',
    origin: 'Base (Go)',
    explanation: 'Number of connection teardown packets out of 100 packets.',
    format: (v) => `${Math.round(v)}`,
  },
  rst_count: {
    index: 13,
    key: 'rst_count',
    label: 'RST Count (Dropped)',
    shortLabel: 'RST Count',
    unit: 'packets',
    origin: 'Base (Go)',
    explanation: 'Number of connection reset packets out of 100 packets.',
    format: (v) => `${Math.round(v)}`,
  },
  TCP: {
    index: 14,
    key: 'TCP',
    label: 'TCP Traffic Share',
    shortLabel: 'TCP Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Percentage of window traffic using TCP.',
    format: fmtPctRatio,
  },
  UDP: {
    index: 15,
    key: 'UDP',
    label: 'UDP Traffic Share',
    shortLabel: 'UDP Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Percentage of window traffic using UDP.',
    format: fmtPctRatio,
  },
  ICMP: {
    index: 16,
    key: 'ICMP',
    label: 'ICMP Traffic Share',
    shortLabel: 'ICMP Share',
    unit: 'ratio',
    origin: 'Base (Go)',
    explanation: 'Percentage of window traffic using ICMP (ping floods).',
    format: fmtPctRatio,
  },
  AVG: {
    index: 17,
    key: 'AVG',
    label: 'Average Packet Size',
    shortLabel: 'Avg Size',
    unit: 'bytes',
    origin: 'Base (Go)',
    explanation: 'Average size of each packet on the wire in bytes.',
    format: (v) => `${v.toFixed(1)} B`,
  },
  Std: {
    index: 18,
    key: 'Std',
    label: 'Packet Size Spread',
    shortLabel: 'Size Spread',
    unit: 'bytes',
    origin: 'Base (Go)',
    explanation: 'Standard deviation of packet lengths (0 B means identical flood packets).',
    format: (v) => `${v.toFixed(1)} B`,
  },
  bytes_per_sec: {
    index: 19,
    key: 'bytes_per_sec',
    label: 'Traffic Speed (Bytes/s)',
    shortLabel: 'Traffic Speed',
    unit: 'B/s',
    origin: 'Derived (Python)',
    explanation: 'Total bandwidth throughput (Packet Rate × Average Packet Size).',
    format: (v) => {
      if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)} MB/s`;
      if (v >= 1_000) return `${(v / 1_000).toFixed(1)} KB/s`;
      return `${Math.round(v)} B/s`;
    },
  },
  syn_ack_ratio: {
    index: 20,
    key: 'syn_ack_ratio',
    label: 'SYN-to-ACK Ratio (Unfinished Connections)',
    shortLabel: 'SYN-to-ACK Ratio',
    unit: 'ratio',
    origin: 'Derived (Python)',
    explanation: 'Compares new connection requests against confirmed replies. High during SYN floods.',
    format: (v) => `${fmtDec(1)(v)}×`,
  },
  hdr_pkt_ratio: {
    index: 21,
    key: 'hdr_pkt_ratio',
    label: 'Header-to-Packet Ratio',
    shortLabel: 'Header Ratio',
    unit: 'ratio',
    origin: 'Derived (Python)',
    explanation: 'Share of packet taken up by headers. High in empty flood packets.',
    format: fmtDec(2),
  },
  pkt_cv: {
    index: 22,
    key: 'pkt_cv',
    label: 'Packet Size Variation',
    shortLabel: 'Size Variation',
    unit: 'ratio',
    origin: 'Derived (Python)',
    explanation: 'Separates uniform single-source DoS floods from multi-source DDoS attacks.',
    format: fmtDec(2),
  },
};

export function getFeatureLabel(featureKey: string): string {
  const meta = FEATURE_METADATA[featureKey as FeatureName22];
  return meta ? meta.label : featureKey;
}

export function getFeatureShortLabel(featureKey: string): string {
  const meta = FEATURE_METADATA[featureKey as FeatureName22];
  return meta ? meta.shortLabel : featureKey;
}

export function formatFeatureValue(featureKey: string, value: number): string {
  const meta = FEATURE_METADATA[featureKey as FeatureName22];
  return meta ? meta.format(value) : Number.isFinite(value) ? value.toFixed(2) : '0';
}

export function getPlainTrafficLabel(predictedClass: TrafficClass): string {
  switch (predictedClass) {
    case 'Benign':
      return 'Normal';
    case 'DoS':
      return 'DoS Attack';
    case 'DDoS':
      return 'DDoS Attack';
  }
}

export function getPlainStatusLabel(status: string): DeviceHealthStatus {
  const upper = status.toUpperCase();
  if (upper === 'UNVERIFIED') return 'Unverified';
  if (upper.includes('DDOS')) return 'DDoS Attack';
  if (upper.includes('DOS')) return 'DoS Attack';
  return 'Normal';
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0m 00s';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${String(h).padStart(2, '0')}h ${String(m).padStart(2, '0')}m`;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

export function formatRelativeTime(isoString: string): string {
  const ts = Date.parse(isoString);
  if (Number.isNaN(ts)) return isoString;
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 10) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatClockTime(isoString: string): string {
  const ts = Date.parse(isoString);
  if (Number.isNaN(ts)) return isoString;
  return new Date(ts).toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

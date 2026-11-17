/// <reference types="vite/client" />
import axios from 'axios';
import {
  HealthResponseSchema,
  type FlowRecord,
  FlowRecordSchema,
} from '../types/telemetry';

const STORAGE_KEY_API_URL = 'sentinel_api_base_url';
const CSV_FEATURE_CONTRACT_ID = 'ciciot23-kaggle-csv22-v2';
const CSV_FEATURE_CONTRACT_HASH =
  '7c9b337a461ca64acabd1b62dd44025b2d3c46148888151a98d137468fa16506';

export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined') {
    const saved = window.localStorage.getItem(STORAGE_KEY_API_URL);
    if (saved && saved.trim().length > 0) {
      return saved.trim().replace(/\/+$/, '');
    }
  }
  return (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(
    /\/+$/,
    ''
  );
}

export function setApiBaseUrl(url: string): void {
  const clean = url.trim().replace(/\/+$/, '');
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY_API_URL, clean);
  }
  apiClient.defaults.baseURL = clean;
}

export function getWsLiveUrl(baseUrl?: string): string {
  const base = (baseUrl || getApiBaseUrl()).replace(/\/+$/, '');
  if (import.meta.env.VITE_WS_URL && !baseUrl) {
    return import.meta.env.VITE_WS_URL;
  }
  return `${base.replace(/^http/, 'ws')}/ws/live`;
}

export const apiClient = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export function getOperatorToken(): string {
  return sessionStorage.getItem('sentinel_operator_token') || '';
}
apiClient.interceptors.request.use(config => {
  const token=getOperatorToken();
  if(token && !config.headers.Authorization) config.headers.Authorization=`Bearer ${token}`;
  return config;
});
export interface BackendHealthStatus {
  online: boolean;
  modelLoaded: boolean;
  isBootstrapModel: boolean;
  latencyMs: number | null;
  error?: string;
}

/**
 * Calls FastAPI `GET /health`
 */
export async function checkBackendHealth(
  overrideBaseUrl?: string
): Promise<BackendHealthStatus> {
  const start = performance.now();
  try {
    const client = overrideBaseUrl
      ? axios.create({ baseURL: overrideBaseUrl.trim().replace(/\/+$/, ''), timeout: 6000 })
      : apiClient;
    const { data } = await client.get('/health');
    const latencyMs = Math.max(1, Math.round(performance.now() - start));
    const parsed = HealthResponseSchema.parse(data);
    return {
      online: parsed.status === 'ok',
      modelLoaded: parsed.model_loaded,
      isBootstrapModel: parsed.is_bootstrap_model,
      latencyMs,
    };
  } catch (err) {
    const msg =
      axios.isAxiosError(err)
        ? err.message || 'Cannot connect to FastAPI server'
        : 'Cannot connect to FastAPI server';
    return {
      online: false,
      modelLoaded: false,
      isBootstrapModel: false,
      latencyMs: null,
      error: msg,
    };
  }
}

/**
 * Sends 18-feature FlowWindowPayloads to FastAPI `POST /api/v1/predict/batch`.
 * No fake fallback: if FastAPI is unreachable, throws an error so the UI stays honest.
 */
export async function sendLiveTrafficBatchToFastApi(
  count = 5
): Promise<BatchPredictionResponse> {
  const safeCount = Math.min(100, Math.max(1, count));
  const targets = ['10.0.0.5', '10.0.0.12', '10.0.0.18', '10.0.0.24'];

  const batchPayload = Array.from({ length: safeCount }, (_, idx) => {
    const roll = Math.random();
    const isDos = roll > 0.62 && roll <= 0.84;
    const isDdos = roll > 0.84;
    const dst_ip = targets[idx % targets.length];
    const src_ip = isDos
      ? '192.168.1.50'
      : isDdos
        ? `192.168.1.${100 + Math.floor(Math.random() * 90)}`
        : `192.168.1.${10 + (idx % 20)}`;

    const Rate = isDos
      ? 9800 + Math.random() * 4500
      : isDdos
        ? 6800 + Math.random() * 3200
        : 18 + Math.random() * 45;
    const syn_count = isDos ? 100 : isDdos ? 75 : 5;
    const ack_count = isDos ? 0 : isDdos ? 5 : 40;
    const AVG = isDos ? 54 : isDdos ? 250 : 500;
    const Std = isDos ? 0 : isDdos ? 180 : 120;

    return {
      src_ip,
      dst_ip,
      src_mac: '00:1A:2B:3C:4D:5E',
      timestamp: new Date().toISOString(),
      window_id: `batch-${Date.now()}-${idx}`,
      packet_count: 100,
      capture_mode: 'CSV_REPLAY',
      src_port: 49152 + idx,
      dst_port: 80,
      dominant_protocol: 'TCP' as const,
      flow_duration: Number((100 / Rate).toFixed(5)),
      Rate: Number(Rate.toFixed(2)),
      Header_Length: 40.0,
      Duration: 64.0,
      fin_flag_number: 0.0,
      syn_flag_number: Number((syn_count / 100).toFixed(2)),
      rst_flag_number: 0.0,
      psh_flag_number: isDos || isDdos ? 0.0 : 0.12,
      ack_flag_number: Number((ack_count / 100).toFixed(2)),
      ack_count,
      syn_count,
      fin_count: 0,
      rst_count: 0,
      TCP: 1.0,
      UDP: 0.0,
      ICMP: 0.0,
      AVG,
      Std,
    };
  });

  const { data } = await apiClient.post('/api/v1/predict/batch', {
    data: batchPayload,
  });
  return BatchPredictionResponseSchema.parse(data);
}

/**
 * Calls FastAPI `POST /api/v1/ingest/windows` using the exact CollectorWindow schema
 * defined in `backend-fastapi/app/schemas.py`.
 */
export async function sendCollectorIngestBatch(
  collectorId = 'browser-probe-01',
  count = 3
): Promise<BatchPredictionResponse> {
  const safeCount = Math.min(100, Math.max(1, count));
  const profiles = [
    {
      label: 'Benign',
      src_ip: '192.168.1.14',
      dst_ip: '10.0.0.5',
      Rate: 24.5,
      syn: 0.05,
      ack: 0.4,
      avg: 500.0,
      std: 120.0,
    },
    {
      label: 'DoS',
      src_ip: '192.168.1.50',
      dst_ip: '10.0.0.5',
      Rate: 10500.0,
      syn: 1.0,
      ack: 0.0,
      avg: 54.0,
      std: 0.0,
    },
    {
      label: 'DDoS',
      src_ip: '192.168.1.142',
      dst_ip: '10.0.0.12',
      Rate: 7400.0,
      syn: 0.75,
      ack: 0.05,
      avg: 250.0,
      std: 180.0,
    },
  ];

  const windows = Array.from({ length: safeCount }, (_, idx) => {
    const p = profiles[idx % profiles.length];
    return {
      window_id: `ingest-${Date.now()}-${idx}`,
      timestamp_end: new Date().toISOString(),
      packet_count: 100,
      metadata: {
        src_ip: p.src_ip,
        dst_ip: p.dst_ip,
        src_mac: '00:1A:2B:3C:4D:5E',
        dst_mac: '02:42:AC:12:00:0A',
        src_port: 50000 + idx,
        dst_port: 80,
        dominant_protocol: 'TCP' as const,
        device_vendor: 'IoT-Endpoint',
      },
      features_18: {
        flow_duration: Number((100 / p.Rate).toFixed(5)),
        Rate: p.Rate,
        Header_Length: 40.0,
        Duration: 64.0,
        fin_flag_number: 0.0,
        syn_flag_number: p.syn,
        rst_flag_number: 0.0,
        psh_flag_number: 0.0,
        ack_flag_number: p.ack,
        ack_count: p.ack * 100,
        syn_count: p.syn * 100,
        fin_count: 0.0,
        rst_count: 0.0,
        TCP: 1.0,
        UDP: 0.0,
        ICMP: 0.0,
        AVG: p.avg,
        Std: p.std,
      },
    };
  });

  const { data } = await apiClient.post('/api/v1/ingest/windows', {
    collector_id: collectorId,
    capture_mode: 'LIVE_INTERFACE',
    source_ref: 'onboarding-verification',
    windows,
  });

  return BatchPredictionResponseSchema.parse(data);
}

export interface UploadAnalysisSummary {
  fileName: string;
  processedWindows: number;
  benignCount: number;
  dosCount: number;
  ddosCount: number;
  flows: FlowRecord[];
}

/** Upload a capture and fetch only the predictions from its analysis session. */
export async function analyzeUploadedFile(file: File): Promise<UploadAnalysisSummary> {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    throw new Error(
      'FastAPI currently accepts 18-feature .csv flow files via POST /api/v1/predict/batch.'
    );
  }

  const text = await file.text();
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) {
    throw new Error('CSV file must contain a header row and at least 1 data row.');
  }

  const headers = lines[0]
    .replace(/^\uFEFF/, '')
    .split(',')
    .map((h) => h.trim());

  const missing = BASE_FEATURE_NAMES.filter((feat) => !headers.includes(feat));
  if (missing.length > 0) {
    throw new Error(
      `CSV is missing required 18-feature columns: ${missing.slice(0, 5).join(', ')}${
        missing.length > 5 ? '...' : ''
      }`
    );
  }

  // Parse up to 100 rows (matching FastAPI BatchPredictionRequest max_length=100)
  const dataLines = lines.slice(1, 101);
  const payloads = dataLines.map((line, idx) => {
    const cols = line.split(',');
    const rowMap: Record<string, string> = {};
    headers.forEach((h, i) => {
      rowMap[h] = (cols[i] ?? '').trim();
    });

    const features: Record<string, number> = {};
    BASE_FEATURE_NAMES.forEach((feat) => {
      const val = Number(rowMap[feat]);
      features[feat] = Number.isFinite(val) ? val : 0;
    });

    const tcp = features.TCP ?? 0;
    const udp = features.UDP ?? 0;
    const icmp = features.ICMP ?? 0;
    const dominant_protocol: 'TCP' | 'UDP' | 'ICMP' =
      tcp >= Math.max(udp, icmp) ? 'TCP' : udp >= icmp ? 'UDP' : 'ICMP';

    return {
      ...features,
      src_ip: rowMap.src_ip || `192.168.1.${10 + (idx % 41)}`,
      dst_ip: rowMap.dst_ip || `10.0.0.${5 + (idx % 4)}`,
      src_mac: rowMap.src_mac || '00:1A:2B:3C:4D:5E',
      timestamp: new Date().toISOString(),
      window_id: `csv-${Date.now()}-${idx + 1}`,
      packet_count: 100,
      capture_mode: 'CSV_REPLAY',
      src_port: 40000 + (idx % 1000),
      dst_port: 80,
      dominant_protocol,
    };
  });

  const { data } = await apiClient.post('/api/v1/predict/batch', {
    data: payloads,
  });
  const parsed = BatchPredictionResponseSchema.parse(data);

  return {
    fileName: file.name,
    processedWindows: parsed.processed_windows,
    benignCount: parsed.benign_count,
    dosCount: parsed.dos_count,
    ddosCount: parsed.ddos_count,
    flows: parsed.predictions,
  };
}

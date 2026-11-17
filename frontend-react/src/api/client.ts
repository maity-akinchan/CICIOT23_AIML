/// <reference types="vite/client" />
import axios from 'axios';
import {
  HealthResponseSchema,
  type FlowRecord,
  FlowRecordSchema,
} from '../types/telemetry';

const STORAGE_KEY_API_URL = 'sentinel_api_base_url';

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
  if (!file.name.toLowerCase().endsWith('.pcap')) throw new Error('Choose a classic .pcap file');
  if (file.size > 32*1024*1024) throw new Error('Maximum PCAP size is 32 MiB');
  const form=new FormData(); form.append('file',file);
  const {data}=await apiClient.post('/api/v1/pcap/upload',form,{headers:{'Content-Type':'multipart/form-data'},timeout:120000});
  const flows: FlowRecord[]=[];
  for(let offset=0;offset<data.processed_windows;offset+=1000){
    const response=await apiClient.get('/api/v1/flows',{params:{capture_session_id:data.capture_session_id,limit:1000,offset}});
    flows.push(...response.data.items.map((row:unknown)=>FlowRecordSchema.parse(row)));
  }
  return {fileName:file.name,processedWindows:data.processed_windows,benignCount:data.benign_count,dosCount:data.dos_count,ddosCount:data.ddos_count,flows};
}

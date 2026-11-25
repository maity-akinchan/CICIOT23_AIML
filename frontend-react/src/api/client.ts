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
  return (import.meta.env.VITE_API_BASE_URL || (typeof window!=='undefined'?window.location.origin:'http://localhost:8000')).replace(
    /\/+$/,
    ''
  );
}

export function setApiBaseUrl(url: string): void {
  const clean = url.trim().replace(/\/+$/, '');
  if (typeof window !== 'undefined') {
    if (clean !== getApiBaseUrl()) window.sessionStorage.removeItem('sentinel_operator_token');
    window.localStorage.setItem(STORAGE_KEY_API_URL, clean);
  }
  apiClient.defaults.baseURL = clean;
}

export function getWsLiveUrl(baseUrl?: string): string {
  const base = (baseUrl || getApiBaseUrl()).replace(/\/+$/, '');
  if (import.meta.env.VITE_WS_URL && !baseUrl && !localStorage.getItem(STORAGE_KEY_API_URL)?.trim()) {
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
      error: parsed.model_loaded ? undefined : (data.reason || 'Model unavailable'),
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
  captureSessionId?: string;
  fileName: string;
  processedWindows: number;
  coverage?: {packets: number; insufficient_packets: number; skipped_packets: number};
  benignCount: number;
  dosCount: number;
  ddosCount: number;
  flows: FlowRecord[];
}

/** Upload a capture and fetch only the predictions from its analysis session. */
export async function analyzeUploadedFile(file: File): Promise<UploadAnalysisSummary> {
  if (!file.name.toLowerCase().endsWith('.pcap')) throw new Error('Choose a classic .pcap file. PCAPNG is not supported.');
  try {
    const health=await apiClient.get('/health');
    if(!health.data.model_loaded)throw new Error(`The server model is not loaded: ${health.data.reason || 'check System console'}`);
    const form=new FormData();form.append('file',file);
    const {data}=await apiClient.post('/api/v1/pcap/upload',form,{headers:{'Content-Type':'multipart/form-data'},timeout:0});
    const response=await apiClient.get('/api/v1/flows',{params:{capture_session_id:data.capture_session_id,limit:1000}});
    return {fileName:file.name,coverage:data.coverage,processedWindows:data.processed_windows,benignCount:data.benign_count,dosCount:data.dos_count,ddosCount:data.ddos_count,flows:response.data.items.map((row:unknown)=>FlowRecordSchema.parse(row)),captureSessionId:data.capture_session_id};
  } catch(error) {throw new Error(apiErrorMessage(error));}
}
export function apiErrorMessage(error:unknown):string {
  if(axios.isAxiosError(error)) {
    const status=error.response?.status;
    if(status===401)return 'Invalid login credentials. Please sign in and try again.';
    if(status===403)return 'This action requires operator access.';
    const detail=error.response?.data?.detail;
    if(typeof detail==='string')return detail;
    if(status===413)return 'A server or proxy rejected the upload size. The application has no PCAP size limit; check the proxy configuration.';
    if(!error.response)return 'Cannot reach the server. Check the server address and connection.';
    return `Request failed (${status}). Check System console for server status.`;
  }
  return error instanceof Error?error.message:'Request failed';
}

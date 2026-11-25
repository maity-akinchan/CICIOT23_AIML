import { z } from 'zod';

/**
 * 18 Base Features extracted in 100-packet windows
 * EXACT case-sensitive CICIoT2023 feature names matching FastAPI app/schemas.py
 */
export const BASE_FEATURE_NAMES = [
  'flow_duration',
  'Rate',
  'Header_Length',
  'Duration',
  'fin_flag_number',
  'syn_flag_number',
  'rst_flag_number',
  'psh_flag_number',
  'ack_flag_number',
  'ack_count',
  'syn_count',
  'fin_count',
  'rst_count',
  'TCP',
  'UDP',
  'ICMP',
  'AVG',
  'Std',
] as const;

/**
 * 4 Derived Ratio Features computed deterministically in FastAPI
 */
export const DERIVED_FEATURE_NAMES = [
  'bytes_per_sec',
  'syn_ack_ratio',
  'hdr_pkt_ratio',
  'pkt_cv',
] as const;

/**
 * All 22 Locked Features in exact indices 0..21 order
 */
export const FEATURE_NAMES_22 = [
  ...BASE_FEATURE_NAMES,
  ...DERIVED_FEATURE_NAMES,
] as const;

export type FeatureName22 = (typeof FEATURE_NAMES_22)[number];

const finiteNumber = z.coerce.number().transform((val) => (Number.isFinite(val) ? val : 0));

export const Features18Schema = z.object({
  flow_duration: finiteNumber,
  Rate: finiteNumber,
  Header_Length: finiteNumber,
  Duration: finiteNumber,
  fin_flag_number: finiteNumber,
  syn_flag_number: finiteNumber,
  rst_flag_number: finiteNumber,
  psh_flag_number: finiteNumber,
  ack_flag_number: finiteNumber,
  ack_count: finiteNumber,
  syn_count: finiteNumber,
  fin_count: finiteNumber,
  rst_count: finiteNumber,
  TCP: finiteNumber,
  UDP: finiteNumber,
  ICMP: finiteNumber,
  AVG: finiteNumber,
  Std: finiteNumber,
});

export const Features22Schema = Features18Schema.extend({
  bytes_per_sec: finiteNumber,
  syn_ack_ratio: finiteNumber,
  hdr_pkt_ratio: finiteNumber,
  pkt_cv: finiteNumber,
});

export type Features18 = z.infer<typeof Features18Schema>;
export type Features22 = z.infer<typeof Features22Schema>;

export const TrafficClassSchema = z.enum(['Benign', 'DoS', 'DDoS']);
export type TrafficClass = z.infer<typeof TrafficClassSchema>;

export const ProtocolSchema = z.enum(['TCP', 'UDP', 'ICMP']);
export type ProtocolType = z.infer<typeof ProtocolSchema>;

export const AnomalyExplanationSchema = z.object({
  feature: z.string(),
  value: finiteNumber,
  benign_median: finiteNumber,
  z_iqr: finiteNumber,
  direction: z.enum(['HIGH', 'LOW']).default('HIGH'),
});

export type AnomalyExplanation = z.infer<typeof AnomalyExplanationSchema>;

/**
 * Matches FastAPI PredictionResult in backend-fastapi/app/schemas.py
 */
export const FlowRecordSchema = z
  .object({
    id: z.union([z.number(), z.string()]).optional(),
    window_id: z.string().nullable().optional(),
    timestamp: z.string(),
    capture_mode: z.string().optional().default('LIVE_INTERFACE'),
    src_ip: z.string(),
    dst_ip: z.string(),
    src_mac: z.string().optional().default(''),
    dst_mac: z.string().optional().default(''),
    src_port: z.number().optional().default(0),
    dst_port: z.number().optional().default(80),
    protocol: z.string().optional(),
    dominant_protocol: z.string().optional(),
    packet_count: z.number().optional().default(100),
    predicted_class: TrafficClassSchema,
    confidence: finiteNumber.optional(),
    confidence_score: finiteNumber.optional(),
    is_anomaly: z.boolean().optional(),
    probabilities: z
      .record(z.string(), finiteNumber),
    model_used: z.string().optional().default('Unknown'),
    top_anomalies: z.array(AnomalyExplanationSchema).optional().default([]),
    capture_session_id: z.string().optional(),
    artifact_sha256: z.string().optional(),
    input_representation: z.string().optional(),
    compatibility_warning: z.string().nullable().optional(),
    features_22: Features22Schema,
  })
  .transform((raw) => {
    const confidence = raw.confidence_score ?? raw.confidence ?? 0;
    const protocol: ProtocolType =
      raw.protocol === 'UDP' || raw.dominant_protocol === 'UDP' || raw.features_22.UDP > 0.5
        ? 'UDP'
        : raw.protocol === 'ICMP' || raw.dominant_protocol === 'ICMP' || raw.features_22.ICMP > 0.5
          ? 'ICMP'
          : 'TCP';
    const windowId =
      raw.window_id ||
      `win-${raw.timestamp}-${raw.src_ip}-${raw.dst_ip}-${raw.features_22.Rate}`;
    return {
      id: raw.id ?? windowId,
      window_id: windowId,
      timestamp: raw.timestamp,
      capture_mode: raw.capture_mode,
      src_ip: raw.src_ip,
      dst_ip: raw.dst_ip,
      src_mac: raw.src_mac,
      dst_mac: raw.dst_mac,
      src_port: raw.src_port,
      dst_port: raw.dst_port,
      protocol,
      packet_count: raw.packet_count,
      predicted_class: raw.predicted_class,
      is_anomaly: raw.is_anomaly ?? raw.predicted_class !== 'Benign',
      confidence: confidence > 1 ? confidence / 100 : confidence,
      probabilities: {
        Benign: raw.probabilities.Benign ?? (raw.predicted_class === 'Benign' ? confidence : 0),
        DoS: raw.probabilities.DoS ?? (raw.predicted_class === 'DoS' ? confidence : 0),
        DDoS: raw.probabilities.DDoS ?? (raw.predicted_class === 'DDoS' ? confidence : 0),
      },
      model_used: raw.model_used,
      top_anomalies: raw.top_anomalies,
      capture_session_id: raw.capture_session_id,
      artifact_sha256: raw.artifact_sha256,
      input_representation: raw.input_representation,
      compatibility_warning: raw.compatibility_warning,
      features_22: raw.features_22,
    };
  });

export type FlowRecord = z.output<typeof FlowRecordSchema>;

/**
 * Matches FastAPI BatchPredictionResponse in backend-fastapi/app/schemas.py
 */
export const BatchPredictionResponseSchema = z.object({
  predictions: z.array(FlowRecordSchema),
  processed_windows: finiteNumber,
  benign_count: finiteNumber,
  dos_count: finiteNumber,
  ddos_count: finiteNumber,
});

export type BatchPredictionResponse = z.output<typeof BatchPredictionResponseSchema>;

/**
 * Matches FastAPI GET /health in backend-fastapi/app/main.py
 */
export const HealthResponseSchema = z.object({
  status: z.string(),
  model_loaded: z.boolean(),
  active_model_id: z.string().nullable().optional(),
  is_bootstrap_model: z.boolean(),
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

export const KpiSummarySchema = z.object({
  total_flows: finiteNumber,
  benign_count: finiteNumber,
  dos_count: finiteNumber,
  ddos_count: finiteNumber,
  attack_percentage: finiteNumber,
  current_fps: finiteNumber.optional().default(0),
  active_alerts_count: finiteNumber.optional().default(0),
});

export type KpiSummary = z.infer<typeof KpiSummarySchema>;

export const SecurityAlertSchema = z.object({
  id: z.string(),
  window_id: z.string(),
  timestamp: z.string(),
  attack_type: z.enum(['DoS', 'DDoS']),
  severity: z.enum(['HIGH', 'CRITICAL']),
  src_ip: z.string(),
  dst_ip: z.string(),
  protocol: ProtocolSchema.catch('TCP'),
  confidence: finiteNumber,
  model_used: z.string(),
  top_anomalies: z.array(AnomalyExplanationSchema).default([]),
  acknowledged: z.boolean().default(false),
});

export type SecurityAlert = z.infer<typeof SecurityAlertSchema>;

export const DeviceStatusSchema = z.enum([
  'Unverified',
  'Normal',
  'DoS Attack',
  'DDoS Attack',
]);

export type DeviceHealthStatus = z.infer<typeof DeviceStatusSchema>;

/**
 * Dynamically aggregated endpoint summary from real FastAPI flows
 */
export interface DiscoveredEndpoint {
  ip_address: string;
  total_flows_seen: number;
  benign_flows_seen: number;
  dos_flows_seen: number;
  ddos_flows_seen: number;
  attack_flows_seen: number;
  last_seen: string;
  status: DeviceHealthStatus;
  last_protocol: ProtocolType;
  peak_rate_pps: number;
}

/**
 * Matches FastAPI WS /ws/live broadcast payload in backend-fastapi/app/routers/ingest.py
 */
export const TelemetryBatchFrameSchema = z.object({
  event_type: z.string().default('TELEMETRY_BATCH'),
  server_timestamp: z.string().optional(),
  active_model_id: z.string().optional().default('xgb'),
  flows: z.array(FlowRecordSchema).default([]),
});

export type TelemetryBatchFrame = z.output<typeof TelemetryBatchFrameSchema>;

export interface TimeSeriesPoint {
  time: string;
  normal: number;
  attack: number;
  dos: number;
  ddos: number;
  packetRate: number;
}

/**
 * Active Dashboard Pages (only features supported by FastAPI are exposed)
 */
export type DashboardPageId =
  | 'capture-history'
  | 'system-console'
  | 'pcap-analysis'
  | 'overview'
  | 'live-traffic'
  | 'alerts'
  | 'flow-explorer'
  | 'onboarding'
  | 'profile';

export type AppStage = 'landing' | 'auth' | 'profile-setup' | 'onboarding' | 'console';

/**
 * Form Validation Schemas (Zod)
 */
export const WorkspaceAuthSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3, 'Enter a valid email or username (at least 3 characters)'),
  password: z.string().min(4, 'Password must be at least 4 characters'),
  orgName: z.string().trim().optional(),
});

export const OperatorProfileSchema = z.object({
  fullName: z
    .string()
    .trim()
    .min(2, 'Enter your full name (at least 2 characters)')
    .max(60, 'Name must be under 60 characters'),
  role: z
    .string()
    .trim()
    .min(2, 'Enter your role or title (e.g. Security Analyst)')
    .max(48, 'Role must be under 48 characters'),
  orgName: z
    .string()
    .trim()
    .min(2, 'Enter your workspace or organization name')
    .max(64, 'Organization name must be under 64 characters'),
  email: z
    .string()
    .trim()
    .min(3, 'Enter your work email or username'),
  apiBaseUrl: z
    .string()
    .trim()
    .url('Enter a valid FastAPI URL (e.g. http://localhost:8000)'),
  batchSize: z.coerce.number().min(1).max(100).default(5),
  onboardingCompleted: z.boolean().default(false),
});

export type OperatorProfile = z.infer<typeof OperatorProfileSchema>;

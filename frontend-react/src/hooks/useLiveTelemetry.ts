import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  analyzeUploadedFile,
  apiClient,
  checkBackendHealth,
  getOperatorToken,
  getWsLiveUrl,
  type BackendHealthStatus,
  type UploadAnalysisSummary,
} from '../api/client';
import {
  TelemetryBatchFrameSchema,
  FlowRecordSchema,
  SecurityAlertSchema,
  type DiscoveredEndpoint,
  type FlowRecord,
  type KpiSummary,
  type SecurityAlert,
  type TimeSeriesPoint,
} from '../types/telemetry';
import { formatClockTime } from '../utils/plainEnglish';

const MAX_FLOWS = 250;
const MAX_CHART_POINTS = 60;

export function useLiveTelemetry() {
  const [wsConnected, setWsConnected] = useState(false);
  const [health, setHealth] = useState<BackendHealthStatus>({
    online: false,
    modelLoaded: false,
    isBootstrapModel: false,
    latencyMs: null,
  });
  const [activeModelName, setActiveModelName] = useState<string>('Checking FastAPI...');
  const [apiError, setApiError] = useState<string | null>(null);

  const [streamPaused, setStreamPaused] = useState(false);

  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [timeSeries, setTimeSeries] = useState<TimeSeriesPoint[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [alertsError, setAlertsError] = useState(false);
  const [flowsError, setFlowsError] = useState(false);

  const [counters, setCounters] = useState({
    total: 0,
    benign: 0,
    dos: 0,
    ddos: 0,
    fps: 0,
  });

  const [lastUpdated, setLastUpdated] = useState<string>('Never');

  const pausedRef = useRef(streamPaused);
  pausedRef.current = streamPaused;

  // Deduplicate windows across HTTP response and WebSocket broadcast
  const seenWindowIdsRef = useRef<Set<string>>(new Set());

  const ingestFlowsIntoState = useCallback((incomingRaw: FlowRecord[]) => {
    if (!incomingRaw.length || pausedRef.current) return;

    const fresh: FlowRecord[] = [];
    for (const item of incomingRaw) {
      if (!seenWindowIdsRef.current.has(item.window_id)) {
        seenWindowIdsRef.current.add(item.window_id);
        fresh.push(item);
      }
    }
    if (fresh.length === 0) return;

    // Prevent unbounded growth of deduplication set
    if (seenWindowIdsRef.current.size > 2000) {
      const arr = Array.from(seenWindowIdsRef.current).slice(-1000);
      seenWindowIdsRef.current = new Set(arr);
    }

    const firstModel = fresh[0]?.model_used;
    if (firstModel) {
      setActiveModelName(firstModel);
    }

    const benignBatch = fresh.filter((f) => f.predicted_class === 'Benign').length;
    const dosBatch = fresh.filter((f) => f.predicted_class === 'DoS').length;
    const ddosBatch = fresh.filter((f) => f.predicted_class === 'DDoS').length;
    const avgRate =
      fresh.reduce((acc, f) => acc + (f.features_22.Rate || 0), 0) / fresh.length;

    setFlows((prev) => [...fresh, ...prev].slice(0, MAX_FLOWS));

    setCounters((prev) => ({
      total: prev.total + fresh.length,
      benign: prev.benign + benignBatch,
      dos: prev.dos + dosBatch,
      ddos: prev.ddos + ddosBatch,
      fps: Number(fresh.length.toFixed(1)),
    }));

    const nowLabel = formatClockTime(new Date().toISOString());
    setLastUpdated(nowLabel);

    setTimeSeries((prev) => {
      const point: TimeSeriesPoint = {
        time: nowLabel,
        normal: benignBatch,
        attack: dosBatch + ddosBatch,
        dos: dosBatch,
        ddos: ddosBatch,
        packetRate: Math.round(avgRate),
      };
      return [...prev, point].slice(-MAX_CHART_POINTS);
    });

  }, []);

  const refreshBackendHealth = useCallback(async (overrideUrl?: string) => {
    const status = await checkBackendHealth(overrideUrl);
    setHealth(status);
    if (status.online) {
      setApiError(null);
      setActiveModelName((prev) =>
        prev === 'Checking FastAPI...' || prev === 'Offline'
          ? status.isBootstrapModel
            ? 'Deterministic Bootstrap Model'
            : 'XGBoost (22F Artifact)'
          : prev
      );
    } else {
      setActiveModelName('Offline');
    }
    return status;
  }, []);

  // Poll FastAPI /health on mount and every 8 seconds
  useEffect(() => {
    refreshBackendHealth();
    const timer = setInterval(() => {
      refreshBackendHealth();
    }, 8000);
    return () => clearInterval(timer);
  }, [refreshBackendHealth]);

  // Connect to FastAPI WebSocket (/ws/live)
  const reconnectWsRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let unmounted = false;

    const connect = () => {
      if (unmounted) return;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      setWsConnected(false);
      try {
        if (ws) {
          ws.onclose = null;
          ws.close();
        }
        const token = getOperatorToken();
        ws = new WebSocket(getWsLiveUrl(), token ? ['sentinel.' + token] : []);
        ws.onopen = () => {
          if (!unmounted) {
            setWsConnected(true);
            setFlowsError(false);
            setHealth((prev) => ({ ...prev, online: true }));
            setApiError(null);
          }
        };
        ws.onmessage = (evt) => {
          try {
            const raw = JSON.parse(evt.data);
            const parsed = TelemetryBatchFrameSchema.safeParse(raw);
            if (parsed.success && parsed.data.flows.length > 0) {
              ingestFlowsIntoState(parsed.data.flows);
            }
          } catch {
            // Ignore non-JSON frames
          }
        };
        ws.onclose = () => {
          if (!unmounted) {
            setWsConnected(false);
            reconnectTimer = setTimeout(connect, 4000);
          }
        };
        ws.onerror = () => {
          ws?.close();
        };
      } catch {
        reconnectTimer = setTimeout(connect, 4000);
      }
    };

    reconnectWsRef.current = connect;
    connect();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [ingestFlowsIntoState]);

  useEffect(() => {
    if (wsConnected || streamPaused) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function syncFlows() {
      try {
        const {data} = await apiClient.get<{items: unknown[]}>('/api/v1/flows', {
          params: {limit: MAX_FLOWS}, signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        const rows = data.items.map(row => FlowRecordSchema.parse(row));
        ingestFlowsIntoState(rows);
        setFlowsError(false);
      } catch {
        if (!controller.signal.aborted) setFlowsError(true);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(syncFlows, 5000);
      }
    }
    void syncFlows();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [ingestFlowsIntoState, streamPaused, wsConnected]);

  const reconnectWebSocket = useCallback(() => {
    reconnectWsRef.current?.();
  }, []);

  // Dynamically aggregate target endpoints from real FastAPI flows
  const discoveredEndpoints: DiscoveredEndpoint[] = useMemo(() => {
    const map = new Map<string, DiscoveredEndpoint>();
    // Iterate oldest to newest so status reflects latest flow
    for (let i = flows.length - 1; i >= 0; i--) {
      const f = flows[i];
      const existing = map.get(f.dst_ip);
      const verified = f.input_representation !== 'packet_approximation';
      const isDos = verified && f.predicted_class === 'DoS';
      const isDdos = verified && f.predicted_class === 'DDoS';
      const status = !verified ? 'Unverified' : isDdos ? 'DDoS Attack' : isDos ? 'DoS Attack' : 'Normal';

      if (!existing) {
        map.set(f.dst_ip, {
          ip_address: f.dst_ip,
          total_flows_seen: 1,
          benign_flows_seen: f.predicted_class === 'Benign' ? 1 : 0,
          dos_flows_seen: isDos ? 1 : 0,
          ddos_flows_seen: isDdos ? 1 : 0,
          attack_flows_seen: isDos || isDdos ? 1 : 0,
          last_seen: f.timestamp,
          status,
          last_protocol: f.protocol,
          peak_rate_pps: f.features_22.Rate,
        });
      } else {
        existing.total_flows_seen += 1;
        if (f.predicted_class === 'Benign') existing.benign_flows_seen += 1;
        if (isDos) existing.dos_flows_seen += 1;
        if (isDdos) existing.ddos_flows_seen += 1;
        if (isDos || isDdos) existing.attack_flows_seen += 1;
        existing.last_seen = f.timestamp;
        existing.status = status;
        existing.last_protocol = f.protocol;
        existing.peak_rate_pps = Math.max(existing.peak_rate_pps, f.features_22.Rate);
      }
    }
    return Array.from(map.values()).sort(
      (a, b) => b.total_flows_seen - a.total_flows_seen
    );
  }, [flows]);

  const kpis: KpiSummary = useMemo(() => {
    const attackTotal = counters.dos + counters.ddos;
    const attackPct =
      counters.total > 0 ? Number(((attackTotal / counters.total) * 100).toFixed(1)) : 0;
    const unackedAlerts = alerts.filter((a) => !a.acknowledged).length;
    return {
      total_flows: counters.total,
      benign_count: counters.benign,
      dos_count: counters.dos,
      ddos_count: counters.ddos,
      attack_percentage: attackPct,
      current_fps: streamPaused ? 0 : counters.fps,
      active_alerts_count: unackedAlerts,
    };
  }, [counters, alerts, streamPaused]);

  const protocolSplit = useMemo(() => {
    if (flows.length === 0) return { TCP: 0, UDP: 0, ICMP: 0 };
    const total = flows.length;
    const tcp = Math.round((flows.filter((f) => f.protocol === 'TCP').length / total) * 100);
    const udp = Math.round((flows.filter((f) => f.protocol === 'UDP').length / total) * 100);
    const icmp = Math.max(0, 100 - tcp - udp);
    return { TCP: tcp, UDP: udp, ICMP: icmp };
  }, [flows]);

  const refreshAlerts = useCallback(async () => {
    try {
      const {data}=await apiClient.get('/api/v1/alerts?limit=1000');
      setAlerts(SecurityAlertSchema.array().parse(data));
      setAlertsError(false);
    } catch { setAlertsError(true); }
  },[]);
  useEffect(()=>{void refreshAlerts();const timer=setInterval(()=>void refreshAlerts(),5000);return()=>clearInterval(timer);},[refreshAlerts]);
  const handleAcknowledgeAlert = useCallback((id:string) => {
    void apiClient.patch(`/api/v1/alerts/${id}/acknowledge`).then(()=>refreshAlerts()).catch(()=>setApiError('Could not save alert acknowledgement.'));
  },[refreshAlerts]);
  const handleAcknowledgeAllAlerts = useCallback(() => {
    void Promise.all(alerts.filter(a=>!a.acknowledged).map(a=>apiClient.patch(`/api/v1/alerts/${a.id}/acknowledge`))).then(()=>refreshAlerts()).catch(()=>setApiError('Some acknowledgements failed. Please refresh and retry.'));
  },[alerts,refreshAlerts]);

  const handleFileUpload = useCallback(
    async (file: File): Promise<UploadAnalysisSummary> => {
      setApiError(null);
      try {
        const summary = await analyzeUploadedFile(file);
        void refreshAlerts();
        if (summary.flows.length > 0) {
          ingestFlowsIntoState(summary.flows);
        }
        return summary;
      } catch (err) {
        const message =
          err instanceof Error
            ? err.message
            : 'Capture upload failed. Check the server connection and try again.';
        setApiError(message);
        throw err;
      }
    },
    [ingestFlowsIntoState,refreshAlerts]
  );

  const handleResetSoc = useCallback(() => {
    seenWindowIdsRef.current.clear();
    setFlows([]);
    setAlerts([]);
    setTimeSeries([]);
    setCounters({
      total: 0,
      benign: 0,
      dos: 0,
      ddos: 0,
      fps: 0,
    });
    setLastUpdated('Cleared');
  }, []);

  return {
    wsConnected,
    health,
    refreshBackendHealth,
    reconnectWebSocket,
    activeModelName,
    apiError,
    clearApiError: () => setApiError(null),
    streamPaused,
    setStreamPaused,
    flows,
    timeSeries,
    protocolSplit,
    kpis,
    discoveredEndpoints,
    alerts,
    alertsError,
    flowsError,
    handleAcknowledgeAlert,
    handleAcknowledgeAllAlerts,
    handleFileUpload,
    handleResetSoc,
    lastUpdated,
  };
}

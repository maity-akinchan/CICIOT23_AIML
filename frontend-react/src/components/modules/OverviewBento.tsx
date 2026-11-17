import {
  ShieldCheck,
  Cpu,
  AlertTriangle,
  ShieldOff,
  Download,
  Play,
  Send,
} from 'lucide-react';
import type {
  DashboardPageId,
  DiscoveredEndpoint,
  KpiSummary,
  SecurityAlert,
  TimeSeriesPoint,
} from '../../types/telemetry';
import {
  formatFeatureValue,
  formatRelativeTime,
  getFeatureShortLabel,
} from '../../utils/plainEnglish';
import {
  AccessibleTableWrapper,
  ProgressBar,
  SmoothSplineChart,
  StatusBadge,
  SurfaceCard,
} from '../shared/ui';

interface OverviewBentoProps {
  kpis: KpiSummary;
  timeSeries: TimeSeriesPoint[];
  discoveredEndpoints: DiscoveredEndpoint[];
  alerts: SecurityAlert[];
  onAcknowledgeAlert: (id: string) => void;
  onSendTestBatch: () => void;
  onStartStream: () => void;
  onNavigate: (page: DashboardPageId) => void;
}

export function OverviewBento({
  kpis,
  timeSeries,
  discoveredEndpoints,
  alerts,
  onAcknowledgeAlert,
  onSendTestBatch,
  onStartStream,
  onNavigate,
}: OverviewBentoProps) {
  const normalRatio =
    kpis.total_flows > 0
      ? Math.max(0, Number((100 - kpis.attack_percentage).toFixed(1)))
      : 0;
  const normalEndpointsCount = discoveredEndpoints.filter(
    (d) => d.status === 'Normal'
  ).length;
  const underAttackEndpointsCount = discoveredEndpoints.length - normalEndpointsCount;

  const handleExportAlertsCsv = () => {
    const header = 'Target IP,Attack Type,Detected,Attacker IP,Confidence,Status\n';
    const rows = alerts
      .map(
        (a) =>
          `${a.dst_ip},${a.attack_type},${a.timestamp},"${a.src_ip}",${(
            a.confidence * 100
          ).toFixed(1)}%,${a.acknowledged ? 'Acknowledged' : 'Active'}`
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sentinel_attack_alerts.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      {/* 1. TOP ROW: 4 REAL-TIME FASTAPI KPI CARDS */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Normal Traffic Share */}
        <SurfaceCard className="p-5 flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <div className="w-9 h-9 rounded-lg bg-[#10B981]/10 border border-[#10B981]/20 flex items-center justify-center text-[#10B981]">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <span className="text-[11px] font-semibold text-[#10B981] tabular-nums">
              {kpis.total_flows.toLocaleString()} total flows
            </span>
          </div>
          <div className="mt-4">
            <div className="text-[11px] font-semibold tracking-wider text-[#8E8CA3] uppercase">
              Normal Traffic Share
            </div>
            <div className="text-[30px] font-bold text-[#F8FAFC] tracking-tight tabular-nums mt-0.5">
              {kpis.total_flows > 0 ? `${normalRatio}%` : '—'}
            </div>
            <ProgressBar value={normalRatio} color="emerald" className="mt-2.5" />
          </div>
        </SurfaceCard>

        {/* Card 2: Observed Target Endpoints */}
        <SurfaceCard
          onClick={() => onNavigate('flow-explorer')}
          className="p-5 flex flex-col justify-between"
        >
          <div className="flex items-start justify-between">
            <div className="w-9 h-9 rounded-lg bg-[#6366F1]/10 border border-[#6366F1]/20 flex items-center justify-center text-[#6366F1]">
              <Cpu className="w-5 h-5" />
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#1A1826] border border-[#222030] text-[#6366F1]">
              From Live Flows
            </span>
          </div>
          <div className="mt-4">
            <div className="text-[11px] font-semibold tracking-wider text-[#8E8CA3] uppercase">
              Observed Target IPs
            </div>
            <div className="text-[30px] font-bold text-[#F8FAFC] tracking-tight tabular-nums mt-0.5">
              {discoveredEndpoints.length}
            </div>
            <p className="text-[12px] font-medium text-[#8E8CA3] mt-2 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
              <span>{normalEndpointsCount} Normal</span>
              <span className="text-[#222030]">·</span>
              <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]" />
              <span>{underAttackEndpointsCount} Flagged</span>
            </p>
          </div>
        </SurfaceCard>

        {/* Card 3: DoS Detections */}
        <SurfaceCard className="p-5 flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <div className="w-9 h-9 rounded-lg bg-[#F59E0B]/10 border border-[#F59E0B]/20 flex items-center justify-center text-[#F59E0B]">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <span className="text-[11px] font-semibold text-[#F59E0B] tabular-nums">
              {kpis.total_flows > 0
                ? `${((kpis.dos_count / kpis.total_flows) * 100).toFixed(1)}% of traffic`
                : '0.0% of traffic'}
            </span>
          </div>
          <div className="mt-4">
            <div className="text-[11px] font-semibold tracking-wider text-[#8E8CA3] uppercase">
              DoS Attack Detections
            </div>
            <div className="text-[30px] font-bold text-[#F8FAFC] tracking-tight tabular-nums mt-0.5">
              {kpis.dos_count.toLocaleString()}
            </div>
            <p className="text-[12px] font-medium text-[#8E8CA3] mt-2">
              Single-source flood windows
            </p>
          </div>
        </SurfaceCard>

        {/* Card 4: DDoS Detections */}
        <SurfaceCard className="p-5 flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <div className="w-9 h-9 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/20 flex items-center justify-center text-[#EF4444]">
              <ShieldOff className="w-5 h-5" />
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#EF4444]/20 border border-[#EF4444]/40 text-[#EF4444] tracking-wider uppercase">
              {kpis.active_alerts_count} Unreviewed
            </span>
          </div>
          <div className="mt-4">
            <div className="text-[11px] font-semibold tracking-wider text-[#8E8CA3] uppercase">
              DDoS Attack Detections
            </div>
            <div className="text-[30px] font-bold text-[#F97316] tracking-tight tabular-nums mt-0.5">
              {kpis.ddos_count.toLocaleString()}
            </div>
            <p className="text-[12px] font-medium text-[#EF4444] mt-2">
              Multi-source flood windows
            </p>
          </div>
        </SurfaceCard>
      </section>

      {/* 2. MIDDLE ROW: 68% LIVE SPLINE CHART / 32% OBSERVED TARGET ENDPOINTS */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Left: Smooth Curved Spline Chart (8 cols) */}
        <SurfaceCard className="lg:col-span-8 p-6 flex flex-col justify-between">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-[17px] font-bold text-[#F8FAFC] tracking-tight">
                Live Network Activity
              </h2>
              <p className="text-[12px] text-[#8E8CA3]">
                Real-time windows classified by FastAPI (Normal vs DoS/DDoS)
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#6366F1]" />
                <span className="text-[12px] font-medium text-[#F8FAFC]">Normal Traffic</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#F97316]" />
                <span className="text-[12px] font-medium text-[#F8FAFC]">
                  Attack Traffic (DoS / DDoS)
                </span>
              </div>
            </div>
          </div>

          {timeSeries.length > 0 ? (
            <SmoothSplineChart data={timeSeries} height={220} mode="traffic" />
          ) : (
            <div className="h-[220px] rounded-xl bg-[#0D0C14] border border-dashed border-[#222030] flex flex-col items-center justify-center p-6 text-center gap-3">
              <p className="text-sm font-semibold text-[#F8FAFC]">
                No traffic windows ingested yet in this session
              </p>
              <p className="text-xs text-[#8E8CA3] max-w-md">
                Send a test batch to FastAPI <code className="text-[#6366F1]">/api/v1/ingest/windows</code>,
                stream simulated traffic, or run <code className="text-[#F8FAFC]">testSimulator.py</code>.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={onSendTestBatch}
                  className="h-9 px-4 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Send 3 Test Windows to FastAPI</span>
                </button>
                <button
                  type="button"
                  onClick={onStartStream}
                  className="h-9 px-4 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#3B3854] text-[#F8FAFC] text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <Play className="w-3.5 h-3.5 text-[#10B981] fill-current" />
                  <span>Start Continuous Stream</span>
                </button>
              </div>
            </div>
          )}
        </SurfaceCard>

        {/* Right: Dynamically Discovered Target Endpoints (4 cols) */}
        <SurfaceCard className="lg:col-span-4 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 mb-1">
              <h2 className="text-[17px] font-bold text-[#F8FAFC] tracking-tight">
                Observed Target IPs
              </h2>
              <span className="px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[11px] font-mono text-[#8E8CA3]">
                {discoveredEndpoints.length} active
              </span>
            </div>
            <p className="text-[12px] text-[#8E8CA3] mb-4">
              Destination endpoints aggregated from live FastAPI flows
            </p>

            {discoveredEndpoints.length === 0 ? (
              <div className="h-[160px] rounded-lg bg-[#0D0C14] border border-[#222030] flex items-center justify-center p-4 text-center text-xs text-[#8E8CA3]">
                Target endpoints appear automatically as FastAPI classifies flow windows.
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[210px] overflow-y-auto pr-1">
                {discoveredEndpoints.map((ep) => (
                  <div
                    key={ep.ip_address}
                    onClick={() => onNavigate('flow-explorer')}
                    className="p-3 rounded-lg bg-[#1A1826]/70 hover:bg-[#1A1826] border border-[#222030] flex items-center justify-between gap-3 cursor-pointer transition-colors"
                  >
                    <div className="min-w-0">
                      <div className="text-[13px] font-semibold font-mono text-[#F8FAFC] truncate">
                        {ep.ip_address}
                      </div>
                      <div className="text-[11px] text-[#8E8CA3] font-mono tabular-nums">
                        {ep.total_flows_seen} flows · {ep.attack_flows_seen} attacks ·{' '}
                        {ep.last_protocol}
                      </div>
                    </div>
                    <StatusBadge status={ep.status} />
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-[#222030] flex items-center justify-between text-[11px] text-[#8E8CA3]">
            <span>22-Feature Pipeline</span>
            <button
              type="button"
              onClick={() => onNavigate('flow-explorer')}
              className="text-[#6366F1] hover:text-[#F8FAFC] font-semibold transition-colors"
            >
              Inspect Flows →
            </button>
          </div>
        </SurfaceCard>
      </section>

      {/* 3. BOTTOM ROW: RECENT ATTACK ALERTS TABLE */}
      <SurfaceCard className="overflow-hidden">
        <div className="p-5 flex flex-wrap items-center justify-between gap-4 border-b border-[#222030]">
          <div>
            <h2 className="text-[17px] font-bold text-[#F8FAFC] tracking-tight">
              Recent Attack Alerts
            </h2>
            <p className="text-[12px] text-[#8E8CA3]">
              DoS and DDoS detections from FastAPI with top plain-English anomaly signals
            </p>
          </div>
          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="px-3 py-1.5 rounded-lg bg-[#1A1826] border border-[#222030] text-[12px] font-medium text-[#F8FAFC] hover:border-[#3B3854] transition-colors"
            >
              View All Alerts ({alerts.length})
            </button>
            {alerts.length > 0 && (
              <button
                type="button"
                onClick={handleExportAlertsCsv}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-[12px] font-semibold text-white shadow-sm transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV</span>
              </button>
            )}
          </div>
        </div>

        {alerts.length === 0 ? (
          <div className="p-10 text-center text-xs text-[#8E8CA3]">
            No DoS or DDoS alerts triggered yet in this session.
          </div>
        ) : (
          <AccessibleTableWrapper ariaLabel="Recent Attack Alerts">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 z-10 bg-[#100F18] text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3] border-b border-[#222030]">
                <tr>
                  <th className="py-3 px-5">Target IP</th>
                  <th className="py-3 px-4">Attack Type</th>
                  <th className="py-3 px-4">Detected</th>
                  <th className="py-3 px-4">Attacker IP</th>
                  <th className="py-3 px-4">Why This Was Flagged</th>
                  <th className="py-3 px-4">Model Confidence</th>
                  <th className="py-3 px-5 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#222030] text-[13px]">
                {alerts.slice(0, 6).map((alert) => {
                  const topReasons = alert.top_anomalies.slice(0, 2);
                  const confPct = Math.round(alert.confidence * 100);
                  return (
                    <tr
                      key={alert.id}
                      className="hover:bg-[#1A1826]/40 transition-colors"
                    >
                      <td className="py-3.5 px-5">
                        <div className="font-semibold font-mono text-[#F8FAFC]">
                          {alert.dst_ip}
                        </div>
                        <div className="text-[11px] text-[#8E8CA3] font-mono tabular-nums">
                          {alert.protocol} · {alert.model_used}
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <StatusBadge status={alert.attack_type} />
                      </td>
                      <td className="py-3.5 px-4 text-[#8E8CA3] tabular-nums whitespace-nowrap">
                        {formatRelativeTime(alert.timestamp)}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[12px] text-[#F8FAFC] tabular-nums whitespace-nowrap">
                        {alert.src_ip}
                      </td>
                      <td className="py-3.5 px-4 text-[12px] text-[#8E8CA3]">
                        {topReasons.length > 0 ? (
                          topReasons.map((anom, idx) => (
                            <span key={anom.feature}>
                              {idx > 0 && ' · '}
                              {getFeatureShortLabel(anom.feature)}:{' '}
                              <span className="text-[#F8FAFC] font-semibold font-mono tabular-nums">
                                {formatFeatureValue(anom.feature, anom.value)}
                              </span>
                            </span>
                          ))
                        ) : (
                          <span>Unusual packet burst rate</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16">
                            <ProgressBar
                              value={confPct}
                              color={alert.attack_type === 'DDoS' ? 'crimson' : 'amber'}
                            />
                          </div>
                          <span className="text-[12px] font-bold text-[#F8FAFC] font-mono tabular-nums">
                            {(alert.confidence * 100).toFixed(1)}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-5 text-right whitespace-nowrap">
                        {alert.acknowledged ? (
                          <span className="text-[11.5px] font-semibold text-[#10B981]">
                            Acknowledged
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => onAcknowledgeAlert(alert.id)}
                            className="px-2.5 py-1 rounded-md bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#8E8CA3] hover:text-[#F8FAFC] text-[11.5px] font-medium transition-colors"
                          >
                            Acknowledge
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </AccessibleTableWrapper>
        )}
      </SurfaceCard>
    </div>
  );
}

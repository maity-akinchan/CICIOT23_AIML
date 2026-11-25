import { Check, CheckCheck, ArrowRight } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { SecurityAlert } from '../../types/telemetry';
import {
  formatFeatureValue,
  formatRelativeTime,
  getFeatureLabel,
} from '../../utils/plainEnglish';
import { ProgressBar, StatusBadge, SurfaceCard } from '../shared/ui';

interface AttackAlertsPanelProps {
  alerts: SecurityAlert[];
  onAcknowledge: (id: string) => void;
  onAcknowledgeAll: () => void;
}

export function AttackAlertsPanel({
  alerts,
  onAcknowledge,
  onAcknowledgeAll,
}: AttackAlertsPanelProps) {
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'UNACK' | 'ACK' | 'ALL'>('ALL');

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (statusFilter === 'UNACK' && a.acknowledged) return false;
      if (statusFilter === 'ACK' && !a.acknowledged) return false;
      return true;
    });
  }, [alerts, severityFilter, statusFilter]);

  return (
    <div className="space-y-5">
      {/* Header & Filter Bar */}
      <SurfaceCard className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-[20px] font-bold text-[#F8FAFC] tracking-tight">
            Attack Alerts &amp; Explanations
          </h2>
          <p className="text-[13px] text-[#8E8CA3] mt-0.5">
            Review DoS and DDoS predictions and the signals behind them.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Severity Filter */}
          <div className="flex items-center bg-[#1A1826] p-1 rounded-lg border border-[#222030]">
            {(
              [
                { id: 'ALL', label: 'All Severities' },
                { id: 'CRITICAL', label: 'Critical (DDoS)' },
                { id: 'HIGH', label: 'High (DoS)' },
              ] as const
            ).map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setSeverityFilter(item.id)}
                className={`px-2.5 py-1 rounded text-[11.5px] font-semibold transition-colors ${
                  severityFilter === item.id
                    ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                    : 'text-[#8E8CA3] hover:text-[#F8FAFC] border border-transparent'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center bg-[#1A1826] p-1 rounded-lg border border-[#222030]">
            {(
              [
                { id: 'ALL', label: 'All' },
                { id: 'UNACK', label: 'Needs Review' },
                { id: 'ACK', label: 'Acknowledged' },
              ] as const
            ).map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setStatusFilter(item.id)}
                className={`px-2.5 py-1 rounded text-[11.5px] font-semibold transition-colors ${
                  statusFilter === item.id
                    ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                    : 'text-[#8E8CA3] hover:text-[#F8FAFC] border border-transparent'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          {alerts.length > 0 && (
            <button
              type="button"
              onClick={onAcknowledgeAll}
              className="h-[34px] px-3.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-[12px] font-semibold flex items-center gap-1.5 transition-colors"
            >
              <CheckCheck className="w-4 h-4" />
              <span>Acknowledge All</span>
            </button>
          )}
        </div>
      </SurfaceCard>

      {/* Alert Cards Grid */}
      {filteredAlerts.length === 0 ? (
        <SurfaceCard className="p-12 text-center">
          <p className="text-[15px] font-semibold text-[#F8FAFC]">
            No attack alerts in this view
          </p>
          <p className="text-[13px] text-[#8E8CA3] mt-1">
            Alerts appear here automatically when FastAPI classifies incoming traffic windows
            as DoS or DDoS.
          </p>
        </SurfaceCard>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {filteredAlerts.map((alert) => {
            const confPct = Math.round(alert.confidence * 100);
            const isCritical = alert.severity === 'CRITICAL';
            return (
              <SurfaceCard
                key={alert.id}
                className="p-5 flex flex-col justify-between gap-4"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10.5px] font-bold uppercase tracking-wider ${
                          isCritical
                            ? 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30'
                            : 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30'
                        }`}
                      >
                        {alert.severity}
                      </span>
                      <StatusBadge status={alert.attack_type} />
                      <span className="px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[11px] font-mono text-[#8E8CA3]">
                        {alert.protocol}
                      </span>
                    </div>
                    <span className="text-[12px] text-[#8E8CA3] tabular-nums">
                      {formatRelativeTime(alert.timestamp)}
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-2 text-xs text-slate-300">
                    {alert.input_representation === 'packet_approximation' && <span className="text-amber-300">Unverified packet prediction</span>}
                    {alert.capture_mode === 'PCAP_UPLOAD' && <span>Uploaded capture</span>}
                    {alert.capture_mode === 'PCAP_REPLAY' && <span>Capture replay</span>}
                    {alert.capture_mode === 'LIVE_INTERFACE' && <span>Live traffic</span>}
                    {alert.collector_id && <span className="break-all">{alert.collector_id}</span>}
                  </div>

                  {/* Endpoints */}
                  <div className="p-3 rounded-lg bg-[#1A1826] border border-[#222030] flex items-center justify-between gap-2 font-mono text-[13px] tabular-nums">
                    <div>
                      <div className="text-[10px] font-sans uppercase text-[#8E8CA3]">
                        Observed Source
                      </div>
                      <div className="font-semibold text-[#F97316]">{alert.src_ip}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-[#8E8CA3] shrink-0" />
                    <div className="text-right">
                      <div className="text-[10px] font-sans uppercase text-[#8E8CA3]">
                        Observed Destination
                      </div>
                      <div className="font-semibold text-[#F8FAFC]">{alert.dst_ip}</div>
                    </div>
                  </div>

                  {/* Why This Was Flagged */}
                  <div className="space-y-2">
                    <div className="text-[11.5px] font-bold uppercase tracking-wider text-[#8E8CA3]">
                      Why This Was Flagged
                    </div>
                    <div className="space-y-1.5">
                      {alert.top_anomalies.length === 0 && <p className="text-xs text-slate-400">No supporting feature signal is available for this alert.</p>}
                      {alert.top_anomalies.slice(0, 3).map((anom) => (
                        <div
                          key={anom.feature}
                          className="px-3 py-2 rounded-lg bg-[#0D0C14] border border-[#222030] flex items-center justify-between flex-wrap gap-2 text-[12.5px]"
                        >
                          <span className="font-medium text-[#F8FAFC] truncate">
                            {getFeatureLabel(anom.feature)}
                          </span>
                          <div className="flex items-center gap-2 flex-wrap font-mono tabular-nums">
                            <span className="text-[#F8FAFC] font-bold">
                              {formatFeatureValue(anom.feature, anom.value)}
                            </span>
                            <span className="text-[11px] text-slate-400">
                              {'model_contribution' in anom
                                ? `+${anom.model_contribution.toFixed(3)} log-odds vs Benign`
                                : `Benign median ${formatFeatureValue(anom.feature, anom.benign_median)}`}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Footer */}
                <div className="pt-3 border-t border-[#222030] flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-[160px]">
                    <span className="text-[11.5px] text-[#8E8CA3]">Model Confidence:</span>
                    <div className="w-20">
                      <ProgressBar
                        value={confPct}
                        color={isCritical ? 'crimson' : 'amber'}
                      />
                    </div>
                    <span className="text-[12.5px] font-bold font-mono tabular-nums text-[#F8FAFC]">
                      {(alert.confidence * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div>
                    {alert.acknowledged ? (
                      <span className="px-3 py-1.5 rounded-lg bg-[#1A1826] border border-[#222030] text-[#10B981] text-[12px] font-semibold flex items-center gap-1">
                        <Check className="w-3.5 h-3.5" />
                        <span>Acknowledged</span>
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onAcknowledge(alert.id)}
                        className="px-3 py-1.5 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#F8FAFC] text-[12px] font-semibold transition-colors"
                      >
                        Acknowledge Alert
                      </button>
                    )}
                  </div>
                </div>
              </SurfaceCard>
            );
          })}
        </div>
      )}
    </div>
  );
}

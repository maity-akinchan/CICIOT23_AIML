import { X, Download, Copy, Check } from 'lucide-react';
import { useState } from 'react';
import {
  FEATURE_NAMES_22,
  type FlowRecord,
} from '../../types/telemetry';
import {
  FEATURE_METADATA,
  formatClockTime,
  formatFeatureValue,
  getFeatureShortLabel,
} from '../../utils/plainEnglish';
import { ProgressBar, StatusBadge } from './ui';

interface FeatureDrawerProps {
  flow: FlowRecord | null;
  onClose: () => void;
}

export function FeatureDrawer({ flow, onClose }: FeatureDrawerProps) {
  const [copied, setCopied] = useState(false);

  if (!flow) return null;

  const unverified = flow.input_representation === 'packet_approximation';
  const flagged = flow.predicted_class !== 'Benign';
  const normalPct = Math.round((flow.probabilities.Benign ?? 0) * 100);
  const dosPct = Math.round((flow.probabilities.DoS ?? 0) * 100);
  const ddosPct = Math.round((flow.probabilities.DDoS ?? 0) * 100);

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(flow, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(flow, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `flow_${flow.window_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="feature-inspector w-full xl:w-[430px] shrink-0 rounded-xl bg-[#13121D] border border-[#222030] p-5 shadow-2xl flex flex-col gap-5 select-none">
      {/* Top Header */}
      <div className="space-y-2.5 border-b border-[#222030] pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                unverified ? 'bg-amber-400' : flagged ? 'bg-[#EF4444]' : 'bg-[#10B981]'
              }`}
            />
            <span className="text-[11px] font-bold text-[#6366F1] tracking-wider uppercase font-mono">
              WINDOW #{String(flow.window_id).slice(-8)}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#8E8CA3] hover:text-[#F8FAFC] hover:bg-[#1A1826] transition-colors"
            title="Close Inspector"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div>
          <h3 className="text-[18px] font-bold text-[#F8FAFC] tracking-tight font-mono tabular-nums">
            {flow.src_ip} → {flow.dst_ip}
          </h3>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            {unverified ? <span className="text-sm text-slate-300">{flow.predicted_class} · Unverified</span> : <StatusBadge status={flow.predicted_class} confidence={flow.confidence} />}
            <span className="px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[#8E8CA3] text-[11px] font-medium">
              {flow.model_used}
            </span>
            <span className="text-[11px] text-[#8E8CA3] font-mono tabular-nums ml-auto">
              {formatClockTime(flow.timestamp)}
            </span>
          </div>
        </div>
      </div>

      {unverified && <p className="subtle-note">{flow.compatibility_warning || 'Packet measurements differ from the training inputs. Scores are unverified.'}</p>}

      {/* Model scores by class */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <h4 className="text-[13px] font-semibold text-[#F8FAFC]">
            Model scores by class
          </h4>
          <span className="text-[11px] text-[#8E8CA3] font-mono tabular-nums">
            {flow.protocol} · {flow.packet_count} pkts
          </span>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <div className="p-2.5 rounded-lg bg-[#1A1826] border border-[#222030]">
            <div className="text-[11px] text-[#8E8CA3]">Normal</div>
            <div className="text-[15px] font-bold text-[#10B981] font-mono tabular-nums mt-0.5">
              {normalPct}%
            </div>
            <ProgressBar value={normalPct} color="emerald" className="mt-1.5" />
          </div>
          <div className="p-2.5 rounded-lg bg-[#1A1826] border border-[#222030]">
            <div className="text-[11px] text-[#8E8CA3]">DoS</div>
            <div className="text-[15px] font-bold text-[#F59E0B] font-mono tabular-nums mt-0.5">
              {dosPct}%
            </div>
            <ProgressBar value={dosPct} color="amber" className="mt-1.5" />
          </div>
          <div className="p-2.5 rounded-lg bg-[#1A1826] border border-[#222030]">
            <div className="text-[11px] text-[#8E8CA3]">DDoS</div>
            <div className="text-[15px] font-bold text-[#EF4444] font-mono tabular-nums mt-0.5">
              {ddosPct}%
            </div>
            <ProgressBar value={ddosPct} color="crimson" className="mt-1.5" />
          </div>
        </div>
      </div>

      {/* Section B: Why This Was Flagged */}
      <div className="space-y-2.5">
        <div>
          <h4 className="text-[14px] font-semibold text-[#F8FAFC]">Why This Was Flagged</h4>
          <p className="text-[11px] text-[#8E8CA3]">
            Signals that contributed to the model prediction or differed from the benign baseline
          </p>
        </div>

        {flow.top_anomalies.length === 0 ? (
          <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-slate-400">
            {flagged ? "No supporting feature signal is available for this prediction." : "The model classified this window as benign."}
          </div>
        ) : (
          <div className="space-y-2">
            {flow.top_anomalies.slice(0, 3).map((anom, idx) => {
              const textColor =
                idx === 0
                  ? 'text-[#EF4444]'
                  : idx === 1
                    ? 'text-[#F97316]'
                    : 'text-[#F59E0B]';
              return (
                <div
                  key={anom.feature}
                  className="bg-[#1A1826] border border-[#222030] rounded-lg p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[12.5px] font-semibold text-[#F8FAFC]">
                      {idx + 1}. {getFeatureShortLabel(anom.feature)}
                    </span>
                    <span className={`font-mono text-[12.5px] font-bold tabular-nums ${textColor}`}>
                      {formatFeatureValue(anom.feature, anom.value)}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {'model_contribution' in anom
                      ? `Pushed the model toward ${flow.predicted_class} over Benign (+${anom.model_contribution.toFixed(3)} log-odds)`
                      : `${anom.direction === 'HIGH' ? 'Above' : 'Below'} the benign median of ${formatFeatureValue(anom.feature, anom.benign_median)}`}
                  </p>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Section C: All 22 Traffic Measurements */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-[14px] font-semibold text-[#F8FAFC]">
              All 22 Traffic Measurements
            </h4>
            <p className="text-[11px] text-[#8E8CA3]">
              18 base packet metrics + 4 computed ratios used by the model
            </p>
          </div>
          <span className="px-2 py-0.5 rounded text-[11px] bg-[#1A1826] border border-[#222030] text-[#6366F1] font-mono font-bold">
            22 / 22
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 max-h-[340px] overflow-y-auto pr-1">
          {FEATURE_NAMES_22.map((key) => {
            const meta = FEATURE_METADATA[key];
            const val = flow.features_22[key] ?? 0;
            const isDerived = meta.origin === 'Derived (Python)';
            return (
              <div
                key={key}
                title={meta.explanation}
                className="bg-[#1A1826]/80 border border-[#222030] p-2.5 rounded-lg flex flex-col justify-between"
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="text-[11px] text-[#8E8CA3] truncate">
                    {meta.index}. {meta.shortLabel}
                  </span>
                  {isDerived && (
                    <span className="text-[9px] font-semibold px-1 rounded bg-[#6366F1]/15 text-[#6366F1]">
                      Ratio
                    </span>
                  )}
                </div>
                <div className="font-mono text-[13px] font-bold tabular-nums text-[#F8FAFC] mt-1">
                  {meta.format(val)}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer Actions */}
      <div className="pt-2 border-t border-[#222030] flex items-center gap-2">
        <button
          type="button"
          onClick={handleDownloadJson}
          className="flex-1 py-2 px-3 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#F8FAFC] text-[12px] font-medium flex items-center justify-center gap-1.5 transition-colors"
        >
          <Download className="w-3.5 h-3.5 text-[#8E8CA3]" />
          <span>Export JSON</span>
        </button>
        <button
          type="button"
          onClick={handleCopyJson}
          className="flex-1 py-2 px-3 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#F8FAFC] text-[12px] font-medium flex items-center justify-center gap-1.5 transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-[#10B981]" />
              <span className="text-[#10B981]">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-[#8E8CA3]" />
              <span>Copy Vector</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}

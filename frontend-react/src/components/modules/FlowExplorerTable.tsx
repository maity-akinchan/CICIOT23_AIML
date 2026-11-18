import { Search, SlidersHorizontal, Download, ChevronRight } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { FlowRecord, ProtocolType, TrafficClass } from '../../types/telemetry';
import {
  formatClockTime,
  formatFeatureValue,
  getFeatureShortLabel,
} from '../../utils/plainEnglish';
import { FeatureDrawer } from '../shared/FeatureDrawer';
import { AccessibleTableWrapper, StatusBadge, SurfaceCard } from '../shared/ui';

interface FlowExplorerTableProps {
  flows: FlowRecord[];
  globalSearch: string;
}

export function FlowExplorerTable({
  flows,
  globalSearch,
}: FlowExplorerTableProps) {
  const [ipSearch, setIpSearch] = useState('');
  const [classFilter, setClassFilter] = useState<'ALL' | TrafficClass>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<'ALL' | ProtocolType>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0);
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);

  const filtered = useMemo(() => {
    const q = (ipSearch || globalSearch).trim().toLowerCase();
    return flows.filter((f) => {
      if (classFilter !== 'ALL' && f.predicted_class !== classFilter) return false;
      if (protocolFilter !== 'ALL' && f.protocol !== protocolFilter) return false;
      if (f.confidence * 100 < minConfidence) return false;
      if (!q) return true;
      return (
        f.src_ip.toLowerCase().includes(q) ||
        f.dst_ip.toLowerCase().includes(q) ||
        f.src_mac.toLowerCase().includes(q) ||
        f.dst_mac.toLowerCase().includes(q)
      );
    });
  }, [flows, ipSearch, globalSearch, classFilter, protocolFilter, minConfidence]);

  const activeFlow = selectedFlow;

  const handleExportCsv = () => {
    const header =
      'Window ID,Timestamp,Source IP,Source MAC,Target IP,Protocol,Packet Rate (pkt/s),Average Size (B),SYN-to-ACK Ratio,Model prediction,Model score,Input verification\n';
    const rows = filtered
      .map(
        (f) =>
          `${f.window_id},${f.timestamp},${f.src_ip},${f.src_mac},${f.dst_ip},${f.protocol},${f.features_22.Rate},${f.features_22.AVG},${f.features_22.syn_ack_ratio},${f.predicted_class},${(
            f.confidence * 100
          ).toFixed(1)}%,${f.input_representation === 'packet_approximation' ? 'Unverified' : 'Dataset features'}`
      )
      .join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinel_flows_export.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col xl:flex-row items-start gap-5 w-full">
      <div className="flex-1 min-w-0 w-full space-y-5">
        {/* Multi-Faceted Search & Filter Toolbar */}
        <SurfaceCard className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-[19px] font-bold text-[#F8FAFC] tracking-tight">
                Flow Explorer &amp; 22-Feature Inspector
              </h2>
              <p className="text-[12.5px] text-[#8E8CA3]">
                Search classified FastAPI windows by IP or MAC and click any row to inspect its
                22 traffic measurements
              </p>
            </div>
            {filtered.length > 0 && (
              <button
                type="button"
                onClick={handleExportCsv}
                className="h-[36px] px-3.5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-[12px] font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Matching CSV ({filtered.length})</span>
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center pt-1">
            {/* Search Input */}
            <div className="md:col-span-4 relative">
              <Search className="w-4 h-4 text-[#8E8CA3] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={ipSearch}
                onChange={(e) => setIpSearch(e.target.value)}
                placeholder="Search src_ip, dst_ip, or MAC..."
                className="w-full h-[38px] pl-9 pr-3 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-[#F8FAFC] placeholder-[#8E8CA3] focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            {/* Prediction Dropdown */}
            <div className="md:col-span-3">
              <select
                aria-label="Filter by classification"
                value={classFilter}
                onChange={(e) => setClassFilter(e.target.value as 'ALL' | TrafficClass)}
                className="w-full h-[38px] px-3 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
              >
                <option value="ALL">Model prediction: All</option>
                <option value="Benign">Normal Traffic</option>
                <option value="DoS">DoS</option>
                <option value="DDoS">DDoS</option>
              </select>
            </div>

            {/* Protocol Dropdown */}
            <div className="md:col-span-2">
              <select
                aria-label="Filter by protocol"
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value as 'ALL' | ProtocolType)}
                className="w-full h-[38px] px-3 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
              >
                <option value="ALL">Protocol: All</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

            {/* Min Model Confidence Slider */}
            <div className="md:col-span-3 px-3 h-[38px] rounded-lg bg-[#1A1826] border border-[#222030] flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-[11.5px] text-[#8E8CA3] whitespace-nowrap">
                <SlidersHorizontal className="w-3.5 h-3.5 text-[#6366F1]" />
                <span>Min Conf:</span>
              </div>
              <input
                type="range"
                min={0}
                max={99}
                value={minConfidence}
                onChange={(e) => setMinConfidence(Number(e.target.value))}
                className="w-20 accent-[#6366F1] cursor-pointer"
              />
              <span className="font-mono text-[12px] font-bold text-[#F8FAFC] tabular-nums w-9 text-right">
                {minConfidence}%
              </span>
            </div>
          </div>
        </SurfaceCard>

        {/* Flows Data Grid */}
        <SurfaceCard className="overflow-hidden">
          {filtered.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#8E8CA3]">
              No matching flow windows found in current session.
            </div>
          ) : (
            <AccessibleTableWrapper ariaLabel="Flow Explorer Table">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 z-10 bg-[#100F18] text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3] border-b border-[#222030]">
                  <tr>
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">Source IP (MAC)</th>
                    <th className="py-3 px-4">Target IP</th>
                    <th className="py-3 px-4">Proto</th>
                    <th className="py-3 px-4">Packet Rate</th>
                    <th className="py-3 px-4">Top Flagged Signal</th>
                    <th className="py-3 px-4">Model prediction</th>
                    <th className="py-3 px-3 text-right">22F</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222030] text-[13px]">
                  {filtered.map((flow) => {
                    const isSelected = activeFlow?.window_id === flow.window_id;
                    const topAnom = flow.top_anomalies[0];
                    return (
                      <tr
                        key={flow.window_id}
                        onClick={() => setSelectedFlow(flow)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-[#1A1826]' : 'hover:bg-[#1A1826]/40'
                        }`}
                      >
                        <td className="py-3.5 px-4 font-mono text-[12px] text-[#8E8CA3] tabular-nums whitespace-nowrap">
                          {formatClockTime(flow.timestamp)}
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="font-mono text-[12.5px] font-semibold text-[#F8FAFC] tabular-nums">
                            {flow.src_ip}
                          </div>
                          {flow.src_mac && (
                            <div className="font-mono text-[11px] text-[#8E8CA3] tabular-nums">
                              {flow.src_mac}
                            </div>
                          )}
                        </td>
                        <td className="py-3.5 px-4 font-mono text-[12.5px] text-[#F8FAFC] tabular-nums">
                          {flow.dst_ip}
                          {flow.dst_port ? `:${flow.dst_port}` : ''}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[11px] font-semibold text-[#F8FAFC]">
                            {flow.protocol}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono tabular-nums text-[12.5px] font-semibold text-[#F8FAFC]">
                          {Math.round(flow.features_22.Rate).toLocaleString()} pkt/s
                        </td>
                        <td className="py-3.5 px-4 text-[12px] text-[#8E8CA3]">
                          {topAnom ? (
                            <span>
                              {getFeatureShortLabel(topAnom.feature)}:{' '}
                              <span className="text-[#F8FAFC] font-mono font-semibold">
                                {formatFeatureValue(topAnom.feature, topAnom.value)}
                              </span>
                            </span>
                          ) : (
                            <span className="text-[#10B981]">No explanation</span>
                          )}
                        </td>
                        <td className="py-3.5 px-4">
                          {flow.input_representation === 'packet_approximation' ? (
                            <span className="text-slate-300">
                              {flow.predicted_class} · {(flow.confidence * 100).toFixed(1)}%
                              <span className="block text-xs text-slate-400">Unverified</span>
                            </span>
                          ) : <StatusBadge status={flow.predicted_class} confidence={flow.confidence} />}
                        </td>
                        <td className="py-3.5 px-3 text-right">
                          <ChevronRight
                            className={`w-4 h-4 inline ${
                              isSelected ? 'text-[#6366F1]' : 'text-[#8E8CA3]'
                            }`}
                          />
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

      {/* Right Slide-Over 22-Feature Drawer */}
      <FeatureDrawer flow={activeFlow} onClose={() => setSelectedFlow(null)} />
    </div>
  );
}

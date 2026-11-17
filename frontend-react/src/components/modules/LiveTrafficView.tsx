import {
  UploadCloud,
  Pause,
  Play,
  Search,
  ChevronRight,
  CheckCircle2,
  Terminal,
  Copy,
  Check,
  Send,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import type { UploadAnalysisSummary } from '../../api/client';
import type {
  DiscoveredEndpoint,
  FlowRecord,
  TimeSeriesPoint,
  TrafficClass,
} from '../../types/telemetry';
import { formatClockTime } from '../../utils/plainEnglish';
import { FeatureDrawer } from '../shared/FeatureDrawer';
import {
  AccessibleTableWrapper,
  SmoothSplineChart,
  StatusBadge,
  SurfaceCard,
} from '../shared/ui';

interface LiveTrafficViewProps {
  flows: FlowRecord[];
  timeSeries: TimeSeriesPoint[];
  protocolSplit: { TCP: number; UDP: number; ICMP: number };
  discoveredEndpoints: DiscoveredEndpoint[];
  streamPaused: boolean;
  onTogglePause: () => void;
  onUploadFile: (file: File) => Promise<UploadAnalysisSummary>;
  onSendTestBatch: () => Promise<void>;
  globalSearch: string;
}

export function LiveTrafficView({
  flows,
  timeSeries,
  protocolSplit,
  discoveredEndpoints,
  streamPaused,
  onTogglePause,
  onUploadFile,
  onSendTestBatch,
  globalSearch,
}: LiveTrafficViewProps) {
  const [localFilter, setLocalFilter] = useState('');
  const [selectedClass, setSelectedClass] = useState<'ALL' | TrafficClass>('ALL');
  const [selectedDeviceIp, setSelectedDeviceIp] = useState<string>('ALL');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<UploadAnalysisSummary | null>(null);
  const [copiedCli, setCopiedCli] = useState(false);
  const [sendingProbe, setSendingProbe] = useState(false);

  const cliCommand = 'python testSimulator.py --batch-size 10 --delay 1.0';

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const res = await onUploadFile(file);
      setUploadResult(res);
      if (res.flows.length > 0) {
        setSelectedFlow(res.flows[0]);
      }
    } catch {
      // Error surfaced via global apiError banner
    } finally {
      setUploading(false);
    }
  };

  const handleTriggerProbe = async () => {
    setSendingProbe(true);
    try {
      await onSendTestBatch();
    } finally {
      setSendingProbe(false);
    }
  };

  const filteredFlows = useMemo(() => {
    const query = (localFilter || globalSearch).trim().toLowerCase();
    return flows.filter((f) => {
      if (selectedClass !== 'ALL' && f.predicted_class !== selectedClass) return false;
      if (selectedDeviceIp !== 'ALL' && f.dst_ip !== selectedDeviceIp) return false;
      if (!query) return true;
      return (
        f.src_ip.toLowerCase().includes(query) ||
        f.dst_ip.toLowerCase().includes(query) ||
        f.protocol.toLowerCase().includes(query) ||
        String(f.window_id).toLowerCase().includes(query)
      );
    });
  }, [flows, localFilter, globalSearch, selectedClass, selectedDeviceIp]);

  const activeFlow = selectedFlow ?? filteredFlows[0] ?? null;

  return (
    <div className="flex flex-col xl:flex-row items-start gap-5 w-full">
      {/* LEFT MAIN WORKSPACE */}
      <div className="flex-1 min-w-0 w-full space-y-5">
        {/* TOP ROW: CSV BATCH ANALYZER & PACKET RATE SPLINE */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* 1. Drag-and-Drop CSV Batch Analyzer (5 cols) */}
          <SurfaceCard className="lg:col-span-5 p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h2 className="text-[16px] font-bold text-[#F8FAFC]">
                    CSV Flow Batch Analyzer
                  </h2>
                  <p className="text-[11.5px] text-[#8E8CA3]">
                    Upload an 18-feature <code className="text-[#6366F1]">.csv</code> file to
                    classify via <code className="text-[#F8FAFC]">/api/v1/predict/batch</code>
                  </p>
                </div>
                <button
                  type="button"
                  disabled={sendingProbe}
                  onClick={handleTriggerProbe}
                  className="h-8 px-2.5 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#3B3854] text-[11px] font-semibold text-[#F8FAFC] flex items-center gap-1.5 shrink-0 transition-colors"
                >
                  <Send className="w-3 h-3 text-[#6366F1]" />
                  <span>{sendingProbe ? 'Sending...' : 'Send 3 Test Flows'}</span>
                </button>
              </div>

              <label className="relative group cursor-pointer rounded-xl bg-[#0D0C14]/90 border border-dashed border-[#3B3854] hover:border-[#6366F1] p-5 text-center flex flex-col items-center justify-center gap-2 transition-all">
                <input
                  type="file"
                  accept=".csv"
                  onChange={handleFileChange}
                  className="sr-only"
                />
                <div className="w-11 h-11 rounded-xl bg-[#2563EB]/15 border border-[#2563EB]/30 flex items-center justify-center text-[#6366F1] group-hover:scale-105 transition-transform">
                  <UploadCloud className="w-5 h-5" />
                </div>
                <div className="text-[13px] font-semibold text-[#F8FAFC]">
                  {uploading
                    ? 'Sending CSV batch to FastAPI...'
                    : 'Drop 18-feature .csv file or click to browse'}
                </div>
                <div className="text-[11px] text-[#8E8CA3]">
                  Compatible with <code className="text-[#F8FAFC]">test_sample_500.csv</code>
                </div>
              </label>
            </div>

            {uploadResult ? (
              <div className="mt-3.5 pt-3 border-t border-[#222030] flex items-center justify-between text-[12px]">
                <div className="flex items-center gap-1.5 text-[#10B981] truncate">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span className="truncate font-medium">{uploadResult.fileName}</span>
                </div>
                <div className="font-mono text-[11.5px] tabular-nums text-[#F8FAFC] shrink-0">
                  {uploadResult.processedWindows} win ·{' '}
                  <span className="text-[#10B981]">{uploadResult.benignCount} Normal</span> ·{' '}
                  <span className="text-[#F59E0B]">{uploadResult.dosCount} DoS</span> ·{' '}
                  <span className="text-[#EF4444]">{uploadResult.ddosCount} DDoS</span>
                </div>
              </div>
            ) : (
              <div className="mt-3.5 pt-3 border-t border-[#222030] flex items-center justify-between gap-2 text-[11px] text-[#8E8CA3]">
                <div className="flex items-center gap-1.5 truncate font-mono">
                  <Terminal className="w-3.5 h-3.5 text-[#6366F1] shrink-0" />
                  <span className="truncate">{cliCommand}</span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(cliCommand);
                    setCopiedCli(true);
                    setTimeout(() => setCopiedCli(false), 2000);
                  }}
                  className="px-2 py-1 rounded bg-[#1A1826] hover:bg-[#222030] text-[#F8FAFC] flex items-center gap-1 shrink-0 transition-colors"
                >
                  {copiedCli ? (
                    <Check className="w-3 h-3 text-[#10B981]" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>{copiedCli ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            )}
          </SurfaceCard>

          {/* 2. Packet Rate Spline Wave & Protocol Share (7 cols) */}
          <SurfaceCard className="lg:col-span-7 p-5 flex flex-col justify-between">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
              <div>
                <h2 className="text-[16px] font-bold text-[#F8FAFC]">
                  Packet Rate Stream{' '}
                  <span className="text-[11px] font-normal text-[#8E8CA3]">(pkt/s)</span>
                </h2>
                <p className="text-[11.5px] text-[#8E8CA3]">
                  Real-time packet speed across classified FastAPI windows
                </p>
              </div>

              <div className="flex items-center gap-3 text-[11px] bg-[#1A1826] px-3 py-1.5 rounded-lg border border-[#222030] tabular-nums">
                <span className="text-[#6366F1] font-semibold">TCP {protocolSplit.TCP}%</span>
                <span className="text-[#222030]">·</span>
                <span className="text-[#10B981] font-semibold">UDP {protocolSplit.UDP}%</span>
                <span className="text-[#222030]">·</span>
                <span className="text-[#F59E0B] font-semibold">ICMP {protocolSplit.ICMP}%</span>
              </div>
            </div>

            {timeSeries.length > 0 ? (
              <SmoothSplineChart
                data={timeSeries}
                height={175}
                primaryColor="#2563EB"
                secondaryColor="#F97316"
                mode="rate"
              />
            ) : (
              <div className="h-[175px] rounded-xl bg-[#0D0C14] border border-dashed border-[#222030] flex items-center justify-center text-xs text-[#8E8CA3]">
                Waiting for FastAPI traffic windows...
              </div>
            )}
          </SurfaceCard>
        </div>

        {/* MIDDLE FILTER & PLAYBACK STRIP */}
        <SurfaceCard className="p-3.5 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1">
            <div className="relative min-w-[210px] flex-1 max-w-xs">
              <Search className="w-4 h-4 text-[#8E8CA3] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={localFilter}
                onChange={(e) => setLocalFilter(e.target.value)}
                placeholder="Filter by IP, protocol, or window..."
                className="w-full h-[36px] pl-9 pr-3 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-[#F8FAFC] placeholder-[#8E8CA3] focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            <select
              aria-label="Filter by target IP"
              value={selectedDeviceIp}
              onChange={(e) => setSelectedDeviceIp(e.target.value)}
              className="h-[36px] px-3 rounded-lg bg-[#1A1826] border border-[#222030] text-[12.5px] text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
            >
              <option value="ALL">All Target IPs ({discoveredEndpoints.length})</option>
              {discoveredEndpoints.map((ep) => (
                <option key={ep.ip_address} value={ep.ip_address}>
                  {ep.ip_address} ({ep.total_flows_seen} flows)
                </option>
              ))}
            </select>

            <div className="flex items-center bg-[#1A1826] p-1 rounded-lg border border-[#222030] gap-1">
              {(
                [
                  { id: 'ALL', label: 'All' },
                  { id: 'Benign', label: 'Normal', dot: 'bg-[#10B981]' },
                  { id: 'DoS', label: 'DoS Attack', dot: 'bg-[#F59E0B]' },
                  { id: 'DDoS', label: 'DDoS Attack', dot: 'bg-[#EF4444]' },
                ] as const
              ).map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  onClick={() => setSelectedClass(pill.id)}
                  className={`px-2.5 py-1 rounded text-[11.5px] font-semibold flex items-center gap-1.5 transition-colors ${
                    selectedClass === pill.id
                      ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                      : 'text-[#8E8CA3] hover:text-[#F8FAFC] border border-transparent'
                  }`}
                >
                  {'dot' in pill && <span className={`w-1.5 h-1.5 rounded-full ${pill.dot}`} />}
                  <span>{pill.label}</span>
                </button>
              ))}
            </div>
          </div>

          <button
            type="button"
            onClick={onTogglePause}
            className={`h-[36px] px-3.5 rounded-lg text-[12.5px] font-semibold flex items-center gap-2 transition-colors shrink-0 ${
              streamPaused
                ? 'bg-[#F59E0B] text-[#0D0C14]'
                : 'bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#F8FAFC]'
            }`}
          >
            {streamPaused ? (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Resume Stream</span>
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5 text-[#F59E0B]" />
                <span>Pause Stream</span>
              </>
            )}
          </button>
        </SurfaceCard>

        {/* BOTTOM LIVE TRAFFIC TABLE */}
        <SurfaceCard className="overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#222030] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-sm bg-[#2563EB]" />
              <h3 className="text-[15px] font-bold text-[#F8FAFC]">Live Incoming Traffic</h3>
              <span className="px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[11px] text-[#8E8CA3] font-mono tabular-nums">
                {filteredFlows.length} windows
              </span>
            </div>
            <span className="text-[11px] text-[#8E8CA3]">
              Click any row to inspect all 22 traffic measurements
            </span>
          </div>

          {filteredFlows.length === 0 ? (
            <div className="p-12 text-center text-xs text-[#8E8CA3]">
              No classified flow windows yet. Click &ldquo;Send 3 Test Flows&rdquo;, &ldquo;Stream
              Traffic&rdquo;, or upload a <code className="text-[#F8FAFC]">.csv</code> file above.
            </div>
          ) : (
            <AccessibleTableWrapper ariaLabel="Live Incoming Network Traffic">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 z-10 bg-[#100F18] text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3] border-b border-[#222030]">
                  <tr>
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">Source IP → Target IP</th>
                    <th className="py-3 px-4">Protocol</th>
                    <th className="py-3 px-4">Packet Rate</th>
                    <th className="py-3 px-4">SYN-to-ACK Ratio</th>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-3 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#222030] text-[13px]">
                  {filteredFlows.slice(0, 50).map((flow) => {
                    const isSelected = activeFlow?.window_id === flow.window_id;
                    return (
                      <tr
                        key={flow.window_id}
                        onClick={() => setSelectedFlow(flow)}
                        className={`cursor-pointer transition-colors group ${
                          isSelected ? 'bg-[#1A1826]' : 'hover:bg-[#1A1826]/50'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono tabular-nums text-[12px] text-[#F8FAFC] whitespace-nowrap">
                          {formatClockTime(flow.timestamp)}
                        </td>
                        <td className="py-3 px-4 font-mono tabular-nums text-[12px] text-[#8E8CA3] whitespace-nowrap">
                          <span
                            className={
                              flow.predicted_class !== 'Benign'
                                ? 'text-[#F97316] font-semibold'
                                : 'text-[#F8FAFC]'
                            }
                          >
                            {flow.src_ip}
                          </span>
                          <span className="px-1.5 text-[#8E8CA3]">→</span>
                          <span className="text-[#F8FAFC]">{flow.dst_ip}</span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[#1A1826] border border-[#222030] text-[#F8FAFC]">
                            {flow.protocol}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono font-semibold tabular-nums text-[12.5px] text-[#F8FAFC] whitespace-nowrap">
                          {Math.round(flow.features_22.Rate).toLocaleString()}{' '}
                          <span className="text-[11px] font-normal text-[#8E8CA3]">pkt/s</span>
                        </td>
                        <td className="py-3 px-4 font-mono tabular-nums text-[12.5px] text-[#F8FAFC]">
                          {flow.features_22.syn_ack_ratio.toFixed(1)}×
                        </td>
                        <td className="py-3 px-4">
                          <StatusBadge
                            status={flow.predicted_class}
                            confidence={flow.confidence}
                          />
                        </td>
                        <td className="py-3 px-3 text-right">
                          <ChevronRight
                            className={`w-4 h-4 inline transition-transform ${
                              isSelected
                                ? 'text-[#6366F1] translate-x-0.5'
                                : 'text-[#8E8CA3] group-hover:text-[#F8FAFC]'
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

      {/* RIGHT 22-FEATURE INSPECTOR DRAWER */}
      <FeatureDrawer flow={activeFlow} onClose={() => setSelectedFlow(null)} />
    </div>
  );
}

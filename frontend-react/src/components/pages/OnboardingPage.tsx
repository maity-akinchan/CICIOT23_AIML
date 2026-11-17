import {
  Shield,
  Check,
  Copy,
  RefreshCw,
  ArrowRight,
  UploadCloud,
  Send,
  Terminal,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { useState } from 'react';
import type { BackendHealthStatus, UploadAnalysisSummary } from '../../api/client';
import type {
  BatchPredictionResponse,
  TimeSeriesPoint,
} from '../../types/telemetry';
import {
  CircularRingGauge,
  SmoothSplineChart,
  SurfaceCard,
} from '../shared/ui';

interface OnboardingPageProps {
  embedded?: boolean;
  health: BackendHealthStatus;
  wsConnected: boolean;
  activeModelName: string;
  apiBaseUrl: string;
  totalFlows: number;
  timeSeries: TimeSeriesPoint[];
  onRefreshHealth: () => Promise<BackendHealthStatus>;
  onSendTestIngest: (
    collectorId: string,
    count: number
  ) => Promise<BatchPredictionResponse>;
  onUploadCsv: (file: File) => Promise<UploadAnalysisSummary>;
  onCompleteOnboarding: () => void;
}

export function OnboardingPage({
  embedded = false,
  health,
  wsConnected,
  activeModelName,
  apiBaseUrl,
  totalFlows,
  timeSeries,
  onRefreshHealth,
  onSendTestIngest,
  onUploadCsv,
  onCompleteOnboarding,
}: OnboardingPageProps) {
  const [collectorId, setCollectorId] = useState('go-sensor-01');
  const [activeTab, setActiveTab] = useState<'probe' | 'cli' | 'csv'>('probe');
  const [sendingProbe, setSendingProbe] = useState(false);
  const [probeResult, setProbeResult] = useState<BatchPredictionResponse | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [uploadingCsv, setUploadingCsv] = useState(false);
  const [csvResult, setCsvResult] = useState<UploadAnalysisSummary | null>(null);

  const step1Done = health.online && health.modelLoaded;
  const step2Done = totalFlows > 0;
  const readinessPct = !step1Done ? 0 : !step2Done ? 50 : 100;

  const uvicornCmd = `cd ciciot23-sentinel/backend-fastapi && source .venv/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`;
  const simulatorCmd = `cd ciciot23-sentinel/backend-fastapi && source .venv/bin/activate && python testSimulator.py --url ${apiBaseUrl}/api/v1/predict/batch`;

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleRecheck = async () => {
    setCheckingHealth(true);
    setProbeError(null);
    try {
      await onRefreshHealth();
    } finally {
      setCheckingHealth(false);
    }
  };

  const handleRunProbe = async () => {
    setSendingProbe(true);
    setProbeError(null);
    try {
      const res = await onSendTestIngest(collectorId.trim() || 'go-sensor-01', 3);
      setProbeResult(res);
    } catch (err) {
      setProbeError(
        err instanceof Error
          ? err.message
          : 'Could not reach FastAPI. Start uvicorn on port 8000 first.'
      );
    } finally {
      setSendingProbe(false);
    }
  };

  const handleCsvChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingCsv(true);
    setProbeError(null);
    try {
      const summary = await onUploadCsv(file);
      setCsvResult(summary);
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : 'Failed to classify CSV file.');
    } finally {
      setUploadingCsv(false);
    }
  };

  const content = (
    <div className="space-y-6">
      {/* Heading */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#F8FAFC] tracking-tight">
            Connect FastAPI &amp; Verify Traffic Ingestion
          </h1>
          <p className="text-xs sm:text-sm text-[#8E8CA3] mt-1">
            Verify that your FastAPI server is online and send a real 100-packet flow batch
            through the 22-feature ML pipeline.
          </p>
        </div>

        {!embedded && (
          <button
            type="button"
            onClick={onCompleteOnboarding}
            className="h-9 px-3.5 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-xs font-semibold text-[#8E8CA3] hover:text-[#F8FAFC] flex items-center gap-1.5 self-start sm:self-center transition-colors shrink-0"
          >
            <span>Skip to Security Console</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* 2-Column Asymmetric Grid (64% Left / 36% Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* LEFT COLUMN (8 cols) */}
        <SurfaceCard className="lg:col-span-8 p-6 space-y-6">
          {/* SECTION 1: Verify FastAPI Backend */}
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                    step1Done
                      ? 'bg-[#10B981]/20 border border-[#10B981] text-[#10B981]'
                      : 'bg-[#6366F1] text-white'
                  }`}
                >
                  {step1Done ? <Check className="w-3.5 h-3.5" /> : '1'}
                </span>
                <h2 className="text-base font-bold text-[#F8FAFC]">
                  Verify FastAPI Backend &amp; WebSocket Stream
                </h2>
              </div>

              <button
                type="button"
                onClick={handleRecheck}
                disabled={checkingHealth}
                className="h-8 px-3 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-xs font-semibold text-[#F8FAFC] flex items-center gap-1.5 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin' : ''}`} />
                <span>Recheck /health</span>
              </button>
            </div>

            {/* 3 Status Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
                <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[#8E8CA3]">
                  GET /health
                </div>
                <div className="flex items-center gap-1.5 mt-1.5">
                  {health.online ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                      <span className="text-xs font-bold text-[#10B981]">
                        Online {health.latencyMs ? `(${health.latencyMs}ms)` : ''}
                      </span>
                    </>
                  ) : (
                    <>
                      <AlertCircle className="w-4 h-4 text-[#F59E0B]" />
                      <span className="text-xs font-bold text-[#F59E0B]">Offline</span>
                    </>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
                <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[#8E8CA3]">
                  ML Inference Engine
                </div>
                <div className="text-xs font-bold text-[#F8FAFC] mt-1.5 truncate">
                  {health.online ? activeModelName : 'Not Connected'}
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
                <div className="text-[10.5px] font-semibold uppercase tracking-wider text-[#8E8CA3]">
                  WS /ws/live
                </div>
                <div className="flex items-center gap-1.5 mt-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      wsConnected ? 'bg-[#10B981] animate-pulse' : 'bg-[#8E8CA3]'
                    }`}
                  />
                  <span
                    className={`text-xs font-bold ${
                      wsConnected ? 'text-[#10B981]' : 'text-[#8E8CA3]'
                    }`}
                  >
                    {wsConnected ? 'Live Stream Ready' : 'Waiting for WS'}
                  </span>
                </div>
              </div>
            </div>

            {!health.online && (
              <div className="p-4 rounded-lg bg-[#0D0C14] border border-[#F59E0B]/40 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-[#F59E0B]">
                    FastAPI is not running yet. Start it in your terminal:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('uvicorn', uvicornCmd)}
                    className="text-[#6366F1] hover:text-[#F8FAFC] font-semibold flex items-center gap-1"
                  >
                    {copiedCmd === 'uvicorn' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#10B981]" />
                        <span className="text-[#10B981]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="text-xs font-mono text-[#F8FAFC] overflow-x-auto py-1">
                  <code>{uvicornCmd}</code>
                </pre>
              </div>
            )}
          </div>

          <div className="h-[1px] bg-[#222030] w-full" />

          {/* SECTION 2: Send First Traffic Windows to FastAPI */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                    step2Done
                      ? 'bg-[#10B981]/20 border border-[#10B981] text-[#10B981]'
                      : 'bg-[#6366F1] text-white'
                  }`}
                >
                  {step2Done ? <Check className="w-3.5 h-3.5" /> : '2'}
                </span>
                <h2 className="text-base font-bold text-[#F8FAFC]">
                  Send Traffic Windows to FastAPI
                </h2>
              </div>
              {step2Done && (
                <span className="text-[11px] font-semibold text-[#10B981] bg-[#10B981]/10 px-2.5 py-0.5 rounded border border-[#10B981]/20">
                  {totalFlows} Windows Classified
                </span>
              )}
            </div>

            {/* 3 Ingestion Method Tabs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-1 bg-[#1A1826] rounded-lg border border-[#222030]">
              <button
                type="button"
                onClick={() => setActiveTab('probe')}
                className={`py-2 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                  activeTab === 'probe'
                    ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                    : 'text-[#8E8CA3] hover:text-[#F8FAFC]'
                }`}
              >
                <Send className="w-3.5 h-3.5 text-[#6366F1]" />
                <span>1-Click Ingest Probe</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('cli')}
                className={`py-2 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                  activeTab === 'cli'
                    ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                    : 'text-[#8E8CA3] hover:text-[#F8FAFC]'
                }`}
              >
                <Terminal className="w-3.5 h-3.5 text-[#10B981]" />
                <span>Run testSimulator.py</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('csv')}
                className={`py-2 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                  activeTab === 'csv'
                    ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                    : 'text-[#8E8CA3] hover:text-[#F8FAFC]'
                }`}
              >
                <UploadCloud className="w-3.5 h-3.5 text-[#38BDF8]" />
                <span>Upload .csv File</span>
              </button>
            </div>

            {/* TAB 1: 1-Click Live Ingest Probe */}
            {activeTab === 'probe' && (
              <div className="p-4 rounded-xl bg-[#0D0C14] border border-[#222030] space-y-4">
                <p className="text-xs text-[#8E8CA3]">
                  Sends a real <code className="text-[#F8FAFC]">IngestBatchRequest</code> (3
                  100-packet windows: Normal, DoS, and DDoS) directly to FastAPI{' '}
                  <code className="text-[#6366F1]">POST /api/v1/ingest/windows</code>.
                </p>

                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1">
                    <label
                      htmlFor="onboard-collector-id"
                      className="block text-[10.5px] font-semibold uppercase tracking-wider text-[#8E8CA3] mb-1"
                    >
                      Collector Identifier
                    </label>
                    <input
                      id="onboard-collector-id"
                      type="text"
                      value={collectorId}
                      onChange={(e) => setCollectorId(e.target.value)}
                      className="w-full h-10 px-3 bg-[#1A1826] border border-[#222030] rounded-lg text-xs font-mono text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
                    />
                  </div>
                  <div className="sm:self-end">
                    <button
                      type="button"
                      disabled={sendingProbe}
                      onClick={handleRunProbe}
                      className="w-full sm:w-auto h-10 px-5 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>
                        {sendingProbe
                          ? 'Sending to FastAPI...'
                          : 'Send 3 Test Windows to FastAPI'}
                      </span>
                    </button>
                  </div>
                </div>

                {probeResult && (
                  <div className="p-3 rounded-lg bg-[#10B981]/10 border border-[#10B981]/30 text-xs text-[#10B981] flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold">
                      FastAPI classified {probeResult.processed_windows} windows:
                    </span>
                    <span className="font-mono font-bold text-[#F8FAFC]">
                      Normal={probeResult.benign_count} · DoS={probeResult.dos_count} · DDoS=
                      {probeResult.ddos_count}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: Run testSimulator.py in Terminal */}
            {activeTab === 'cli' && (
              <div className="p-4 rounded-xl bg-[#0D0C14] border border-[#222030] space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#8E8CA3]">
                    Stream real rows from <code className="text-[#F8FAFC]">test_sample_500.csv</code>{' '}
                    to <code className="text-[#6366F1]">POST /api/v1/predict/batch</code>:
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopy('sim', simulatorCmd)}
                    className="text-[#6366F1] hover:text-[#F8FAFC] font-semibold flex items-center gap-1"
                  >
                    {copiedCmd === 'sim' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#10B981]" />
                        <span className="text-[#10B981]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Command</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-3 rounded-lg bg-[#13121D] border border-[#222030] text-xs font-mono text-[#F8FAFC] overflow-x-auto">
                  <code>{simulatorCmd}</code>
                </pre>
                <p className="text-[11px] text-[#8E8CA3]">
                  As <code className="text-[#F8FAFC]">testSimulator.py</code> sends batches,
                  FastAPI broadcasts predictions over <code className="text-[#10B981]">/ws/live</code>{' '}
                  and updates the Live Readiness gauge on the right automatically.
                </p>
              </div>
            )}

            {/* TAB 3: Upload .csv File */}
            {activeTab === 'csv' && (
              <div className="p-4 rounded-xl bg-[#0D0C14] border border-[#222030] space-y-3">
                <label className="cursor-pointer rounded-xl bg-[#13121D] border border-dashed border-[#3B3854] hover:border-[#6366F1] p-6 text-center flex flex-col items-center justify-center gap-2 transition-colors">
                  <input
                    type="file"
                    accept=".csv"
                    onChange={handleCsvChange}
                    className="sr-only"
                  />
                  <UploadCloud className="w-6 h-6 text-[#6366F1]" />
                  <div className="text-xs font-semibold text-[#F8FAFC]">
                    {uploadingCsv
                      ? 'Sending CSV rows to FastAPI...'
                      : 'Click to select an 18-feature .csv file (e.g. test_sample_500.csv)'}
                  </div>
                  <div className="text-[11px] text-[#8E8CA3]">
                    Posts up to 100 rows to FastAPI /api/v1/predict/batch
                  </div>
                </label>

                {csvResult && (
                  <div className="p-3 rounded-lg bg-[#10B981]/10 border border-[#10B981]/30 text-xs text-[#10B981] flex items-center justify-between">
                    <span>{csvResult.fileName} classified by FastAPI:</span>
                    <span className="font-mono font-bold text-[#F8FAFC]">
                      {csvResult.processedWindows} windows ({csvResult.benignCount} Normal,{' '}
                      {csvResult.dosCount} DoS, {csvResult.ddosCount} DDoS)
                    </span>
                  </div>
                )}
              </div>
            )}

            {probeError && (
              <div className="p-3 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/30 text-xs text-[#EF4444]">
                {probeError}
              </div>
            )}
          </div>
        </SurfaceCard>

        {/* RIGHT COLUMN (4 cols): Live Readiness Ring Gauge & Stream Preview */}
        <div className="lg:col-span-4 space-y-5">
          <SurfaceCard className="p-5 flex flex-col items-center">
            <div className="w-full flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-[#10B981]/20 border border-[#10B981] text-[#10B981] flex items-center justify-center text-[11px] font-bold">
                  3
                </span>
                <h3 className="text-sm font-bold text-[#F8FAFC]">Pipeline Readiness</h3>
              </div>
              <span
                className={`flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded border ${
                  health.online
                    ? 'text-[#10B981] bg-[#10B981]/10 border-[#10B981]/20'
                    : 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/20'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    health.online ? 'bg-[#10B981] animate-pulse' : 'bg-[#F59E0B]'
                  }`}
                />
                <span>{health.online ? 'FastAPI Online' : 'Offline'}</span>
              </span>
            </div>

            <div className="my-2">
              <CircularRingGauge
                percentage={readinessPct}
                centerTitle={
                  readinessPct === 100
                    ? 'VERIFIED'
                    : readinessPct === 50
                      ? 'READY'
                      : 'OFFLINE'
                }
                centerSubtitle={
                  readinessPct === 100
                    ? `${totalFlows} FLOWS INGESTED`
                    : readinessPct === 50
                      ? 'SEND 1ST BATCH'
                      : 'START FASTAPI'
                }
                color={readinessPct > 0 ? '#10B981' : '#F59E0B'}
                size={156}
              />
            </div>

            <div className="w-full bg-[#1A1826] border border-[#222030] rounded-lg p-3.5 mt-3 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[#8E8CA3]">FastAPI Endpoint:</span>
                <span className="font-mono text-[11px] text-[#F8FAFC] truncate max-w-[160px]">
                  {apiBaseUrl}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#8E8CA3]">Active Model:</span>
                <span className="font-semibold text-[#F8FAFC] truncate max-w-[160px]">
                  {health.online ? activeModelName : 'Unavailable'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#8E8CA3]">Flows Classified:</span>
                <span className="font-mono font-bold tabular-nums text-[#10B981]">
                  {totalFlows} windows
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={onCompleteOnboarding}
              className="w-full h-11 mt-4 bg-[#10B981] hover:bg-[#059669] text-[#0D0C14] font-bold text-xs uppercase tracking-wider rounded-lg transition-colors flex items-center justify-center gap-2 shadow-sm"
            >
              <span>Enter Security Console</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </SurfaceCard>

          {/* Live Traffic Ingest Preview */}
          <SurfaceCard className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#F8FAFC]">
                Live FastAPI Traffic Stream
              </span>
              <span className="text-[10px] font-mono text-[#10B981] bg-[#10B981]/10 px-2 py-0.5 rounded border border-[#10B981]/20">
                {totalFlows} total windows
              </span>
            </div>
            {timeSeries.length > 0 ? (
              <SmoothSplineChart data={timeSeries} height={95} mode="traffic" />
            ) : (
              <div className="h-[95px] rounded-lg bg-[#0D0C14] border border-[#222030] flex items-center justify-center text-[11px] text-[#8E8CA3]">
                Send a test batch in Step 2 to see live curve
              </div>
            )}
          </SurfaceCard>
        </div>
      </div>
    </div>
  );

  if (embedded) {
    return content;
  }

  return (
    <div className="min-h-screen bg-[#0D0C14] text-[#F8FAFC] flex flex-col justify-between">
      {/* Top Onboarding Header (56px) */}
      <header className="h-14 bg-[#100F18] border-b border-[#222030] px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#1A1826] border border-[#222030] flex items-center justify-center text-[#6366F1]">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold tracking-tight text-[#F8FAFC]">
              CICIoT23 Sentinel
            </span>
            <span className="text-xs text-[#8E8CA3] hidden sm:inline">
              — Step 3 of 3 · FastAPI Onboarding
            </span>
          </div>
        </div>

        {/* Center 3-Step Progress */}
        <div className="hidden md:flex items-center gap-3 text-xs">
          <span
            className={`font-semibold ${
              step1Done ? 'text-[#10B981]' : 'text-[#F8FAFC]'
            }`}
          >
            1. FastAPI Health
          </span>
          <span className="text-[#222030]">→</span>
          <span
            className={`font-semibold ${
              step2Done ? 'text-[#10B981]' : 'text-[#6366F1]'
            }`}
          >
            2. Ingest Traffic
          </span>
          <span className="text-[#222030]">→</span>
          <span
            className={`font-semibold ${
              readinessPct === 100 ? 'text-[#10B981]' : 'text-[#8E8CA3]'
            }`}
          >
            3. Ready
          </span>
        </div>

        <button
          type="button"
          onClick={onCompleteOnboarding}
          className="text-xs font-medium text-[#8E8CA3] hover:text-[#F8FAFC] flex items-center gap-1"
        >
          <span>Open Console</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </header>

      <main className="flex-1 w-full max-w-[1240px] mx-auto px-6 py-8">{content}</main>

      <footer className="h-8 bg-[#100F18] border-t border-[#222030] px-6 flex items-center justify-between text-[11px] font-mono text-[#8E8CA3]">
        <span>FASTAPI ENDPOINT: {apiBaseUrl}</span>
        <span>WS /ws/live: {wsConnected ? 'CONNECTED' : 'STANDBY'}</span>
      </footer>
    </div>
  );
}

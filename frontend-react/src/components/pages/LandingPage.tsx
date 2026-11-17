import {
  Shield,
  ArrowRight,
  Activity,
  Cpu,
  Layers,
  Radio,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  UserCheck,
} from 'lucide-react';
import { useState } from 'react';
import type { BackendHealthStatus } from '../../api/client';
import type { AppStage, OperatorProfile } from '../../types/telemetry';
import { SurfaceCard } from '../shared/ui';

interface LandingPageProps {
  health: BackendHealthStatus;
  wsConnected: boolean;
  activeModelName: string;
  apiBaseUrl: string;
  profile: OperatorProfile | null;
  onRefreshHealth: () => Promise<BackendHealthStatus>;
  onNavigateStage: (stage: AppStage) => void;
}

export function LandingPage({
  health,
  wsConnected,
  activeModelName,
  apiBaseUrl,
  profile,
  onRefreshHealth,
  onNavigateStage,
}: LandingPageProps) {
  const [checking, setChecking] = useState(false);

  const handleRecheck = async () => {
    setChecking(true);
    try {
      await onRefreshHealth();
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0D0C14] text-[#F8FAFC] flex flex-col justify-between">
      {/* Top Public Brand Header */}
      <header className="h-16 bg-[#100F18] border-b border-[#222030] px-6 md:px-12 flex items-center justify-between sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1]">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-[16px] tracking-tight text-[#F8FAFC]">
              CICIoT23 Sentinel
            </span>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#1A1826] border border-[#222030] text-[#8E8CA3] font-mono">
              FASTAPI v1.0
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Live FastAPI Status Pill */}
          <div
            className={`hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg border text-[12px] font-medium ${
              health.online
                ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#10B981]'
                : 'bg-[#F59E0B]/10 border-[#F59E0B]/30 text-[#F59E0B]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                health.online ? 'bg-[#10B981] animate-pulse' : 'bg-[#F59E0B]'
              }`}
            />
            <span>
              {health.online
                ? `FastAPI Online${health.latencyMs ? ` · ${health.latencyMs}ms` : ''}`
                : 'FastAPI Offline (:8000)'}
            </span>
          </div>

          {profile ? (
            <button
              type="button"
              onClick={() => onNavigateStage('console')}
              className="h-9 px-4 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <span>Open Console</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onNavigateStage('auth')}
                className="h-9 px-3.5 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-[#F8FAFC] text-xs font-semibold transition-colors"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => onNavigateStage('profile-setup')}
                className="h-9 px-4 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <span>Set Up Workspace</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-[1160px] w-full mx-auto px-6 py-12 space-y-12">
        {/* Hero Section */}
        <section className="text-center max-w-3xl mx-auto space-y-5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#6366F1]/10 border border-[#6366F1]/25 text-[#6366F1] text-xs font-semibold">
            <Radio className="w-3.5 h-3.5" />
            <span>Real-Time IoT Network Traffic Triage &amp; Explainable ML</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-[#F8FAFC] leading-tight">
            Detect DoS &amp; DDoS Floods in{' '}
            <span className="text-[#6366F1]">Plain English</span>
          </h1>

          <p className="text-sm sm:text-base text-[#8E8CA3] leading-relaxed max-w-2xl mx-auto">
            CICIoT23 Sentinel classifies 100-packet network windows through a live FastAPI
            inference engine, computing 22 traffic measurements and explaining why anomalous
            flows were flagged in real time over WebSockets.
          </p>

          {/* Primary CTAs */}
          <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
            {profile ? (
              <>
                <button
                  type="button"
                  onClick={() => onNavigateStage('console')}
                  className="h-11 px-6 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-sm font-semibold flex items-center gap-2 shadow-lg shadow-[#2563EB]/20 transition-all"
                >
                  <UserCheck className="w-4 h-4" />
                  <span>Continue as {profile.fullName}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigateStage('onboarding')}
                  className="h-11 px-5 rounded-lg bg-[#13121D] hover:bg-[#1A1826] border border-[#222030] text-[#F8FAFC] text-sm font-semibold transition-colors"
                >
                  Pipeline Onboarding
                </button>
                <button
                  type="button"
                  onClick={() => onNavigateStage('profile-setup')}
                  className="h-11 px-4 rounded-lg bg-[#13121D] hover:bg-[#1A1826] border border-[#222030] text-[#8E8CA3] hover:text-[#F8FAFC] text-sm font-medium transition-colors"
                >
                  Edit Profile
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => onNavigateStage('auth')}
                  className="h-11 px-6 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-sm font-semibold flex items-center gap-2 shadow-lg shadow-[#2563EB]/20 transition-all"
                >
                  <span>Get Started — Sign In &amp; Setup</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigateStage('profile-setup')}
                  className="h-11 px-5 rounded-lg bg-[#13121D] hover:bg-[#1A1826] border border-[#222030] text-[#F8FAFC] text-sm font-semibold transition-colors"
                >
                  Configure Operator Profile
                </button>
              </>
            )}
          </div>
        </section>

        {/* 3 Core Capabilities (Strictly matching implemented FastAPI backend) */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <SurfaceCard className="p-6 space-y-3">
            <div className="w-10 h-10 rounded-lg bg-[#6366F1]/15 border border-[#6366F1]/30 flex items-center justify-center text-[#6366F1]">
              <Activity className="w-5 h-5" />
            </div>
            <h2 className="text-base font-bold text-[#F8FAFC]">
              100-Packet Flow Classification
            </h2>
            <p className="text-xs text-[#8E8CA3] leading-relaxed">
              Ingests live collector windows (<code className="text-[#F8FAFC]">/api/v1/ingest/windows</code>) and
              CSV batches (<code className="text-[#F8FAFC]">/api/v1/predict/batch</code>) to classify traffic into{' '}
              <span className="text-[#10B981] font-medium">Normal</span>,{' '}
              <span className="text-[#F59E0B] font-medium">DoS Attack</span>, or{' '}
              <span className="text-[#EF4444] font-medium">DDoS Attack</span>.
            </p>
          </SurfaceCard>

          <SurfaceCard className="p-6 space-y-3">
            <div className="w-10 h-10 rounded-lg bg-[#10B981]/15 border border-[#10B981]/30 flex items-center justify-center text-[#10B981]">
              <Layers className="w-5 h-5" />
            </div>
            <h2 className="text-base font-bold text-[#F8FAFC]">
              22 Deterministic Traffic Signals
            </h2>
            <p className="text-xs text-[#8E8CA3] leading-relaxed">
              Combines 18 base packet header features with 4 derived ratios computed in FastAPI:
              Traffic Speed, SYN-to-ACK Ratio, Header-to-Packet Ratio, and Packet Size Variation.
            </p>
          </SurfaceCard>

          <SurfaceCard className="p-6 space-y-3">
            <div className="w-10 h-10 rounded-lg bg-[#2563EB]/15 border border-[#2563EB]/30 flex items-center justify-center text-[#38BDF8]">
              <Cpu className="w-5 h-5" />
            </div>
            <h2 className="text-base font-bold text-[#F8FAFC]">
              Why This Was Flagged (IQR Signals)
            </h2>
            <p className="text-xs text-[#8E8CA3] leading-relaxed">
              Every DoS or DDoS detection ranks the top 3 anomalous measurements against normal
              baseline medians and streams results immediately over{' '}
              <code className="text-[#F8FAFC]">WS /ws/live</code>.
            </p>
          </SurfaceCard>
        </section>

        {/* Live FastAPI Backend Status Card */}
        <SurfaceCard className="p-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-[#222030]">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-[#6366F1]">
                Live Backend Telemetry Check
              </div>
              <h3 className="text-lg font-bold text-[#F8FAFC] mt-0.5">
                FastAPI Server &amp; Inference Engine Status
              </h3>
            </div>
            <button
              type="button"
              onClick={handleRecheck}
              disabled={checking}
              className="h-9 px-3.5 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#222030] text-xs font-semibold text-[#F8FAFC] flex items-center gap-2 self-start md:self-center transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${checking ? 'animate-spin' : ''}`} />
              <span>Check /health Now</span>
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-5">
            <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
              <div className="text-[11px] text-[#8E8CA3] uppercase font-semibold">
                API Endpoint
              </div>
              <div className="text-xs font-mono font-bold text-[#F8FAFC] mt-1 truncate">
                {apiBaseUrl}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
              <div className="text-[11px] text-[#8E8CA3] uppercase font-semibold">
                GET /health
              </div>
              <div className="flex items-center gap-1.5 mt-1">
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
                    <span className="text-xs font-bold text-[#F59E0B]">Unreachable</span>
                  </>
                )}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
              <div className="text-[11px] text-[#8E8CA3] uppercase font-semibold">
                Inference Model
              </div>
              <div className="text-xs font-bold text-[#F8FAFC] mt-1 truncate">
                {health.online ? activeModelName : 'Waiting for FastAPI'}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#1A1826] border border-[#222030]">
              <div className="text-[11px] text-[#8E8CA3] uppercase font-semibold">
                WebSocket (/ws/live)
              </div>
              <div className="flex items-center gap-1.5 mt-1">
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
                  {wsConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>
            </div>
          </div>
        </SurfaceCard>
      </main>

      {/* Footer */}
      <footer className="h-10 bg-[#100F18] border-t border-[#222030] px-6 md:px-12 flex items-center justify-between text-[11px] text-[#8E8CA3] font-mono">
        <span>CICIoT23 SENTINEL · REAL-TIME TRAFFIC CLASSIFICATION</span>
        <span>FASTAPI + REACT + ZOD + AXIOS</span>
      </footer>
    </div>
  );
}

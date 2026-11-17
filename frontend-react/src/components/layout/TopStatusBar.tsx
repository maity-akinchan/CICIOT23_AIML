import { Play, Square, Upload, RotateCcw, Search, Bell, Cpu } from 'lucide-react';
import type { DashboardPageId, OperatorProfile } from '../../types/telemetry';
import { getInitials } from '../pages/ProfileSetupPage';

interface TopStatusBarProps {
  wsConnected: boolean;
  backendOnline: boolean;
  activeModelName: string;
  currentFps: number;
  isReplaying: boolean;
  onToggleReplay: () => void;
  replaySpeedFps: 5 | 15 | 30;
  onChangeReplaySpeed: (speed: 5 | 15 | 30) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onNavigateTo: (page: DashboardPageId) => void;
  onResetSoc: () => void;
  unacknowledgedAlertsCount: number;
  profile: OperatorProfile;
}

export function TopStatusBar({
  wsConnected,
  backendOnline,
  activeModelName,
  currentFps,
  isReplaying,
  onToggleReplay,
  replaySpeedFps,
  onChangeReplaySpeed,
  searchQuery,
  onSearchChange,
  onNavigateTo,
  onResetSoc,
  unacknowledgedAlertsCount,
  profile,
}: TopStatusBarProps) {
  const initials = getInitials(profile.fullName);

  return (
    <header className="sticky top-0 h-[56px] px-6 bg-[#0D0C14]/95 backdrop-blur border-b border-[#222030] flex items-center justify-between gap-4 z-20">
      {/* Left: Live FastAPI & WebSocket Status + Active Model Badge */}
      <div className="flex items-center gap-3 min-w-0">
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-[12px] font-semibold tabular-nums shrink-0 ${
            backendOnline && wsConnected
              ? 'bg-[#13121D] border-[#222030] text-[#10B981]'
              : backendOnline
                ? 'bg-[#13121D] border-[#222030] text-[#38BDF8]'
                : 'bg-[#13121D] border-[#222030] text-[#F59E0B]'
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              backendOnline && wsConnected
                ? 'bg-[#10B981] animate-pulse'
                : backendOnline
                  ? 'bg-[#38BDF8]'
                  : 'bg-[#F59E0B]'
            }`}
          />
          <span>
            {backendOnline && wsConnected
              ? 'WS LIVE'
              : backendOnline
                ? 'API ONLINE'
                : 'FASTAPI OFFLINE'}{' '}
            · {currentFps.toFixed(1)} win/s
          </span>
        </div>

        {/* Real Active Model Readout */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#13121D] border border-[#222030] text-[12px] text-[#8E8CA3] truncate">
          <Cpu className="w-3.5 h-3.5 text-[#6366F1] shrink-0" />
          <span className="truncate">
            Engine:{' '}
            <strong className="text-[#F8FAFC] font-semibold">{activeModelName}</strong>
          </span>
        </div>
      </div>

      {/* Right: Quick Actions & Dynamic Operator Profile */}
      <div className="flex items-center gap-2.5">
        {/* Global Search */}
        <div className="relative w-48 hidden md:block">
          <Search className="w-3.5 h-3.5 text-[#8E8CA3] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Filter by IP..."
            className="w-full h-[34px] pl-8 pr-3 rounded-lg bg-[#13121D] border border-[#222030] text-[12px] text-[#F8FAFC] placeholder-[#8E8CA3] focus:outline-none focus:border-[#6366F1] transition-colors"
          />
        </div>

        {/* Live FastAPI Batch Stream Control */}
        <div className="flex items-center rounded-lg bg-[#13121D] border border-[#222030] p-0.5">
          <button
            type="button"
            onClick={onToggleReplay}
            className={`h-[30px] px-2.5 rounded-md text-[12px] font-semibold flex items-center gap-1.5 transition-colors ${
              isReplaying
                ? 'bg-[#F59E0B] text-[#0D0C14]'
                : 'text-[#F8FAFC] hover:bg-[#1A1826]'
            }`}
          >
            {isReplaying ? (
              <>
                <Square className="w-3 h-3 fill-current" />
                <span>Stop Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 fill-current text-[#10B981]" />
                <span>Stream Traffic</span>
              </>
            )}
          </button>
          <select
            aria-label="Stream rate"
            value={replaySpeedFps}
            onChange={(e) => onChangeReplaySpeed(Number(e.target.value) as 5 | 15 | 30)}
            className="h-[30px] px-1.5 bg-transparent text-[11px] font-mono text-[#8E8CA3] focus:outline-none cursor-pointer border-l border-[#222030]"
          >
            <option value={5} className="bg-[#13121D]">
              Slow
            </option>
            <option value={15} className="bg-[#13121D]">
              Med
            </option>
            <option value={30} className="bg-[#13121D]">
              Fast
            </option>
          </select>
        </div>

        {/* Upload CSV shortcut */}
        <button
          type="button"
          onClick={() => onNavigateTo('live-traffic')}
          className="h-[34px] px-3 rounded-lg bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-[12px] font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <Upload className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Upload CSV</span>
        </button>

        {/* Clear Session Counters */}
        <button
          type="button"
          onClick={onResetSoc}
          title="Clear Session Flows"
          className="h-[34px] px-2.5 rounded-lg bg-[#13121D] hover:bg-[#1A1826] border border-[#222030] text-[#8E8CA3] hover:text-[#F8FAFC] text-[12px] font-medium flex items-center gap-1 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span className="hidden xl:inline">Clear</span>
        </button>

        {/* Alerts Bell */}
        <button
          type="button"
          onClick={() => onNavigateTo('alerts')}
          aria-label="View Attack Alerts"
          className="relative h-[34px] w-[34px] rounded-lg bg-[#13121D] border border-[#222030] flex items-center justify-center text-[#8E8CA3] hover:text-[#F8FAFC] hover:border-[#3B3854] transition-colors"
        >
          <Bell className="w-4 h-4" />
          {unacknowledgedAlertsCount > 0 && (
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#F97316]" />
          )}
        </button>

        {/* Dynamic Operator Profile Button -> Opens Profile Setup Page */}
        <button
          type="button"
          onClick={() => onNavigateTo('profile')}
          title="Edit Operator Profile & Workspace Settings"
          className="flex items-center gap-2 pl-2 border-l border-[#222030] hover:opacity-90 transition-opacity"
        >
          <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-[#2563EB] to-[#6366F1] flex items-center justify-center text-[11px] font-bold text-white shadow">
            {initials}
          </div>
          <div className="text-left leading-tight hidden xl:block max-w-[130px]">
            <div className="text-[12px] font-semibold text-[#F8FAFC] truncate">
              {profile.fullName}
            </div>
            <div className="text-[10px] text-[#8E8CA3] truncate">
              {profile.role} · {profile.orgName}
            </div>
          </div>
        </button>
      </div>
    </header>
  );
}

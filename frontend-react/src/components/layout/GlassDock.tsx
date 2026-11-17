import {
  Shield,
  LayoutGrid,
  Zap,
  Bell,
  Search,
  Sparkles,
  UserCog,
  Home,
} from 'lucide-react';
import type { DashboardPageId } from '../../types/telemetry';

interface GlassDockProps {
  activePage: DashboardPageId;
  onSelectPage: (page: DashboardPageId) => void;
  unacknowledgedAlertsCount: number;
  totalFlowsCount: number;
  backendOnline: boolean;
  latencyMs: number | null;
  activeModelName: string;
  lastUpdated: string;
  onGoToLanding: () => void;
}

export function GlassDock({
  activePage,
  onSelectPage,
  unacknowledgedAlertsCount,
  totalFlowsCount,
  backendOnline,
  latencyMs,
  activeModelName,
  lastUpdated,
  onGoToLanding,
}: GlassDockProps) {
  const monitoringLinks: {
    id: DashboardPageId;
    label: string;
    icon: typeof LayoutGrid;
    badge?: number;
    badgeTone?: 'amber' | 'crimson' | 'neutral';
  }[] = [
    { id: 'overview', label: 'Security Overview', icon: LayoutGrid },
    { id: 'live-traffic', label: 'Live Traffic & CSV', icon: Zap },
    {
      id: 'alerts',
      label: 'Attack Alerts',
      icon: Bell,
      badge: unacknowledgedAlertsCount > 0 ? unacknowledgedAlertsCount : undefined,
      badgeTone: 'crimson',
    },
    {
      id: 'flow-explorer',
      label: 'Flow Explorer',
      icon: Search,
      badge: totalFlowsCount > 0 ? totalFlowsCount : undefined,
      badgeTone: 'neutral',
    },
  ];

  const setupLinks: {
    id: DashboardPageId;
    label: string;
    icon: typeof Sparkles;
  }[] = [
    { id: 'onboarding', label: 'Onboarding & Ingest', icon: Sparkles },
    { id: 'profile', label: 'Operator Profile', icon: UserCog },
  ];

  const renderNavItem = (item: {
    id: DashboardPageId;
    label: string;
    icon: typeof LayoutGrid;
    badge?: number;
    badgeTone?: 'amber' | 'crimson' | 'neutral';
  }) => {
    const Icon = item.icon;
    const isActive = activePage === item.id;
    const badgeStyles =
      item.badgeTone === 'crimson'
        ? 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/30'
        : item.badgeTone === 'amber'
          ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/30'
          : 'bg-[#222030] text-[#8E8CA3]';

    return (
      <button
        key={item.id}
        type="button"
        aria-current={isActive ? 'page' : undefined}
        onClick={() => onSelectPage(item.id)}
        className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-[13px] font-medium transition-colors ${
          isActive
            ? 'bg-[#1A1826] text-[#F8FAFC] border border-[#222030] shadow-sm'
            : 'text-[#8E8CA3] hover:text-[#F8FAFC] hover:bg-[#13121D] border border-transparent'
        }`}
      >
        <div className="flex items-center gap-3 min-w-0">
          <Icon
            className={`w-4 h-4 shrink-0 ${
              isActive ? 'text-[#6366F1]' : 'text-[#8E8CA3]'
            }`}
          />
          <span className="truncate">{item.label}</span>
        </div>
        {item.badge !== undefined && (
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-semibold tabular-nums ${badgeStyles}`}
          >
            {item.badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <>
      {/* LEFT SIDEBAR (240px fixed) */}
      <aside className="fixed top-0 bottom-0 left-0 w-[240px] bg-[#100F18] border-r border-[#222030] flex flex-col justify-between select-none z-30">
        <div className="overflow-y-auto">
          {/* Brand Header */}
          <div className="h-[56px] px-5 flex items-center gap-3 border-b border-[#222030]">
            <div className="w-8 h-8 rounded-lg bg-[#6366F1] flex items-center justify-center shadow-lg shadow-[#6366F1]/20 shrink-0">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div className="overflow-hidden">
              <h1 className="text-[14.5px] font-bold tracking-tight text-[#F8FAFC] truncate">
                CICIoT23 Sentinel
              </h1>
              <p className="text-[9.5px] font-semibold tracking-wider text-[#8E8CA3] uppercase truncate">
                Network Defense SOC
              </p>
            </div>
          </div>

          {/* Navigation Sections */}
          <div className="px-3 py-4 space-y-5">
            <div>
              <div className="px-3 mb-1.5 text-[10px] font-bold tracking-wider text-[#8E8CA3] uppercase">
                Monitoring
              </div>
              <nav aria-label="Monitoring navigation" className="space-y-1">
                {monitoringLinks.map(renderNavItem)}
              </nav>
            </div>

            <div>
              <div className="px-3 mb-1.5 text-[10px] font-bold tracking-wider text-[#8E8CA3] uppercase">
                Workspace &amp; Setup
              </div>
              <nav aria-label="Workspace navigation" className="space-y-1">
                {setupLinks.map(renderNavItem)}
              </nav>
            </div>
          </div>
        </div>

        {/* Bottom Sidebar Controls */}
        <div className="p-3 border-t border-[#222030] space-y-1.5 bg-[#100F18]">
          <button
            type="button"
            onClick={onGoToLanding}
            className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-[#8E8CA3] hover:text-[#F8FAFC] hover:bg-[#13121D] text-[12.5px] font-medium transition-colors"
          >
            <span>Landing Page</span>
            <Home className="w-3.5 h-3.5" />
          </button>
        </div>
      </aside>

      {/* BOTTOM SYSTEM TELEMETRY FOOTER (32px fixed) */}
      <footer className="fixed bottom-0 left-[240px] right-0 h-[32px] px-6 bg-[#100F18] border-t border-[#222030] flex items-center justify-between text-[11px] font-semibold text-[#8E8CA3] tracking-wide select-none z-20">
        <div className="flex items-center gap-3.5 overflow-hidden">
          <span
            className={`flex items-center gap-1.5 shrink-0 ${
              backendOnline ? 'text-[#10B981]' : 'text-[#F59E0B]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-[2px] ${
                backendOnline ? 'bg-[#10B981]' : 'bg-[#F59E0B]'
              }`}
            />
            <span>{backendOnline ? 'FASTAPI ONLINE' : 'FASTAPI OFFLINE'}</span>
          </span>
          {latencyMs !== null && (
            <>
              <span className="text-[#222030]">·</span>
              <span className="tabular-nums font-mono shrink-0">
                HEALTH LATENCY: {latencyMs}MS
              </span>
            </>
          )}
          <span className="text-[#222030] hidden sm:inline">·</span>
          <span className="hidden sm:inline text-[#F8FAFC] font-mono shrink-0 truncate">
            MODEL: {activeModelName.toUpperCase()}
          </span>
        </div>

        <div className="flex items-center gap-3 tabular-nums font-mono shrink-0">
          <span>FASTAPI v1.0.0</span>
          <span className="text-[#222030]">·</span>
          <span>LAST INGEST: {lastUpdated}</span>
        </div>
      </footer>
    </>
  );
}

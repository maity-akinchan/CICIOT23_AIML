import React from 'react';
import type { DeviceHealthStatus, TimeSeriesPoint, TrafficClass } from '../../types/telemetry';
import { getPlainTrafficLabel } from '../../utils/plainEnglish';

/**
 * Fortify360 Obsidian Surface Card (#13121D, 12px radius, 1px solid #222030)
 */
export function SurfaceCard({
  children,
  className = '',
  onClick,
}: {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={`rounded-xl bg-[#13121D] border border-[#222030] ${
        onClick ? 'cursor-pointer hover:border-[#3B3854] transition-all' : ''
      } ${className}`}
    >
      {children}
    </div>
  );
}

/**
 * 8-Bar Mini Vertical Equalizer (Endpoint Management signature visual)
 */
export function MiniEqualizer({
  color = 'emerald',
  heights = [12, 16, 24, 20, 12, 24, 16, 20],
}: {
  color?: 'emerald' | 'indigo' | 'amber' | 'crimson';
  heights?: number[];
}) {
  const colorMap = {
    emerald: 'bg-[#10B981]',
    indigo: 'bg-[#6366F1]',
    amber: 'bg-[#F59E0B]',
    crimson: 'bg-[#EF4444]',
  };
  const baseClass = colorMap[color];

  return (
    <div aria-hidden="true" className="flex items-end gap-1 h-7 pb-0.5 shrink-0">
      {heights.map((h, i) => (
        <span
          key={i}
          className={`w-1 rounded-[2px] ${baseClass}`}
          style={{
            height: `${Math.min(24, Math.max(4, h))}px`,
            opacity: i % 2 === 0 ? 0.95 : 0.65,
          }}
        />
      ))}
    </div>
  );
}

/**
 * Rounded Horizontal Progress Bar (6px height, pill ends)
 */
export function ProgressBar({
  value,
  color = 'emerald',
  className = '',
}: {
  value: number;
  color?: 'emerald' | 'indigo' | 'amber' | 'crimson' | 'coral' | 'blue';
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  const fillMap = {
    emerald: 'bg-[#10B981]',
    indigo: 'bg-[#6366F1]',
    amber: 'bg-[#F59E0B]',
    crimson: 'bg-[#EF4444]',
    coral: 'bg-[#F97316]',
    blue: 'bg-[#2563EB]',
  };
  return (
    <div className={`w-full h-1.5 bg-[#1E1D2B] rounded-full overflow-hidden ${className}`}>
      <div
        className={`h-full rounded-full transition-all duration-500 ${fillMap[color]}`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

/**
 * Semantic Traffic / Device Status Badge (always pairs dot with explicit text)
 */
export function StatusBadge({
  status,
  confidence,
}: {
  status: TrafficClass | DeviceHealthStatus | 'ACTIVE' | 'RESOLVED';
  confidence?: number;
}) {
  const label =
    status === 'Benign' || status === 'DoS' || status === 'DDoS'
      ? getPlainTrafficLabel(status)
      : status;

  const pct =
    confidence !== undefined
      ? ` ${(confidence <= 1 ? confidence * 100 : confidence).toFixed(1)}%`
      : '';

  if (label === 'Unverified') {
    return <span className="text-sm text-slate-300">Unverified</span>;
  }

  if (label === 'Normal' || label === 'RESOLVED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#10B981]/15 border border-[#10B981]/30 text-[#10B981] tabular-nums whitespace-nowrap">
        <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
        <span>
          {label}
          {pct}
        </span>
      </span>
    );
  }

  if (label === 'DoS Attack') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#F59E0B]/15 border border-[#F59E0B]/40 text-[#F59E0B] tabular-nums whitespace-nowrap">
        <span className="w-1.5 h-1.5 rounded-full bg-[#F59E0B]" />
        <span>
          {label}
          {pct}
        </span>
      </span>
    );
  }

  if (label === 'Internet Blocked') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#F97316]/15 border border-[#F97316]/40 text-[#F97316] tabular-nums whitespace-nowrap">
        <span className="w-1.5 h-1.5 rounded-full bg-[#F97316]" />
        <span>Internet Blocked</span>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-[#EF4444]/15 border border-[#EF4444]/40 text-[#EF4444] tabular-nums whitespace-nowrap">
      <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-pulse" />
      <span>
        {label}
        {pct}
      </span>
    </span>
  );
}

/**
 * Thick Rounded-Cap Circular Ring Gauge (14px stroke width, DESIGN.md Section 7)
 */
export function CircularRingGauge({
  percentage,
  centerTitle,
  centerSubtitle,
  color = '#10B981',
  size = 168,
}: {
  percentage: number;
  centerTitle: string;
  centerSubtitle: string;
  color?: string;
  size?: number;
}) {
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, percentage));
  const dashOffset = circumference - (clamped / 100) * circumference;

  return (
    <div
      className="relative flex items-center justify-center select-none mx-auto"
      style={{ width: size, height: size }}
    >
      <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 160 160">
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="transparent"
          stroke="#1E1D2B"
          strokeWidth="14"
        />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="transparent"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
        <span className="text-[28px] font-bold text-[#F8FAFC] tabular-nums tracking-tight leading-none">
          {centerTitle}
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-[#8E8CA3] mt-1.5">
          {centerSubtitle}
        </span>
      </div>
    </div>
  );
}

/**
 * Smooth Cubic-Bezier Spline Wave Chart (6px rounded stroke caps, DESIGN.md Section 7)
 */
function buildSmoothBezierPath(points: { x: number; y: number }[]): string {
  if (points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x},${points[0].y}`;
  let d = `M ${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const curr = points[i];
    const next = points[i + 1];
    const ctrlX = (curr.x + next.x) / 2;
    d += ` C ${ctrlX.toFixed(1)},${curr.y.toFixed(1)} ${ctrlX.toFixed(1)},${next.y.toFixed(1)} ${next.x.toFixed(1)},${next.y.toFixed(1)}`;
  }
  return d;
}

export function SmoothSplineChart({
  data,
  height = 210,
  primaryColor = '#6366F1',
  secondaryColor = '#F97316',
  mode = 'traffic',
}: {
  data: TimeSeriesPoint[];
  height?: number;
  primaryColor?: string;
  secondaryColor?: string;
  mode?: 'traffic' | 'rate';
}) {
  const width = 720;
  const topPad = 20;
  const bottomY = height - 18;
  const usableHeight = bottomY - topPad;

  const series = data.length >= 2 ? data.slice(-20) : data;
  const maxVal = Math.max(
    10,
    ...series.map((d) =>
      mode === 'rate' ? d.packetRate : Math.max(d.normal, d.attack)
    )
  );

  const normalPts = series.map((pt, i) => {
    const x = series.length > 1 ? (i / (series.length - 1)) * width : width / 2;
    const val = mode === 'rate' ? Math.min(pt.packetRate, maxVal * 0.25) : pt.normal;
    const y = bottomY - (val / maxVal) * usableHeight;
    return { x, y };
  });

  const attackPts = series.map((pt, i) => {
    const x = series.length > 1 ? (i / (series.length - 1)) * width : width / 2;
    const val = mode === 'rate' ? pt.packetRate : pt.attack;
    const y = bottomY - (val / maxVal) * usableHeight;
    return { x, y };
  });

  const normalLine = buildSmoothBezierPath(normalPts);
  const attackLine = buildSmoothBezierPath(attackPts);

  const normalArea =
    normalPts.length > 1
      ? `${normalLine} L ${width},${bottomY} L 0,${bottomY} Z`
      : '';
  const attackArea =
    attackPts.length > 1
      ? `${attackLine} L ${width},${bottomY} L 0,${bottomY} Z`
      : '';

  const labelStep = Math.max(1, Math.floor(series.length / 5));
  const xLabels = series.filter((_, idx) => idx % labelStep === 0 || idx === series.length - 1);

  return (
    <div className="w-full select-none">
      <div className="relative w-full" style={{ height }}>
        <svg
          className="w-full h-full overflow-visible"
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id={`gradPrimary-${mode}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={primaryColor} stopOpacity="0.24" />
              <stop offset="100%" stopColor={primaryColor} stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id={`gradSecondary-${mode}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={secondaryColor} stopOpacity="0.28" />
              <stop offset="100%" stopColor={secondaryColor} stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Subtle horizontal gridlines */}
          {[0.15, 0.4, 0.65, 0.9].map((ratio, idx) => {
            const y = Math.round(topPad + usableHeight * ratio);
            return (
              <line
                key={idx}
                x1="0"
                y1={y}
                x2={width}
                y2={y}
                stroke="#222030"
                strokeWidth="1"
                strokeDasharray={idx === 3 ? '4 4' : undefined}
              />
            );
          })}

          {normalArea && <path d={normalArea} fill={`url(#gradPrimary-${mode})`} />}
          {attackArea && <path d={attackArea} fill={`url(#gradSecondary-${mode})`} />}

          {attackLine && (
            <path
              d={attackLine}
              fill="none"
              stroke={secondaryColor}
              strokeWidth="5.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {normalLine && (
            <path
              d={normalLine}
              fill="none"
              stroke={primaryColor}
              strokeWidth="5.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
        </svg>
      </div>

      <div className="flex justify-between items-center text-[11px] font-medium text-[#8E8CA3] tabular-nums pt-2.5 border-t border-[#222030]/80 mt-1">
        {xLabels.slice(0, 5).map((pt, i) => (
          <span key={i}>{pt.time}</span>
        ))}
        <span className="text-[#10B981] font-semibold flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse" />
          LIVE
        </span>
      </div>
    </div>
  );
}

/**
 * Accessible Scrollable Table Container (following modern-web-guidance `responsive-table`)
 */
export function AccessibleTableWrapper({
  ariaLabel,
  children,
  className = '',
}: {
  ariaLabel: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      tabIndex={0}
      role="region"
      aria-label={ariaLabel}
      className={`overflow-x-auto max-w-full focus:outline-none focus-visible:ring-1 focus-visible:ring-[#6366F1] rounded-lg ${className}`}
    >
      {children}
    </div>
  );
}

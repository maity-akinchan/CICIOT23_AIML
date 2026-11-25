import { useEffect, useState } from 'react';
import { Activity, Monitor, ShieldAlert } from 'lucide-react';
import { apiClient } from '../../api/client';
import { formatRelativeTime } from '../../utils/plainEnglish';

interface MonitoredDevice {
  collector_id: string;
  status: 'online' | 'offline';
  last_seen: string;
  windows_24h: number;
  dos_24h: number;
  ddos_24h: number;
  last_flagged_24h: string | null;
  coverage: {
    iface: string;
    received_at: string;
    captured: number;
    insufficient_packets: number;
    windows_emitted: number;
    kernel_drops: number;
    queue_drops: number;
    windows_dropped: number;
    http_ok: number;
    http_fail: number;
  } | null;
}

export function ConnectedDevicesPage({ onSetup }: { onSetup: () => void }) {
  const [devices, setDevices] = useState<MonitoredDevice[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const { data } = await apiClient.get<MonitoredDevice[]>('/api/v1/monitoring/devices', {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setDevices(data);
        setFailed(false);
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 5000);
      }
    }
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, []);

  if (devices === null || devices.length === 0) {
    return <section className="workspace-card space-y-3">
      {failed ? <p role="alert" className="text-red-300">Could not load connected devices.</p>
        : devices === null ? <p role="status">Loading connected devices…</p>
          : <>
              <h2 className="text-lg font-semibold">Waiting for the first device</h2>
              <p className="text-sm text-slate-400">A device appears here when its monitoring service contacts this server.</p>
              <button className="secondary-action" onClick={onSetup}>Set up monitoring</button>
            </>}
    </section>;
  }

  const online = devices.filter(device => device.status === 'online').length;
  const flagged = devices.filter(device => device.dos_24h + device.ddos_24h > 0).length;
  return <div className="space-y-5">
    {failed && <p role="alert" className="text-red-300">Could not refresh. Showing the last available report.</p>}
    <div className="grid gap-3 sm:grid-cols-3">
      {[
        { label: 'Online', value: online, Icon: Activity },
        { label: 'Offline', value: devices.length - online, Icon: Monitor },
        { label: 'Saw flagged traffic in 24h', value: flagged, Icon: ShieldAlert },
      ].map(({ label, value, Icon }) => <section key={label} className="workspace-card">
        <Icon size={18} className="mb-2 text-indigo-300" aria-hidden />
        <p className="text-sm text-slate-400">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      </section>)}
    </div>
    <p className="subtle-note">Recent activity covers live windows seen by each device in the past 24 hours. Packet predictions are unverified.</p>
    <div className="grid gap-4 xl:grid-cols-2">
      {devices.map(device => {
        const online = device.status === 'online';
        const report = device.coverage;
        const hasFlags = device.dos_24h + device.ddos_24h > 0;
        return <article key={device.collector_id} className="workspace-card space-y-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="break-all text-lg font-semibold">{device.collector_id}</h2>
              <p className="mt-1 text-sm text-slate-400">{report ? `${report.iface} · ` : ''}Last seen {formatRelativeTime(device.last_seen).toLowerCase()}</p>
            </div>
            <span className={online ? 'text-sm font-medium text-emerald-300' : 'text-sm font-medium text-slate-400'}>{online ? 'Online' : 'Offline'}</span>
          </div>
          <dl className="grid grid-cols-3 gap-2 border-y border-slate-700 py-3">
            {[
              ['Classified windows', device.windows_24h],
              ['DoS flags', device.dos_24h],
              ['DDoS flags', device.ddos_24h],
            ].map(([label, value]) => <div key={label}>
              <dt className="text-xs text-slate-400">{label}</dt>
              <dd className="mt-1 font-semibold tabular-nums">{value.toLocaleString()}</dd>
            </div>)}
          </dl>
          <p className={hasFlags ? 'text-sm text-amber-300' : 'text-sm text-slate-400'}>
            {device.last_flagged_24h
              ? `Most recent flag ${formatRelativeTime(device.last_flagged_24h).toLowerCase()}`
              : device.windows_24h ? 'No DoS or DDoS flags in the past 24 hours' : 'No live windows classified in the past 24 hours'}
          </p>
          <div className="space-y-1 text-sm text-slate-400">
            <h3 className="font-medium text-slate-200">Capture health</h3>
            {report ? <>
              <p>Last report {formatRelativeTime(report.received_at).toLowerCase()} · counts for this capture session</p>
              <p>{report.captured.toLocaleString()} packets captured · {report.insufficient_packets.toLocaleString()} in short flows</p>
              <p>{report.windows_emitted.toLocaleString()} windows emitted · {report.http_ok.toLocaleString()} accepted batches · {report.http_fail.toLocaleString()} failed batches</p>
              <p>{(report.kernel_drops + report.queue_drops).toLocaleString()} packet drops · {report.windows_dropped.toLocaleString()} window drops</p>
              {report.windows_emitted === 0 && report.insufficient_packets > 0 && <p>Inference needs at least five packets in one direction of the same flow within two seconds.</p>}
            </> : <p>Waiting for a capture health report.</p>}
          </div>
        </article>;
      })}
    </div>
  </div>;
}

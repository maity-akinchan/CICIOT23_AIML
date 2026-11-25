import { useEffect, useRef, useState } from 'react';
import { UploadCloud, ArrowRight, Check, Copy, Activity, ShieldCheck, Server } from 'lucide-react';
import { FlowRecordSchema } from '../../types/telemetry';
import { apiClient, apiErrorMessage, getApiBaseUrl, type UploadAnalysisSummary } from '../../api/client';
import type { DashboardPageId, FlowRecord, KpiSummary, TimeSeriesPoint } from '../../types/telemetry';
import { FlowExplorerTable } from '../modules/FlowExplorerTable';
import { SmoothSplineChart } from '../shared/ui';

export const pages: {id:DashboardPageId; label:string; description:string}[] = [
  {id:'overview',label:'Overview',description:'Your detection workspace at a glance.'},
  {id:'pcap-analysis',label:'PCAP analysis',description:'Upload a capture and inspect what the model sees.'},
  {id:'capture-history',label:'Analysis history',description:'Reopen previous capture analyses.'},
  {id:'live-traffic',label:'Live traffic',description:'Monitor windows arriving from your monitoring service.'},
  {id:'flow-explorer',label:'Flow explorer',description:'Search classified windows and inspect their features.'},
  {id:'alerts',label:'Attack alerts',description:'Review detections and acknowledge alerts.'},
  {id:'onboarding',label:'Monitoring service',description:'Install and connect the monitoring service.'},
  {id:'system-console',label:'System console',description:'Server connectivity and runtime information.'},
  {id:'profile',label:'Workspace settings',description:'Manage your local profile and server connection.'},
];
export function SummaryPage({kpis,onNavigate}:{kpis:KpiSummary;onNavigate:(p:DashboardPageId)=>void}) {
 return <div className="space-y-6"><div className="workspace-hero"><span className="eyebrow">CICIoT23</span><h2>From packets to predictions.</h2><p>Analyze a saved capture or connect your monitoring service. Review model predictions for eligible windows.</p><button className="primary-action" onClick={()=>onNavigate('pcap-analysis')}>Analyze a PCAP <ArrowRight size={17}/></button></div>
 <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">{[['Classified windows',kpis.total_flows],['DoS / DDoS prediction share',`${kpis.attack_percentage.toFixed(1)}%`],['Benign predictions',kpis.benign_count]].map(([label,value])=><div className="workspace-card" key={label}><p className="text-slate-400 text-sm">{label}</p><p className="text-3xl font-semibold mt-3 tabular-nums">{value}</p></div>)}</div>
 <div className="grid md:grid-cols-2 gap-4">{[{id:'pcap-analysis' as const,title:'Analyze a capture',text:'Upload a PCAP, compare class counts, and inspect probabilities.',icon:ShieldCheck},{id:'onboarding' as const,title:'Connect a service',text:'Install the monitoring service on your device.',icon:Server}].map(item=><button key={item.id} className="workspace-card text-left hover:border-indigo-400 transition-colors" onClick={()=>onNavigate(item.id)}><item.icon className="text-indigo-400 mb-4"/><h3 className="text-lg font-semibold">{item.title}</h3><p className="text-sm text-slate-400 mt-2 leading-relaxed">{item.text}</p></button>)}</div><p className="subtle-note">Packet measurements differ from the training inputs. Packet predictions are unverified and do not create alerts.</p></div>;
}
export function PcapPage({onUpload}:{onUpload:(f:File)=>Promise<UploadAnalysisSummary>}) {
 const [result,setResult]=useState<UploadAnalysisSummary|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[drag,setDrag]=useState(false);
 const input=useRef<HTMLInputElement>(null);
 async function analyze(file?:File){if(!file || busy)return;setBusy(true);setError('');setResult(null);try{setResult(await onUpload(file));}catch(e){setError(e instanceof Error?e.message:'Upload failed. Please try again.');}finally{setBusy(false);if(input.current)input.current.value='';}}
 return <div className="space-y-6"><div className="grid lg:grid-cols-[minmax(0,1fr)_280px] gap-5"><section className="workspace-card"><h2 className="text-lg font-semibold mb-2">Choose a packet capture</h2><p className="text-sm text-slate-400 mb-5">Classify the flow windows inside your file with the selected model.</p><input ref={input} type="file" accept=".pcap" className="sr-only" aria-label="Choose PCAP file" disabled={busy} onChange={e=>void analyze(e.target.files?.[0])}/><button disabled={busy} onClick={()=>input.current?.click()} onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);void analyze(e.dataTransfer.files[0]);}} className={`upload-zone ${drag?'drag-active':''}`}><UploadCloud size={34} className="text-indigo-400"/><span className="font-semibold">{busy?'Analyzing your capture…':'Drop a PCAP here or browse files'}</span><span className="text-sm text-slate-400">Classic .pcap · no fixed file-size limit</span></button>{error&&<p role="alert" className="mt-4 text-red-300 text-sm">{error}</p>}<div aria-live="polite" className="mt-4 text-sm text-slate-400">{busy?'Extracting features and classifying windows. Keep this page open.':result?`Analysis complete: ${result.fileName}`:'Your capture is used for inference. No retraining is required.'}</div></section><aside className="workspace-card space-y-4"><span className="eyebrow">Before you upload</span><p className="text-sm text-slate-300 leading-relaxed">Use classic Ethernet captures with IPv4 TCP, UDP, or ICMP traffic. Other packets are skipped.</p><p className="text-sm text-slate-400 leading-relaxed">A file can contain several classes. Results show unverified model predictions for individual windows.</p><p className="subtle-note">PCAPNG and truncated packets are not supported by upload. Large files take longer and require available server disk space.</p></aside></div>
 {result&&<section className="space-y-4"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-xl font-semibold break-all">Results · {result.fileName}</h2><span className="text-sm text-slate-400">{result.processedWindows} windows processed{result.coverage && ` · ${result.coverage.packets} packets read · ${result.coverage.insufficient_packets} packets in short windows · ${result.coverage.skipped_packets} unsupported packets skipped`}</span></div><div className="grid grid-cols-1 sm:grid-cols-3 gap-4">{[['Benign',result.benignCount,'text-emerald-400'],['DoS',result.dosCount,'text-amber-400'],['DDoS',result.ddosCount,'text-red-400']].map(([name,count,color])=><div className="workspace-card" key={name}><p className={`font-medium ${color}`}>{name}</p><p className="text-3xl mt-2 tabular-nums">{count}</p></div>)}</div>{result.processedWindows===0?<p className="workspace-card">No eligible windows were found. Each flow window needs at least five supported packets.</p>:<SessionFlows session={result.captureSessionId!} total={result.processedWindows}/>}</section>}</div>;
}
interface CaptureReport {
  collector_id: string;
  iface: string;
  received_at: string;
  captured: number;
  insufficient_packets: number;
  windows_emitted: number;
  kernel_drops: number;
  queue_drops: number;
  windows_dropped: number;
  http_fail: number;
}

function CoveragePanel() {
  const [reports, setReports] = useState<CaptureReport[]>([]);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const response = await apiClient.get<CaptureReport[]>('/api/v1/capture/coverage', {signal: controller.signal});
        if (!controller.signal.aborted) { setReports(response.data); setFailed(false); }
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 10000);
      }
    }
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, []);
  return <section className="workspace-card space-y-3">
    <h2 className="text-lg font-semibold">Live capture coverage</h2>
    {failed && <p role="alert">Capture reports could not be refreshed.</p>}
    {!reports.length && !failed && <p>Waiting for the monitoring service’s first capture report.</p>}
    {reports.map(r => <div key={r.collector_id} className="space-y-1">
      <h3>{r.collector_id} · {r.iface}</h3>
      <p>Last report {new Date(r.received_at).toLocaleString()}</p>
      <p>{r.captured.toLocaleString()} packets captured · {r.insufficient_packets.toLocaleString()} packets in short windows · {r.windows_emitted.toLocaleString()} windows emitted</p>
      <p>Kernel drops {r.kernel_drops} · Packet queue drops {r.queue_drops} · Window drops {r.windows_dropped} · Failed batches {r.http_fail}</p>
    </div>)}
  </section>;
}
export function TrafficPage({flows,timeSeries,search}:{flows:FlowRecord[];timeSeries:TimeSeriesPoint[];search:string}){const live=flows.filter(f=>f.capture_mode==='LIVE_INTERFACE'||f.capture_mode==='PCAP_REPLAY');return <div className="space-y-5"><CoveragePanel/><section className="workspace-card"><div className="flex items-center gap-3 mb-5"><Activity className="text-indigo-400"/><div><h2 className="text-lg font-semibold">Incoming traffic</h2><p className="text-sm text-slate-400">The chart includes recent workspace observations. The table shows service traffic.</p></div></div>{timeSeries.length?<SmoothSplineChart data={timeSeries} height={220} primaryColor="#6366F1" secondaryColor="#f97316" mode="rate"/>:<p className="py-12 text-center text-slate-400">Waiting for classified traffic. Start your monitoring service to see activity.</p>}</section><FlowExplorerTable flows={live} globalSearch={search}/></div>;}
export function ServiceSetupPage(){
 const [name,setName]=useState('sentinel-sensor'),[iface,setIface]=useState('eth0'),[copied,setCopied]=useState(false),[copiedLocal,setCopiedLocal]=useState(false);
 const base=getApiBaseUrl();
 const sensorId=(name.trim()||'sentinel-sensor').replace(/[^A-Za-z0-9_-]/g,'-');
 const ifaceClean=(iface.trim()||'eth0').replace(/[^A-Za-z0-9_.:-]/g,'');
 const command=`curl -fsSL '${base}/api/v1/install.sh' -o /tmp/sentinel-install.sh && sudo bash /tmp/sentinel-install.sh '${base}' '${ifaceClean}' '${sensorId}'`;
 const localCommand=`sudo ./collector-go/collector --mode live --iface ${ifaceClean} --collector-id ${sensorId} --api-url ${base}/api/v1/ingest/windows`;
 return <div className="space-y-5 max-w-3xl"><section className="workspace-card space-y-5"><h2 className="text-xl font-semibold">Run the monitoring service</h2><p className="text-slate-400">Anyone can run the collector service without any access token. Choose your network interface and sensor name, then run either command below.</p><div className="grid sm:grid-cols-2 gap-4"><label className="block text-sm">Device / Sensor ID<input className="workspace-input mt-2" placeholder="office-device" value={name} onChange={e=>setName(e.target.value)} maxLength={64}/></label><label className="block text-sm">Network interface<input className="workspace-input mt-2" placeholder="eth0" value={iface} onChange={e=>setIface(e.target.value)} maxLength={32}/></label></div><div className="space-y-2"><p className="text-sm text-slate-300 font-medium">Option 1: Run directly from repository checkout</p><div className="command-box"><code>{localCommand}</code><button aria-label="Copy direct command" onClick={()=>void navigator.clipboard.writeText(localCommand).then(()=>setCopiedLocal(true))}>{copiedLocal?<Check size={18}/>:<Copy size={18}/>}</button></div></div><div className="space-y-2"><p className="text-sm text-slate-300 font-medium">Option 2: Install as a background systemd service</p><div className="command-box"><code>{command}</code><button aria-label="Copy installation command" onClick={()=>void navigator.clipboard.writeText(command).then(()=>setCopied(true))}>{copied?<Check size={18}/>:<Copy size={18}/>}</button></div></div><p className="subtle-note">No operator token or enrollment code is required. The service immediately streams packet windows to {base}.</p></section></div>;
}

interface SavedCapture {id:string;filename:string;uploaded_at:string;processed_windows:number;benign_count:number;dos_count:number;ddos_count:number;artifact_sha256:string;}
export function CaptureHistoryPage(){
 const [items,setItems]=useState<SavedCapture[]>([]),[total,setTotal]=useState(0),[offset,setOffset]=useState(0),[,setFlows]=useState<FlowRecord[]>([]),[selected,setSelected]=useState<SavedCapture|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let active=true;apiClient.get('/api/v1/captures',{params:{limit:25,offset}}).then(r=>{if(active){setItems(r.data.items);setTotal(r.data.total);}}).catch(()=>setError('Could not load analysis history.'));return()=>{active=false;};},[offset]);
 async function open(c:SavedCapture){setBusy(true);setError('');setSelected(c);setFlows([]);try{const all:FlowRecord[]=[];for(let start=0;start<Math.min(c.processed_windows,1000);start+=1000){const r=await apiClient.get('/api/v1/flows',{params:{capture_session_id:c.id,limit:1000,offset:start}});all.push(...r.data.items.map((f:unknown)=>FlowRecordSchema.parse(f)));}setFlows(all);}catch{setError('Could not load the selected analysis.');}finally{setBusy(false);}}
 return <div className="space-y-5">{error&&<p role="alert" className="text-red-300">{error}</p>}<section className="workspace-card space-y-4">{items.length===0?<p className="text-slate-400">No saved analyses. Upload a capture to get started.</p>:items.map(c=><button key={c.id} className="block w-full text-left border-b border-slate-700 pb-4" onClick={()=>void open(c)} disabled={busy}><span className="font-semibold break-all">{c.filename}</span><span className="block text-sm text-slate-400 mt-2">{new Date(c.uploaded_at+'Z').toLocaleString()} · {c.processed_windows} windows · Benign {c.benign_count} / DoS {c.dos_count} / DDoS {c.ddos_count}</span></button>)}<div className="flex flex-wrap items-center gap-4"><button className="secondary-action" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button><span className="text-sm text-slate-400">{total} analyses</span><button className="secondary-action" disabled={offset+25>=total} onClick={()=>setOffset(offset+25)}>Next</button></div></section>{busy?<p role="status">Loading analysis…</p>:selected&&<section className="space-y-4"><h2 className="text-xl font-semibold break-all">{selected.filename}</h2><SessionFlows session={selected.id} total={selected.processed_windows}/></section>}</div>;
}
function SessionFlows({session,total}:{session:string;total:number}) {
 const [offset,setOffset]=useState(0),[rows,setRows]=useState<FlowRecord[]>([]),[error,setError]=useState('');
 useEffect(()=>{setOffset(0);},[session]);
 useEffect(()=>{let active=true;setRows([]);apiClient.get('/api/v1/flows',{params:{capture_session_id:session,limit:100,offset}}).then(r=>{if(active)setRows(r.data.items.map((v:unknown)=>FlowRecordSchema.parse(v)));}).catch(e=>{if(active)setError(apiErrorMessage(e));});return()=>{active=false;};},[session,offset]);
 return <div className="space-y-4">{error&&<p role="alert">{error}</p>}<div className="flex flex-wrap gap-3 items-center"><button className="secondary-action" disabled={!offset} onClick={()=>setOffset(offset-100)}>Previous windows</button><span>{offset+1}–{Math.min(offset+100,total)} of {total}</span><button className="secondary-action" disabled={offset+100>=total} onClick={()=>setOffset(offset+100)}>Next windows</button></div><FlowExplorerTable key={`${session}-${offset}`} flows={rows} globalSearch=""/></div>;
}

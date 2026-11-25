import { ConnectedDevicesPage } from './components/workspace/ConnectedDevicesPage';
import { WorkspaceNavigation } from './components/layout/WorkspaceNavigation';
import { pages, SummaryPage, CaptureHistoryPage, PcapPage, TrafficPage, ServiceSetupPage } from './components/workspace/WorkspacePages';
import { AlertCircle, X } from 'lucide-react';
import { useState } from 'react';
import { getApiBaseUrl, setApiBaseUrl } from './api/client';
import { AttackAlertsPanel } from './components/modules/AttackAlertsPanel';
import { FlowExplorerTable } from './components/modules/FlowExplorerTable';
import { AuthPage } from './components/pages/AuthPage';
import { LandingPage } from './components/pages/LandingPage';
import { ProfileSetupPage } from './components/pages/ProfileSetupPage';
import { useLiveTelemetry } from './hooks/useLiveTelemetry';
import {
  OperatorProfileSchema,
  type AppStage,
  type DashboardPageId,
  type OperatorProfile,
} from './types/telemetry';

const PROFILE_STORAGE_KEY = 'sentinel_operator_profile';

function loadSavedProfile(): OperatorProfile | null {
  try {
    const raw = window.localStorage.getItem(PROFILE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = OperatorProfileSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export function App() {
  const [profile, setProfile] = useState<OperatorProfile | null>(loadSavedProfile);
  const [stage, setStage] = useState<AppStage>('landing');
  const [activePage, setActivePage] = useState<DashboardPageId>('overview');
  const [searchQuery, setSearchQuery] = useState('');

  // Draft values passed from AuthPage -> ProfileSetupPage
  const [draftAuth, setDraftAuth] = useState<{ email: string; orgName?: string }>({
    email: '',
    orgName: '',
  });

  const telemetry = useLiveTelemetry();

  const handleSaveProfile = (nextProfile: OperatorProfile, fromConsole = false) => {
    setApiBaseUrl(nextProfile.apiBaseUrl);
    window.localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(nextProfile));
    setProfile(nextProfile);
    telemetry.refreshBackendHealth(nextProfile.apiBaseUrl);
    telemetry.reconnectWebSocket();

    if (!fromConsole) {
      setStage(nextProfile.onboardingCompleted ? 'console' : 'onboarding');
    }
  };

  const handleCompleteOnboarding = () => {
    if (profile) {
      const updated = { ...profile, onboardingCompleted: true };
      window.localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(updated));
      setProfile(updated);
    }
    setActivePage('overview');
    setStage('console');
  };

  const handleSignOut = () => {
    window.localStorage.removeItem(PROFILE_STORAGE_KEY);
    window.sessionStorage.removeItem('sentinel_operator_token');
    setProfile(null);
    setStage('landing');
  };

  // Stage 1: Landing Page
  if (stage === 'landing') {
    return (
      <LandingPage
        health={telemetry.health}
        wsConnected={telemetry.wsConnected}
        activeModelName={telemetry.activeModelName}
        apiBaseUrl={profile?.apiBaseUrl || getApiBaseUrl()}
        profile={profile}
        onRefreshHealth={telemetry.refreshBackendHealth}
        onNavigateStage={setStage}
      />
    );
  }

  // Stage 2: Authentication Page
  if (stage === 'auth') {
    return (
      <AuthPage
        initialEmail={profile?.email || draftAuth.email}
        initialOrgName={profile?.orgName || draftAuth.orgName}
        onAuthSuccess={({ email, orgName }) => {
          telemetry.reconnectWebSocket();
          setDraftAuth({ email, orgName });
          if (profile) {
            setStage(profile.onboardingCompleted ? 'console' : 'onboarding');
          } else {
            setStage('profile-setup');
          }
        }}
        onNavigateStage={setStage}
      />
    );
  }

  // Stage 3: Operator & Workspace Profile Setup Page
  if (stage === 'profile-setup') {
    return (
      <ProfileSetupPage
        initialProfile={{
          fullName: profile?.fullName || '',
          role: profile?.role || 'Security Analyst',
          orgName: profile?.orgName || draftAuth.orgName || '',
          email: profile?.email || draftAuth.email || '',
          apiBaseUrl: profile?.apiBaseUrl || getApiBaseUrl(),
          batchSize: profile?.batchSize ?? 5,
          onboardingCompleted: profile?.onboardingCompleted ?? false,
        }}
        onSaveProfile={(saved) => handleSaveProfile(saved, false)}
        onNavigateStage={setStage}
      />
    );
  }

  // Stage 4: FastAPI Pipeline Onboarding Page
  if (stage === 'onboarding') {
    return <div className="max-w-6xl mx-auto p-5 sm:p-10 space-y-6"><div className="flex flex-wrap justify-between items-center gap-4"><div><p className="eyebrow">Workspace ready</p><h1 className="text-2xl font-semibold mt-2">Install the monitoring service</h1></div><button className="primary-action" onClick={handleCompleteOnboarding}>Continue to workspace</button></div><p className="subtle-note">You can finish service setup later from the workspace.</p><ServiceSetupPage/></div>;
  }

  // Ensure a profile exists before rendering the console
  const activeProfile: OperatorProfile = profile ?? {
    fullName: 'Operator',
    role: 'Security Analyst',
    orgName: 'Sentinel Workspace',
    email: draftAuth.email || 'operator@sentinel.local',
    apiBaseUrl: getApiBaseUrl(),
    batchSize: 5,
    onboardingCompleted: true,
  };

  // Stage 5: Security Console (Only FastAPI-backed pages)
  return (
    <div className="min-h-screen bg-[#0D0C14] text-[#F8FAFC]">
      <WorkspaceNavigation active={activePage} onNavigate={setActivePage} onHome={()=>setStage('landing')}/>
      <div className="workspace-main">
        <header className="workspace-topbar"><span className="text-sm text-slate-400">Detection workspace <span className="mx-2 text-slate-600">/</span><span className="text-slate-200">{pages.find(p=>p.id===activePage)?.label}</span></span>{activePage!=='onboarding'&&<button className="secondary-action" onClick={()=>setActivePage('pcap-analysis')}>Upload PCAP</button>}</header>
        <main className="workspace-content space-y-6">
          <div><p className="eyebrow mb-2">Network analysis</p><h1 className="text-2xl sm:text-3xl font-semibold tracking-tight">{pages.find(p=>p.id===activePage)?.label}</h1><p className="text-sm sm:text-base text-slate-400 mt-2">{pages.find(p=>p.id===activePage)?.description}</p></div>
          {/* Connection errors */}
          {telemetry.apiError && (
            <div className="p-3.5 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444] text-xs flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{telemetry.apiError}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => setActivePage('onboarding')}
                  className="px-2.5 py-1 rounded bg-[#1A1826] border border-[#222030] text-[#F8FAFC] font-semibold hover:border-[#3B3854]"
                >
                  Open Onboarding
                </button>
                <button
                  type="button"
                  onClick={telemetry.clearApiError}
                  aria-label="Dismiss error"
                  className="p-1 rounded hover:bg-[#EF4444]/20"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {activePage === 'capture-history' && <CaptureHistoryPage/>}
          {activePage === 'overview' && <SummaryPage kpis={telemetry.kpis} onNavigate={setActivePage}/>}
          {activePage === 'pcap-analysis' && <PcapPage onUpload={telemetry.handleFileUpload}/>}
          {['live-traffic','flow-explorer'].includes(activePage)&&<label className="block text-sm text-slate-400">Search windows<input className="workspace-input mt-2" value={searchQuery} onChange={e=>setSearchQuery(e.target.value)} placeholder="Search by IP, protocol or window"/></label>}
          {activePage === 'live-traffic' && <TrafficPage flows={telemetry.flows} timeSeries={telemetry.timeSeries} search={searchQuery}/>}
          {activePage === 'alerts' && telemetry.alertsError && <p role="alert" className="text-red-300">Could not refresh attack alerts.</p>}
          {activePage === 'connected-devices' && <ConnectedDevicesPage onSetup={() => setActivePage('onboarding')} />}
          {activePage === 'alerts' && (
            <AttackAlertsPanel
              alerts={telemetry.alerts}
              onAcknowledge={telemetry.handleAcknowledgeAlert}
              onAcknowledgeAll={telemetry.handleAcknowledgeAllAlerts}
            />
          )}

          {['live-traffic','flow-explorer'].includes(activePage) && telemetry.flowsError && <p role="alert" className="text-red-300">Could not load saved traffic windows.</p>}
          {activePage === 'flow-explorer' && (
            <FlowExplorerTable
              flows={telemetry.flows}
              globalSearch={searchQuery}
            />
          )}

          {activePage === 'onboarding' && <ServiceSetupPage/>}

          {activePage === 'system-console' && <section className="workspace-card space-y-5"><h2 className="text-lg font-semibold">Connection details</h2><dl className="diagnostic-list">{[['API server',telemetry.health.online?'Online':'Offline'],['Live updates',telemetry.wsConnected?'Connected':'Disconnected'],['Model',telemetry.activeModelName],['Model loaded',telemetry.health.modelLoaded?'Yes':telemetry.health.error || 'No'],['Server URL',getApiBaseUrl()],['Health latency',telemetry.health.latencyMs===null?'Unavailable':`${telemetry.health.latencyMs} ms`],['Last observation',telemetry.lastUpdated]].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><button className="secondary-action" onClick={()=>void telemetry.refreshBackendHealth()}>Refresh connection</button></section>}
          {activePage === 'profile'  && (
            <ProfileSetupPage
              embedded
              initialProfile={activeProfile}
              onSaveProfile={(saved) => handleSaveProfile(saved, true)}
              onSignOut={handleSignOut}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;

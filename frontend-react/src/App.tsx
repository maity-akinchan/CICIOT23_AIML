import { AlertCircle, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { getApiBaseUrl, setApiBaseUrl } from './api/client';
import { GlassDock } from './components/layout/GlassDock';
import { TopStatusBar } from './components/layout/TopStatusBar';
import { AttackAlertsPanel } from './components/modules/AttackAlertsPanel';
import { FlowExplorerTable } from './components/modules/FlowExplorerTable';
import { LiveTrafficView } from './components/modules/LiveTrafficView';
import { OverviewBento } from './components/modules/OverviewBento';
import { AuthPage } from './components/pages/AuthPage';
import { LandingPage } from './components/pages/LandingPage';
import { OnboardingPage } from './components/pages/OnboardingPage';
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

  const telemetry = useLiveTelemetry(profile?.batchSize ?? 5);

  const unacknowledgedAlertsCount = useMemo(
    () => telemetry.alerts.filter((a) => !a.acknowledged).length,
    [telemetry.alerts]
  );

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
    return (
      <OnboardingPage
        health={telemetry.health}
        wsConnected={telemetry.wsConnected}
        activeModelName={telemetry.activeModelName}
        apiBaseUrl={profile?.apiBaseUrl || getApiBaseUrl()}
        totalFlows={telemetry.kpis.total_flows}
        timeSeries={telemetry.timeSeries}
        onRefreshHealth={telemetry.refreshBackendHealth}
        onSendTestIngest={telemetry.handleSendTestIngestBatch}
        onUploadCsv={telemetry.handleFileUpload}
        onCompleteOnboarding={handleCompleteOnboarding}
      />
    );
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
      <GlassDock
        activePage={activePage}
        onSelectPage={setActivePage}
        unacknowledgedAlertsCount={unacknowledgedAlertsCount}
        totalFlowsCount={telemetry.kpis.total_flows}
        backendOnline={telemetry.health.online}
        latencyMs={telemetry.health.latencyMs}
        activeModelName={telemetry.activeModelName}
        lastUpdated={telemetry.lastUpdated}
        onGoToLanding={() => setStage('landing')}
      />

      <div className="pl-[240px] flex flex-col min-h-screen">
        <TopStatusBar
          wsConnected={telemetry.wsConnected}
          backendOnline={telemetry.health.online}
          activeModelName={telemetry.activeModelName}
          currentFps={telemetry.kpis.current_fps}
          isReplaying={telemetry.isReplaying}
          onToggleReplay={() => telemetry.setIsReplaying((v) => !v)}
          replaySpeedFps={telemetry.replaySpeedFps}
          onChangeReplaySpeed={telemetry.setReplaySpeedFps}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onNavigateTo={setActivePage}
          onResetSoc={telemetry.handleResetSoc}
          unacknowledgedAlertsCount={unacknowledgedAlertsCount}
          profile={activeProfile}
        />

        <main className="flex-1 p-6 pb-14 max-w-[1600px] w-full mx-auto space-y-5">
          {/* Honest FastAPI Connection Error Banner */}
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

          {activePage === 'overview' && (
            <OverviewBento
              kpis={telemetry.kpis}
              timeSeries={telemetry.timeSeries}
              discoveredEndpoints={telemetry.discoveredEndpoints}
              alerts={telemetry.alerts}
              onAcknowledgeAlert={telemetry.handleAcknowledgeAlert}
              onSendTestBatch={() => {
                telemetry.handleSendTestIngestBatch('overview-probe', 3).catch(() => {});
              }}
              onStartStream={() => telemetry.setIsReplaying(true)}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'live-traffic' && (
            <LiveTrafficView
              flows={telemetry.flows}
              timeSeries={telemetry.timeSeries}
              protocolSplit={telemetry.protocolSplit}
              discoveredEndpoints={telemetry.discoveredEndpoints}
              streamPaused={telemetry.streamPaused}
              onTogglePause={() => telemetry.setStreamPaused((p) => !p)}
              onUploadFile={telemetry.handleFileUpload}
              onSendTestBatch={async () => {
                await telemetry.handleSendTestIngestBatch('live-traffic-probe', 3);
              }}
              globalSearch={searchQuery}
            />
          )}

          {activePage === 'alerts' && (
            <AttackAlertsPanel
              alerts={telemetry.alerts}
              onAcknowledge={telemetry.handleAcknowledgeAlert}
              onAcknowledgeAll={telemetry.handleAcknowledgeAllAlerts}
            />
          )}

          {activePage === 'flow-explorer' && (
            <FlowExplorerTable
              flows={telemetry.flows}
              globalSearch={searchQuery}
            />
          )}

          {activePage === 'onboarding' && (
            <OnboardingPage
              embedded
              health={telemetry.health}
              wsConnected={telemetry.wsConnected}
              activeModelName={telemetry.activeModelName}
              apiBaseUrl={activeProfile.apiBaseUrl}
              totalFlows={telemetry.kpis.total_flows}
              timeSeries={telemetry.timeSeries}
              onRefreshHealth={telemetry.refreshBackendHealth}
              onSendTestIngest={telemetry.handleSendTestIngestBatch}
              onUploadCsv={telemetry.handleFileUpload}
              onCompleteOnboarding={() => setActivePage('overview')}
            />
          )}

          {activePage === 'profile' && (
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

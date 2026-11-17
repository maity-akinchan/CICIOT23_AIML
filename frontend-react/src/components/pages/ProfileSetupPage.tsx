import {
  Shield,
  User,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  ArrowLeft,
  RefreshCw,
  LogOut,
  Server,
} from 'lucide-react';
import { useState } from 'react';
import {
  checkBackendHealth,
  getApiBaseUrl,
  type BackendHealthStatus,
} from '../../api/client';
import {
  OperatorProfileSchema,
  type AppStage,
  type OperatorProfile,
} from '../../types/telemetry';
import { SurfaceCard } from '../shared/ui';

interface ProfileSetupPageProps {
  initialProfile: Partial<OperatorProfile>;
  embedded?: boolean;
  onSaveProfile: (profile: OperatorProfile) => void;
  onSignOut?: () => void;
  onNavigateStage?: (stage: AppStage) => void;
}

export function getInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return 'OP';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

export function ProfileSetupPage({
  initialProfile,
  embedded = false,
  onSaveProfile,
  onSignOut,
  onNavigateStage,
}: ProfileSetupPageProps) {
  const [fullName, setFullName] = useState(initialProfile.fullName || '');
  const [role, setRole] = useState(initialProfile.role || 'Security Analyst');
  const [orgName, setOrgName] = useState(initialProfile.orgName || '');
  const [email, setEmail] = useState(initialProfile.email || '');
  const [apiBaseUrl, setApiBaseUrlState] = useState(
    initialProfile.apiBaseUrl || getApiBaseUrl()
  );
  const [batchSize, setBatchSize] = useState<number>(initialProfile.batchSize || 5);

  const [formError, setFormError] = useState<string | null>(null);
  const [savedNotice, setSavedNotice] = useState(false);
  const [testingApi, setTestingApi] = useState(false);
  const [apiTestResult, setApiTestResult] = useState<BackendHealthStatus | null>(null);

  const handleTestConnection = async () => {
    setTestingApi(true);
    try {
      const res = await checkBackendHealth(apiBaseUrl);
      setApiTestResult(res);
    } finally {
      setTestingApi(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = OperatorProfileSchema.safeParse({
      fullName,
      role,
      orgName,
      email,
      apiBaseUrl,
      batchSize,
      onboardingCompleted: Boolean(initialProfile.onboardingCompleted),
    });

    if (!parsed.success) {
      setFormError(parsed.error.issues[0]?.message || 'Please complete all required fields');
      return;
    }

    setFormError(null);
    onSaveProfile(parsed.data);
    if (embedded) {
      setSavedNotice(true);
      setTimeout(() => setSavedNotice(false), 2500);
    }
  };

  const initials = getInitials(fullName);

  const formContent = (
    <div className="w-full max-w-[760px] mx-auto space-y-6">
      <SurfaceCard className="p-6 sm:p-8 space-y-6">
        {/* Header & Live Avatar Preview */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-[#222030]">
          <div>
            <div className="text-[11px] font-bold uppercase tracking-wider text-[#6366F1] mb-1">
              {embedded ? 'Workspace & Operator Settings' : 'Step 2 of 3 · Profile Setup'}
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[#F8FAFC]">
              {embedded ? 'Operator Profile & Connection settings' : 'Set Up Your Operator Profile'}
            </h1>
            <p className="text-xs text-[#8E8CA3] mt-1">
              Configure your identity, workspace name, and the server address.
            </p>
          </div>

          <div className="flex items-center gap-3 bg-[#1A1826] border border-[#222030] px-4 py-2.5 rounded-xl shrink-0">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-[#2563EB] to-[#6366F1] flex items-center justify-center text-sm font-bold text-white shadow">
              {initials}
            </div>
            <div className="text-left">
              <div className="text-xs font-bold text-[#F8FAFC] truncate max-w-[140px]">
                {fullName.trim() || 'Your Name'}
              </div>
              <div className="text-[11px] text-[#8E8CA3] truncate max-w-[140px]">
                {role.trim() || 'Operator'}
              </div>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Operator Identity Fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label
                htmlFor="profile-full-name"
                className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
              >
                Full Name *
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-[#8E8CA3] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="profile-full-name"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Enter your full name"
                  className="w-full h-10 pl-9 pr-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="profile-role"
                className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
              >
                Role / Title *
              </label>
              <input
                id="profile-role"
                type="text"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                placeholder="e.g. SOC Lead, Security Researcher"
                className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="profile-org"
                className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
              >
                Workspace / Organization Name *
              </label>
              <input
                id="profile-org"
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. CICIoT23 Security Lab"
                className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="profile-email"
                className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
              >
                Work Email or Username *
              </label>
              <input
                id="profile-email"
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. operator@sentinel.local"
                className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
              />
            </div>
          </div>

          {/* Server Backend Connection Settings */}
          <div className="pt-3 border-t border-[#222030] space-y-4">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-[#6366F1]" />
              <h2 className="text-sm font-bold text-[#F8FAFC]">
                Server Server Connection &amp; Batch Preferences
              </h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-12 gap-4 items-end">
              <div className="sm:col-span-6 space-y-1.5">
                <label
                  htmlFor="profile-api-url"
                  className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
                >
                  Server Backend URL
                </label>
                <input
                  id="profile-api-url"
                  type="text"
                  value={apiBaseUrl}
                  onChange={(e) => setApiBaseUrlState(e.target.value)}
                  placeholder="http://localhost:8000"
                  className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs font-mono text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
                />
              </div>

              <div className="sm:col-span-3 space-y-1.5">
                <label
                  htmlFor="profile-batch-size"
                  className="block text-[11px] font-semibold uppercase tracking-wider text-[#8E8CA3]"
                >
                  Windows / Batch
                </label>
                <select
                  id="profile-batch-size"
                  value={batchSize}
                  onChange={(e) => setBatchSize(Number(e.target.value))}
                  className="w-full h-10 px-3 bg-[#1A1826] border border-[#222030] rounded-lg text-xs font-mono text-[#F8FAFC] focus:outline-none focus:border-[#6366F1]"
                >
                  <option value={3}>3 windows / batch</option>
                  <option value={5}>5 windows / batch</option>
                  <option value={10}>10 windows / batch</option>
                  <option value={20}>20 windows / batch</option>
                </select>
              </div>

              <div className="sm:col-span-3">
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testingApi}
                  className="w-full h-10 px-3 rounded-lg bg-[#1A1826] hover:bg-[#222030] border border-[#3B3854] text-xs font-semibold text-[#F8FAFC] flex items-center justify-center gap-1.5 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${testingApi ? 'animate-spin' : ''}`} />
                  <span>Test /health</span>
                </button>
              </div>
            </div>

            {apiTestResult && (
              <div
                className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                  apiTestResult.online
                    ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#10B981]'
                    : 'bg-[#F59E0B]/10 border-[#F59E0B]/30 text-[#F59E0B]'
                }`}
              >
                <div className="flex items-center gap-2">
                  {apiTestResult.online ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 shrink-0" />
                  )}
                  <span>
                    {apiTestResult.online
                      ? `Connected to Server (${apiTestResult.latencyMs}ms) · Model Loaded: ${
                          apiTestResult.isBootstrapModel
                            ? 'Bootstrap Model'
                            : 'XGBoost Artifact'
                        }`
                      : `Server not reachable at ${apiBaseUrl}. Run: uvicorn app.main:app --port 8000 --reload`}
                  </span>
                </div>
              </div>
            )}
          </div>

          {formError && (
            <div className="p-3 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444] text-xs">
              {formError}
            </div>
          )}

          {savedNotice && (
            <div className="p-3 rounded-lg bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981] text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Operator profile and Server settings saved.</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="pt-2 flex flex-wrap items-center justify-between gap-3">
            {embedded && onSignOut ? (
              <button
                type="button"
                onClick={onSignOut}
                className="h-10 px-4 rounded-lg bg-[#EF4444]/10 hover:bg-[#EF4444]/20 border border-[#EF4444]/30 text-[#EF4444] text-xs font-semibold flex items-center gap-2 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out &amp; Clear Profile</span>
              </button>
            ) : (
              <div />
            )}

            <button
              type="submit"
              className="h-[42px] px-6 bg-[#2563EB] hover:bg-[#1D4ED8] text-white rounded-lg text-xs font-semibold flex items-center gap-2 transition-colors shadow-md ml-auto"
            >
              <span>
                {embedded
                  ? 'Save Profile Settings'
                  : 'Save Profile & Continue to Onboarding'}
              </span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </form>
      </SurfaceCard>
    </div>
  );

  if (embedded) {
    return formContent;
  }

  return (
    <div className="min-h-screen bg-[#0D0C14] text-[#F8FAFC] flex flex-col justify-between">
      <header className="h-16 bg-[#100F18] border-b border-[#222030] px-6 md:px-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1]">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold text-[15px] tracking-tight text-[#F8FAFC]">
            CICIoT23 Sentinel — Profile Setup
          </span>
        </div>

        {onNavigateStage && (
          <button
            type="button"
            onClick={() => onNavigateStage('landing')}
            className="text-xs font-medium text-[#8E8CA3] hover:text-[#F8FAFC] flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#13121D] border border-[#222030]"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Landing</span>
          </button>
        )}
      </header>

      <main className="flex-1 flex items-center justify-center p-6">{formContent}</main>

      <footer className="h-8 bg-[#100F18] border-t border-[#222030] px-6 flex items-center justify-between text-[11px] text-[#8E8CA3] font-mono">
        <span>STEP 2 OF 3 · OPERATOR &amp; WORKSPACE PROFILE</span>
        <span>CICIoT23 SENTINEL</span>
      </footer>
    </div>
  );
}

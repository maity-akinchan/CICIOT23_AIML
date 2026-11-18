import { apiClient } from '../../api/client';
import { Shield, ArrowRight, ArrowLeft } from 'lucide-react';
import { useState } from 'react';
import {
  WorkspaceAuthSchema,
  type AppStage,
} from '../../types/telemetry';

interface AuthPageProps {
  initialEmail?: string;
  initialOrgName?: string;
  onAuthSuccess: (data: { email: string; orgName?: string; isNewAccount: boolean }) => void;
  onNavigateStage: (stage: AppStage) => void;
}

export function AuthPage({
  initialEmail = '',
  initialOrgName = '',
  onAuthSuccess,
  onNavigateStage,
}: AuthPageProps) {
  const [authMode, setAuthMode] = useState<'signin' | 'create'>('create');
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState(initialOrgName);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = WorkspaceAuthSchema.safeParse({
      email,
      password,
      orgName: authMode === 'create' ? orgName : undefined,
    });
    if (!parsed.success) {
      setAuthError(parsed.error.issues[0]?.message || 'Invalid local profile details');
      return;
    }
    if (authMode === 'create' && (!orgName || orgName.trim().length < 2)) {
      setAuthError('Please enter your Workspace or Organization name');
      return;
    }
    try {
      await apiClient.post('/api/v1/auth/login', {
        email: parsed.data.email,
        password,
        org_name: orgName.trim() || undefined,
        mode: authMode,
      });
      sessionStorage.removeItem('sentinel_operator_token');
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
        'Invalid email or password, or server could not be reached';
      setAuthError(detail);
      return;
    }
    setAuthError(null);
    onAuthSuccess({
      email: parsed.data.email,
      orgName: orgName.trim() || undefined,
      isNewAccount: authMode === 'create',
    });
  };

  return (
    <div className="min-h-screen bg-[#0D0C14] text-[#F8FAFC] flex flex-col justify-between">
      {/* Top Minimalist Brand Bar */}
      <header className="h-16 bg-[#100F18] border-b border-[#222030] px-6 md:px-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#6366F1]/15 border border-[#6366F1]/40 flex items-center justify-center text-[#6366F1]">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold text-[15px] tracking-tight text-[#F8FAFC]">
            CICIoT23 Sentinel
          </span>
        </div>

        <button
          type="button"
          onClick={() => onNavigateStage('landing')}
          className="text-xs font-medium text-[#8E8CA3] hover:text-[#F8FAFC] flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#13121D] border border-[#222030] transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Landing</span>
        </button>
      </header>

      {/* Centered Auth Card */}
      <main className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-[440px] bg-[#13121D] border border-[#222030] rounded-xl p-8 shadow-2xl">
          <div className="mb-6">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#6366F1]/10 border border-[#6366F1]/20 text-[#6366F1] text-xs font-medium mb-3">
              <Shield className="w-3.5 h-3.5" />
              <span>Workspace Access</span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[#F8FAFC]">
              {authMode === 'create' ? 'Configure Local Profile' : 'Connect to Server'}
            </h1>
            <p className="text-xs text-[#8E8CA3] mt-1 leading-relaxed">
              Authenticate to configure your operator profile, connect to the FastAPI engine, and
              monitor live traffic.
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="grid grid-cols-2 p-1 bg-[#1A1826] rounded-lg border border-[#222030] mb-6">
            <button
              type="button"
              onClick={() => {
                setAuthMode('create');
                setAuthError(null);
              }}
              className={`py-1.5 text-xs font-semibold rounded-md transition-colors ${
                authMode === 'create'
                  ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                  : 'text-[#8E8CA3] hover:text-[#F8FAFC] border border-transparent'
              }`}
            >
              New Profile
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMode('signin');
                setAuthError(null);
              }}
              className={`py-1.5 text-xs font-semibold rounded-md transition-colors ${
                authMode === 'signin'
                  ? 'bg-[#13121D] text-[#F8FAFC] border border-[#3B3854]'
                  : 'text-[#8E8CA3] hover:text-[#F8FAFC] border border-transparent'
              }`}
            >
              Connect
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {authMode === 'create' && (
              <div className="space-y-1.5">
                <label
                  htmlFor="auth-org-name"
                  className="block text-[11px] font-semibold text-[#8E8CA3] uppercase tracking-wider"
                >
                  Workspace / Organization Name
                </label>
                <input
                  id="auth-org-name"
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. IoT Security Lab"
                  className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
                />
              </div>
            )}

            <div className="space-y-1.5">
              <label
                htmlFor="auth-email"
                className="block text-[11px] font-semibold text-[#8E8CA3] uppercase tracking-wider"
              >
                Work Email or Username
              </label>
              <input
                id="auth-email"
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. analyst@organization.org"
                className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="auth-password"
                className="block text-[11px] font-semibold text-[#8E8CA3] uppercase tracking-wider"
              >
                Password
              </label>
              <input
                id="auth-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                className="w-full h-10 px-3.5 bg-[#1A1826] border border-[#222030] rounded-lg text-xs text-[#F8FAFC] placeholder-[#8E8CA3]/60 focus:outline-none focus:border-[#6366F1]"
              />
            </div>

            {authError && (
              <div className="p-2.5 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444] text-[11.5px]">
                {authError}
              </div>
            )}

            <button
              type="submit"
              className="w-full h-[42px] bg-[#2563EB] hover:bg-[#1D4ED8] text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-md"
            >
              <span>
                {authMode === 'create'
                  ? 'Continue to Profile Setup'
                  : 'Connect & Continue'}
              </span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </main>

      <footer className="h-8 bg-[#100F18] border-t border-[#222030] px-6 flex items-center justify-between text-[11px] text-[#8E8CA3] font-mono">
        <span>STEP 1 OF 3 · WORKSPACE AUTHENTICATION</span>
        <span>CICIoT23 SENTINEL</span>
      </footer>
    </div>
  );
}

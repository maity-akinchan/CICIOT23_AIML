import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { apiClient, apiErrorMessage } from '../../api/client';

interface ModelCatalog {
  active_model_id: string | null;
  models: { model_id: string; model_name: string }[];
}

async function fetchCatalog() {
  const { data } = await apiClient.get<ModelCatalog>('/api/v1/models');
  return data;
}

export function ModelSelector({ onSelect }: { onSelect: () => void }) {
  const [catalog, setCatalog] = useState<ModelCatalog | null>(null);
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let cancelled = false;
    fetchCatalog()
      .then(data => { if (!cancelled) setCatalog(data); })
      .catch(error => { if (!cancelled) setMessage(apiErrorMessage(error)); })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, []);

  async function refresh() {
    setBusy(true);
    setMessage('');
    try {
      setCatalog(await fetchCatalog());
      onSelect();
    } catch (error) {
      setMessage(apiErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function select(modelId: string) {
    setBusy(true);
    setMessage('Loading model…');
    try {
      const { data } = await apiClient.post<Pick<ModelCatalog, 'active_model_id'>>(
        '/api/v1/models/select', { model_id: modelId }, { timeout: 0 }
      );
      setCatalog(current => current && { ...current, active_model_id: data.active_model_id });
      setMessage('');
      onSelect();
    } catch (error) {
      setMessage(apiErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2">
        <label htmlFor="active-model" className="text-sm text-slate-300">Model</label>
        <select
          id="active-model"
          className="workspace-input min-w-0 max-w-[min(54vw,21rem)]"
          value={catalog?.active_model_id ?? ''}
          onChange={event => void select(event.target.value)}
          disabled={busy || !catalog?.models.length}
        >
          {!catalog?.active_model_id && (
            <option value="" disabled>
              {busy ? 'Loading models…' : catalog?.models.length ? 'Select a model' : 'No models available'}
            </option>
          )}
          {catalog?.models.map(model => (
            <option key={model.model_id} value={model.model_id}>{model.model_name}</option>
          ))}
        </select>
        <button
          className="secondary-action shrink-0"
          type="button"
          title="Refresh models"
          aria-label="Refresh models"
          onClick={() => void refresh()}
          disabled={busy}
        >
          <RefreshCw size={16} aria-hidden="true" />
        </button>
      </div>
      <p role="status" className="max-w-xs break-words text-xs text-slate-300">{message}</p>
    </div>
  );
}

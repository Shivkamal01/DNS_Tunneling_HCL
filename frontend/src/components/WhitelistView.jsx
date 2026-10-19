import React, { useCallback, useEffect, useState } from 'react';
import { PlusIcon, RefreshIcon, ShieldIcon, XIcon } from './Icons';
import { api, describeError } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

function formatWhen(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function WhitelistView({ onNotify, onChanged }) {
  const [rules, setRules] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pattern, setPattern] = useState('');
  const [reason, setReason] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [busyPattern, setBusyPattern] = useState(null);
  const [error, setError] = useState(null);

  // Live preview of what the current input would score.
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState(null);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    try {
      const payload = await api.getWhitelist();
      setRules(payload.data || []);
      setError(null);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Debounced scoring preview as the analyst types a candidate domain.
  useEffect(() => {
    const candidate = pattern.trim();
    if (candidate.length < 4 || !candidate.includes('.')) {
      setPreview(null);
      setPreviewError(null);
      return undefined;
    }

    const timer = setTimeout(async () => {
      try {
        const payload = await api.analyzeDomain(candidate);
        setPreview(payload.data);
        setPreviewError(null);
      } catch (err) {
        setPreview(null);
        setPreviewError(describeError(err));
      }
    }, 420);

    return () => clearTimeout(timer);
  }, [pattern]);

  const handleAdd = async (event) => {
    event.preventDefault();
    if (!pattern.trim()) return;

    setIsSaving(true);
    try {
      const payload = await api.addWhitelist(pattern.trim(), reason.trim() || undefined);
      onNotify?.(payload.message || `Whitelisted ${pattern}`, 'success');
      setPattern('');
      setReason('');
      setPreview(null);
      await load(true);
      onChanged?.();
    } catch (err) {
      onNotify?.(describeError(err), 'error', 'Could not add rule');
    } finally {
      setIsSaving(false);
    }
  };

  const handleRemove = async (rule) => {
    setBusyPattern(rule.domain_pattern);
    try {
      await api.removeWhitelist(rule.domain_pattern);
      setRules((prev) => prev.filter((item) => item.domain_pattern !== rule.domain_pattern));
      onNotify?.(`Removed ${rule.domain_pattern}`, 'success');
      onChanged?.();
    } catch (err) {
      onNotify?.(describeError(err), 'error', 'Could not remove rule');
    } finally {
      setBusyPattern(null);
    }
  };

  const previewColor = preview ? SEVERITY_COLORS[preview.severity] || SEVERITY_COLORS.MEDIUM : null;

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h3>Whitelist rules</h3>
          <p className="panel-sub">
            Matching queries are scored 0 before any other heuristic runs — they still appear in
            telemetry, flagged as suppressed
          </p>
        </div>
        <div className="toolbar-right">
          <div className="table-count-badge">
            <strong>{rules.length}</strong>
            <span>rules</span>
          </div>
          <button className="btn-action" onClick={() => load()} disabled={isLoading}>
            <RefreshIcon size={12} className={isLoading ? 'spin-anim' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <form className="whitelist-form" onSubmit={handleAdd}>
        <div className="field-group">
          <label className="control-label" htmlFor="whitelist-pattern">Domain pattern</label>
          <input
            id="whitelist-pattern"
            className="text-input"
            placeholder="example.com or cdn.example.com"
            value={pattern}
            onChange={(event) => setPattern(event.target.value)}
            autoComplete="off"
            spellCheck="false"
          />
        </div>

        <div className="field-group">
          <label className="control-label" htmlFor="whitelist-reason">Reason</label>
          <input
            id="whitelist-reason"
            className="text-input"
            placeholder="Why is this traffic known-good?"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            autoComplete="off"
            style={{ fontFamily: 'var(--font-sans)' }}
          />
        </div>

        <button className="btn-action primary" type="submit" disabled={isSaving || !pattern.trim()}>
          <PlusIcon size={13} />
          <span>{isSaving ? 'Adding…' : 'Add rule'}</span>
        </button>
      </form>

      {/* Live scoring preview */}
      {previewError && (
        <div className="sim-result-banner error" style={{ margin: '0 14px 12px' }}>
          {previewError}
        </div>
      )}

      {preview && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            flexWrap: 'wrap',
            margin: '0 14px 12px',
            padding: '8px 11px',
            border: '1px solid var(--rule)',
            borderLeft: `2px solid ${previewColor}`,
            borderRadius: 'var(--radius)',
            background: 'var(--bg-inset)',
            fontSize: 11.5,
            color: 'var(--text-muted)',
          }}
        >
          <span style={{ color: 'var(--text-dim)' }}>Current score for this pattern:</span>
          <span className="mono" style={{ color: previewColor, fontWeight: 600 }}>
            {preview.risk_score} · {preview.severity}
          </span>
          <span style={{ color: 'var(--text-dim)' }}>
            {preview.risk_score > 0
              ? '— whitelisting will suppress this'
              : '— already below threshold'}
          </span>
        </div>
      )}

      {error ? (
        <div className="table-empty-wrap">
          <span>Could not load whitelist: {error}</span>
          <button className="btn-action primary" onClick={() => load()}>Retry</button>
        </div>
      ) : isLoading ? (
        <div className="table-loading-wrap">
          <div className="table-spinner" />
          <span>Loading rules…</span>
        </div>
      ) : rules.length === 0 ? (
        <div className="table-empty-wrap">
          <ShieldIcon size={26} color="#3a3a44" />
          <p>No whitelist rules configured.</p>
        </div>
      ) : (
        <div className="whitelist-list">
          {rules.map((rule) => (
            <div className="whitelist-row" key={rule.domain_pattern}>
              <span className="whitelist-pattern" title={rule.domain_pattern}>
                {rule.domain_pattern}
              </span>
              <span className="whitelist-reason" title={rule.reason || ''}>
                {rule.reason || '—'}
              </span>
              <span className={`whitelist-source ${rule.added_by === 'analyst' ? 'analyst' : ''}`}>
                {rule.added_by || 'system'}
                {rule.created_at ? ` · ${formatWhen(rule.created_at)}` : ''}
              </span>
              <button
                className="btn-remove"
                onClick={() => handleRemove(rule)}
                disabled={busyPattern === rule.domain_pattern}
                title={`Remove rule for ${rule.domain_pattern}`}
                aria-label={`Remove rule for ${rule.domain_pattern}`}
              >
                <XIcon size={12} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { PlusIcon, RefreshIcon, ShieldIcon, XIcon, SearchIcon } from './Icons';
import { api, describeError } from '../services/api';
import { formatDate } from '../utils/format';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

/**
 * Mirror the API's whitelist validation so an analyst sees the problem before
 * a round trip. The backend remains authoritative; this only shortens the loop.
 */
function validatePattern(value) {
  const cleaned = value.trim().replace(/\.$/, '').toLowerCase();

  if (!cleaned) return 'Enter a domain suffix.';
  if (cleaned.includes('*')) {
    return 'Wildcards are not supported. Add a concrete suffix such as example.com.';
  }
  if (!cleaned.includes('.')) return 'A rule needs at least one dot, e.g. example.com.';
  if (cleaned.includes('..')) return 'Remove the empty label (two dots in a row).';
  if (cleaned.length > 255) return 'Keep the pattern under 255 characters.';
  if (!/^[a-z0-9._-]+$/.test(cleaned)) {
    return 'Use letters, digits, dots, hyphens, or underscores only.';
  }
  return null;
}

function sourceLabel(rule) {
  return rule.added_by === 'analyst' ? 'analyst' : 'seeded';
}

export function WhitelistView({ onNotify, onChanged }) {
  const [rules, setRules] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [pattern, setPattern] = useState('');
  const [reason, setReason] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [busyPattern, setBusyPattern] = useState(null);
  const [confirmPattern, setConfirmPattern] = useState(null);
  const [search, setSearch] = useState('');
  const [error, setError] = useState(null);

  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const patternError = useMemo(
    () => (pattern.trim() ? validatePattern(pattern) : null),
    [pattern],
  );

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    else setIsRefreshing(true);
    try {
      const payload = await api.getWhitelist();
      setRules(payload.data || []);
      setError(null);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Debounced scoring preview as the analyst types a candidate domain. The
  // cancelled flag drops a slow response for an earlier pattern so it cannot
  // overwrite the score for what is currently in the input.
  useEffect(() => {
    const candidate = pattern.trim();

    if (candidate.length < 4 || !candidate.includes('.') || patternError) {
      setPreview(null);
      setPreviewError(null);
      return undefined;
    }

    let cancelled = false;
    setPreview(null);
    setPreviewError(null);

    const timer = setTimeout(async () => {
      try {
        const payload = await api.analyzeDomain(candidate.replace(/\.$/, ''));
        if (cancelled) return;
        setPreview(payload.data);
        setPreviewError(null);
      } catch (err) {
        if (cancelled) return;
        setPreview(null);
        setPreviewError(describeError(err));
      }
    }, 420);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [pattern, patternError]);

  const handleAdd = async (event) => {
    event.preventDefault();

    const normalized = pattern.trim().replace(/\.$/, '').toLowerCase();
    const validationError = validatePattern(normalized);
    if (validationError) return;

    setIsSaving(true);
    try {
      const payload = await api.addWhitelist(normalized, reason.trim() || undefined);
      onNotify?.(payload.message || `Whitelisted ${normalized}`, 'success');
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
      setConfirmPattern(null);
      onNotify?.(`Removed ${rule.domain_pattern}`, 'success');
      onChanged?.();
    } catch (err) {
      onNotify?.(describeError(err), 'error', 'Could not remove rule');
    } finally {
      setBusyPattern(null);
    }
  };

  const analystRules = rules.filter((rule) => rule.added_by === 'analyst').length;
  const seedRules = rules.length - analystRules;

  const searchTerm = search.trim().toLowerCase();
  const visibleRules = useMemo(() => rules.filter((rule) => (
    !searchTerm
    || rule.domain_pattern.toLowerCase().includes(searchTerm)
    || (rule.reason || '').toLowerCase().includes(searchTerm)
    || (rule.added_by || '').toLowerCase().includes(searchTerm)
  )), [rules, searchTerm]);

  const previewColor = preview ? SEVERITY_COLORS[preview.severity] || SEVERITY_COLORS.MEDIUM : null;

  return (
    <div className="panel whitelist-panel">
      <div className="panel-header">
        <div>
          <h3>Whitelist rules</h3>
          <p className="panel-sub">
            Matching queries are flagged and score 0 before risk scoring. They still appear in
            telemetry. A suffix rule covers every subdomain beneath it.
          </p>
        </div>
        <div className="toolbar-right">
          <div className="whitelist-rule-meta">
            <span><strong>{rules.length}</strong> total</span>
            <span><strong>{seedRules}</strong> seeded</span>
            <span><strong>{analystRules}</strong> analyst</span>
          </div>
          <button
            className="btn-action"
            onClick={() => load(rules.length > 0)}
            disabled={isLoading || isRefreshing}
          >
            <RefreshIcon size={12} className={isLoading || isRefreshing ? 'spin-anim' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <form className="whitelist-form" onSubmit={handleAdd} noValidate>
        <div className="field-group">
          <label className="control-label" htmlFor="whitelist-pattern">Domain pattern</label>
          <input
            id="whitelist-pattern"
            className={`text-input ${patternError ? 'input-invalid' : ''}`}
            placeholder="example.com or cdn.example.com"
            value={pattern}
            onChange={(event) => setPattern(event.target.value)}
            autoComplete="off"
            spellCheck="false"
            aria-invalid={Boolean(patternError)}
            aria-describedby={patternError ? 'whitelist-pattern-error' : undefined}
          />
          {patternError && (
            <span className="field-error" id="whitelist-pattern-error" role="alert">
              {patternError}
            </span>
          )}
        </div>

        <div className="field-group">
          <label className="control-label" htmlFor="whitelist-reason">Reason</label>
          <input
            id="whitelist-reason"
            className="text-input text-input-sans"
            placeholder="Why is this traffic known-good?"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            maxLength={500}
            autoComplete="off"
          />
        </div>

        <button
          className="btn-action primary"
          type="submit"
          disabled={isSaving || !pattern.trim() || Boolean(patternError)}
        >
          <PlusIcon size={13} />
          <span>{isSaving ? 'Adding…' : 'Add rule'}</span>
        </button>
      </form>

      {previewError && (
        <div className="sim-result-banner error whitelist-preview-error" role="alert">{previewError}</div>
      )}

      {preview && (
        <div
          className="preview-strip"
          style={{ borderLeftColor: previewColor }}
          role="status"
          aria-live="polite"
        >
          <span className="preview-strip-label">Score for the suffix itself</span>
          <span className="mono preview-strip-score" style={{ color: previewColor }}>
            {preview.risk_score} · {preview.severity}
          </span>
          <span className="preview-strip-note">
            {preview.risk_score > 0
              ? 'The suffix itself scores above threshold; the rule suppresses it and every subdomain beneath it.'
              : 'The suffix itself is already benign; the rule still suppresses every subdomain beneath it.'}
          </span>
        </div>
      )}

      {error && rules.length > 0 && (
        <div className="inline-warning whitelist-inline-error" role="alert">
          <span>Rule refresh failed: {error}</span>
          <button className="section-link" onClick={() => load(true)}>Retry</button>
        </div>
      )}

      <div className="whitelist-filter-bar">
        <div className="incident-search">
          <SearchIcon size={13} className="search-icon" />
          <input
            type="text"
            className="table-search"
            placeholder="Filter rules by pattern, reason, or source…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Filter whitelist rules"
          />
          {search && (
            <button className="search-clear-btn" onClick={() => setSearch('')} aria-label="Clear rule filter">
              <XIcon size={12} />
            </button>
          )}
        </div>
        <div className="table-count-badge">
          <strong>{visibleRules.length}</strong>
          <span>of {rules.length} rules</span>
        </div>
      </div>

      {error && rules.length === 0 ? (
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
          <ShieldIcon size={26} color="var(--text-dim)" />
          <p>No whitelist rules configured. Every query is scored by the detector.</p>
        </div>
      ) : visibleRules.length === 0 ? (
        <div className="table-empty-wrap">
          <SearchIcon size={26} color="var(--text-dim)" />
          <p>No rules match this filter.</p>
          <button className="btn-action" onClick={() => setSearch('')}>Clear filter</button>
        </div>
      ) : (
        <div className="whitelist-list">
          <div className="whitelist-column-head" aria-hidden="true">
            <span>Pattern</span>
            <span>Reason</span>
            <span>Source</span>
            <span />
          </div>

          {visibleRules.map((rule) => {
            const confirming = confirmPattern === rule.domain_pattern;
            const busy = busyPattern === rule.domain_pattern;

            return (
              <div className={`whitelist-row ${confirming ? 'is-confirming' : ''}`} key={rule.domain_pattern}>
                <span className="whitelist-pattern" title={rule.domain_pattern}>
                  {rule.domain_pattern}
                </span>
                <span className="whitelist-reason" title={rule.reason || ''}>
                  {rule.reason || '—'}
                </span>
                <span className={`whitelist-source ${rule.added_by === 'analyst' ? 'analyst' : ''}`}>
                  {sourceLabel(rule)}
                  {rule.created_at ? <span className="whitelist-source-date"> · {formatDate(rule.created_at)}</span> : null}
                </span>

                {confirming ? (
                  <span className="delete-confirm">
                    <span className="delete-confirm-label">Remove?</span>
                    <button
                      className="btn-confirm danger"
                      onClick={() => handleRemove(rule)}
                      disabled={busy}
                    >
                      {busy ? 'Removing…' : 'Remove'}
                    </button>
                    <button
                      className="btn-confirm"
                      onClick={() => setConfirmPattern(null)}
                      disabled={busy}
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    className="btn-remove"
                    onClick={() => setConfirmPattern(rule.domain_pattern)}
                    title={`Remove rule for ${rule.domain_pattern}`}
                    aria-label={`Remove rule for ${rule.domain_pattern}`}
                  >
                    <XIcon size={12} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

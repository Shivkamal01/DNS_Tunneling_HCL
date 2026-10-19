import React, { useEffect, useRef, useState } from 'react';
import {
  ShieldIcon, RefreshIcon, PlayIcon, DownloadIcon,
  TerminalIcon, LayersIcon,
} from './Icons';

function timeAgo(timestamp) {
  if (!timestamp) return '';
  const diff = Date.now() - new Date(timestamp).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

export function Header({
  connectionStatus,
  lastUpdated,
  countdown,
  refreshInterval,
  isRefreshing,
  onRefresh,
  onOpenSimulator,
  onOpenTelemetry,
  onExport,
  density,
  onToggleDensity,
}) {
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef(null);

  // Close the export menu on outside click or Escape.
  useEffect(() => {
    if (!exportOpen) return undefined;

    const handleClick = (event) => {
      if (exportRef.current && !exportRef.current.contains(event.target)) setExportOpen(false);
    };
    const handleKey = (event) => {
      if (event.key === 'Escape') setExportOpen(false);
    };

    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [exportOpen]);

  const progressPct = ((refreshInterval - countdown) / refreshInterval) * 100;
  const statusLabel = connectionStatus === 'online'
    ? 'Live'
    : connectionStatus === 'offline'
      ? 'Offline · sample data'
      : 'Connecting';

  return (
    <header className="header" role="banner">
      <div className="header-left">
        <div className="brand-logo" aria-hidden="true">
          <ShieldIcon size={19} color="currentColor" />
        </div>
        <div className="brand-titles">
          <div className="brand-meta">
            <span className="brand-tag">HCL Cyber Defense</span>
            <span className="brand-divider">/</span>
            <span className="brand-product">Incident Response</span>
          </div>
          <h1>DNS Tunneling Detection &amp; Triage</h1>
        </div>
      </div>

      <div className="header-right">
        <div className={`status-pill ${connectionStatus}`}>
          <span className="status-indicator-dot" />
          <span className="status-pill-label">{statusLabel}</span>
        </div>

        {lastUpdated && (
          <div className="header-chip" title={new Date(lastUpdated).toLocaleString()}>
            Updated {timeAgo(lastUpdated)}
          </div>
        )}

        <div className={`refresh-widget ${isRefreshing ? 'busy' : ''}`} title="Auto-refresh countdown">
          <RefreshIcon size={12} className={isRefreshing ? 'spin-anim' : ''} />
          <span>{countdown}s</span>
          <div className="refresh-bar-track">
            <div className="refresh-bar-fill" style={{ width: `${progressPct}%` }} />
          </div>
        </div>

        <div className="header-actions">
          <button
            className="btn-action primary"
            onClick={onOpenSimulator}
            title="Inject simulated DNS traffic into the pipeline"
          >
            <PlayIcon size={12} />
            <span>Simulate</span>
          </button>

          <button
            className="btn-action"
            onClick={onOpenTelemetry}
            title="Inspect raw DNS queries and extracted features"
          >
            <TerminalIcon size={13} />
            <span>Telemetry</span>
          </button>

          <div style={{ position: 'relative' }} ref={exportRef}>
            <button
              className={`btn-action ${exportOpen ? 'active' : ''}`}
              onClick={() => setExportOpen((open) => !open)}
              title="Export alert data"
              aria-haspopup="menu"
              aria-expanded={exportOpen}
            >
              <DownloadIcon size={13} />
              <span>Export</span>
            </button>

            {exportOpen && (
              <div
                role="menu"
                style={{
                  position: 'absolute',
                  top: 'calc(100% + 4px)',
                  right: 0,
                  minWidth: 140,
                  zIndex: 400,
                  background: 'var(--bg-panel)',
                  border: '1px solid var(--rule-strong)',
                  borderRadius: 'var(--radius)',
                  boxShadow: '0 10px 28px rgba(0,0,0,0.55)',
                  overflow: 'hidden',
                }}
              >
                {[
                  { format: 'csv', label: 'Download CSV' },
                  { format: 'json', label: 'Download JSON' },
                ].map((option) => (
                  <button
                    key={option.format}
                    role="menuitem"
                    onClick={() => { onExport(option.format); setExportOpen(false); }}
                    style={{
                      display: 'block',
                      width: '100%',
                      padding: '8px 11px',
                      border: 'none',
                      borderBottom: option.format === 'csv' ? '1px solid var(--rule-faint)' : 'none',
                      background: 'transparent',
                      color: 'var(--text-muted)',
                      fontFamily: 'var(--font-sans)',
                      fontSize: 11.5,
                      textAlign: 'left',
                      cursor: 'pointer',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            className={`btn-action btn-icon-only ${density === 'compact' ? 'active' : ''}`}
            onClick={onToggleDensity}
            title={`Row density: ${density}`}
            aria-label="Toggle row density"
          >
            <LayersIcon size={14} />
          </button>

          <button
            className="btn-action btn-icon-only"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh now"
            aria-label="Refresh alerts"
          >
            <RefreshIcon size={13} className={isRefreshing ? 'spin-anim' : ''} />
          </button>
        </div>
      </div>
    </header>
  );
}

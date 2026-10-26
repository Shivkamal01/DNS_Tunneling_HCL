import React, { useEffect, useRef, useState } from 'react';
import {
  ShieldIcon, RefreshIcon, PlayIcon, DownloadIcon,
  TerminalIcon, LayersIcon, ClockIcon,
} from './Icons';
import { formatClock } from '../utils/format';

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
  isLoading,
  isRefreshing,
  onRefresh,
  onOpenSimulator,
  onOpenTelemetry,
  onExport,
  density,
  onToggleDensity,
}) {
  const [exportOpen, setExportOpen] = useState(false);
  const [now, setNow] = useState(() => new Date());
  const exportRef = useRef(null);

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

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
      ? 'Offline · local data'
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
        <div className="header-clock" title={now.toLocaleString()}>
          <ClockIcon size={12} />
          <span className="mono">{formatClock(now)}</span>
          <span className="header-clock-zone">UTC</span>
        </div>

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

        <div className="operator-chip" title="Local analyst session">
          <span className="avatar avatar-sm">SA</span>
          <span className="operator-copy">
            <strong>SOC Analyst</strong>
            <span>Tier 1 · on shift</span>
          </span>
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
              <div className="export-menu" role="menu">
                {[
                  { format: 'csv', label: 'Download CSV' },
                  { format: 'json', label: 'Download JSON' },
                ].map((option) => (
                  <button
                    key={option.format}
                    className="export-menu-item"
                    role="menuitem"
                    onClick={() => { onExport(option.format); setExportOpen(false); }}
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
            disabled={isLoading || isRefreshing}
            title="Refresh now"
            aria-label="Refresh alerts"
          >
            <RefreshIcon size={13} className={isLoading || isRefreshing ? 'spin-anim' : ''} />
          </button>
        </div>
      </div>
    </header>
  );
}

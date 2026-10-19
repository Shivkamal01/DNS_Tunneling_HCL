import React, { useMemo } from 'react';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  BarChart, Bar,
} from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#d3564f',
  HIGH:     '#cf8748',
  MEDIUM:   '#6b8fb5',
  LOW:      '#7fa583',
};

const AXIS_STYLE = { fill: '#6b6b76', fontSize: 10, fontFamily: 'IBM Plex Mono, monospace' };
const GRID_COLOR = '#1a1a1f';

function PieTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const entry = payload[0];
  return (
    <div className="chart-tooltip">
      <div className="tooltip-title" style={{ color: SEVERITY_COLORS[entry.name] }}>
        {entry.name}
      </div>
      <div className="tooltip-row">
        <span>Alerts</span>
        <strong>{entry.value}</strong>
      </div>
    </div>
  );
}

function TimelineTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <div className="tooltip-title">{label}</div>
      <div className="tooltip-row">
        <span>Alerts</span>
        <strong>{point.count}</strong>
      </div>
      {point.avgRisk !== undefined && (
        <div className="tooltip-row">
          <span>Avg risk</span>
          <strong>{point.avgRisk}</strong>
        </div>
      )}
    </div>
  );
}

function DomainTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <div className="tooltip-title mono">{point.fullDomain}</div>
      <div className="tooltip-row">
        <span>Alerts</span>
        <strong>{point.count}</strong>
      </div>
      <div className="tooltip-row">
        <span>Peak risk</span>
        <strong style={{ color: point.risk >= 80 ? SEVERITY_COLORS.CRITICAL : point.risk >= 55 ? SEVERITY_COLORS.HIGH : SEVERITY_COLORS.MEDIUM }}>
          {point.risk}
        </strong>
      </div>
    </div>
  );
}

export function ThreatAnalytics({ alerts, metricsData, isLoading }) {
  /**
   * Severity split. Prefer the server-side breakdown, which covers every alert
   * in the database — deriving it from the loaded page made the donut disagree
   * with the metric strip as soon as the table was paginated.
   */
  const pieData = useMemo(() => {
    const breakdown = metricsData?.severity_breakdown;
    if (Array.isArray(breakdown) && breakdown.some((entry) => entry.value > 0)) {
      return breakdown.filter((entry) => entry.value > 0);
    }

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach((alert) => {
      const severity = (alert.severity || '').toUpperCase();
      if (severity in counts) counts[severity] += 1;
    });
    return Object.entries(counts)
      .filter(([, value]) => value > 0)
      .map(([name, value]) => ({ name, value }));
  }, [alerts, metricsData]);

  const totalForLegend = useMemo(
    () => pieData.reduce((sum, entry) => sum + entry.value, 0),
    [pieData],
  );

  const timelineData = useMemo(() => {
    if (metricsData?.timeline?.length) {
      return metricsData.timeline.map((bucket) => ({
        time: bucket.time_bucket,
        count: parseInt(bucket.alert_count, 10) || 0,
        avgRisk: bucket.avg_risk !== undefined ? parseInt(bucket.avg_risk, 10) : undefined,
      }));
    }

    const buckets = {};
    [...alerts]
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
      .forEach((alert) => {
        if (!alert.created_at) return;
        const date = new Date(alert.created_at);
        const key = `${String(date.getHours()).padStart(2, '0')}:00`;
        buckets[key] = (buckets[key] || 0) + 1;
      });
    return Object.entries(buckets)
      .map(([time, count]) => ({ time, count }))
      .slice(-12);
  }, [alerts, metricsData]);

  const topDomainsData = useMemo(() => {
    if (metricsData?.top_domains?.length) {
      return metricsData.top_domains.map((entry) => ({
        label: entry.domain.length > 26 ? `${entry.domain.slice(0, 24)}…` : entry.domain,
        fullDomain: entry.domain,
        count: parseInt(entry.query_count, 10) || 0,
        risk: parseInt(entry.max_risk, 10) || 0,
      }));
    }

    const byDomain = {};
    alerts.forEach((alert) => {
      const domain = alert.domain || 'unknown';
      byDomain[domain] = byDomain[domain] || { count: 0, risk: 0 };
      byDomain[domain].count += 1;
      byDomain[domain].risk = Math.max(byDomain[domain].risk, alert.risk_score || 0);
    });

    return Object.entries(byDomain)
      .map(([domain, info]) => ({
        label: domain.length > 26 ? `${domain.slice(0, 24)}…` : domain,
        fullDomain: domain,
        count: info.count,
        risk: info.risk,
      }))
      .sort((a, b) => b.count - a.count || b.risk - a.risk)
      .slice(0, 5);
  }, [alerts, metricsData]);

  const renderEmpty = (message, height = 200) => (
    <div className="chart-empty" style={{ minHeight: height }}>{message}</div>
  );

  return (
    <div className="analytics-grid">
      {/* Severity distribution */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div>
            <h3>Severity mix</h3>
            <p className="panel-sub">Distribution across all scored alerts</p>
          </div>
        </div>

        <div className="chart-wrapper">
          {isLoading ? (
            <div className="chart-skeleton" style={{ height: 190 }} />
          ) : pieData.length === 0 ? (
            renderEmpty('No alerts recorded')
          ) : (
            <>
              <ResponsiveContainer width="100%" height={172}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
                    outerRadius={78}
                    paddingAngle={2}
                    dataKey="value"
                    stroke="none"
                    isAnimationActive={false}
                  >
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || SEVERITY_COLORS.MEDIUM} />
                    ))}
                  </Pie>
                  <Tooltip content={<PieTooltip />} />
                </PieChart>
              </ResponsiveContainer>

              <div className="severity-legend">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => {
                  const entry = pieData.find((item) => item.name === severity);
                  const value = entry?.value || 0;
                  const share = totalForLegend > 0 ? Math.round((value / totalForLegend) * 100) : 0;
                  return (
                    <div className="legend-item" key={severity}>
                      <span className="legend-dot" style={{ background: SEVERITY_COLORS[severity] }} />
                      <span className="legend-label">{severity}</span>
                      <span className="legend-count">
                        {value} <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>({share}%)</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Detection timeline */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div>
            <h3>Detection activity</h3>
            <p className="panel-sub">Alert volume per hour, most recent 15 buckets</p>
          </div>
        </div>

        <div className="chart-wrapper">
          {isLoading ? (
            <div className="chart-skeleton" style={{ height: 240 }} />
          ) : timelineData.length === 0 ? (
            renderEmpty('No activity recorded yet', 240)
          ) : (
            <ResponsiveContainer width="100%" height={258}>
              <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: -22, bottom: 4 }}>
                <defs>
                  <linearGradient id="activityGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#d9a04a" stopOpacity={0.26} />
                    <stop offset="100%" stopColor="#d9a04a" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 4" stroke={GRID_COLOR} vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={AXIS_STYLE}
                  axisLine={{ stroke: GRID_COLOR }}
                  tickLine={false}
                  interval="preserveStartEnd"
                  minTickGap={24}
                />
                <YAxis
                  allowDecimals={false}
                  tick={AXIS_STYLE}
                  axisLine={false}
                  tickLine={false}
                  width={40}
                />
                <Tooltip content={<TimelineTooltip />} cursor={{ stroke: '#33333c', strokeDasharray: '2 3' }} />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#d9a04a"
                  strokeWidth={1.5}
                  fill="url(#activityGrad)"
                  dot={false}
                  activeDot={{ r: 3, fill: '#d9a04a', stroke: '#0a0a0b', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Top targeted domains */}
      <div className="panel chart-panel">
        <div className="panel-header">
          <div>
            <h3>Top targets</h3>
            <p className="panel-sub">Hostnames generating the most alerts</p>
          </div>
        </div>

        <div className="chart-wrapper">
          {isLoading ? (
            <div className="chart-skeleton" style={{ height: 240 }} />
          ) : topDomainsData.length === 0 ? (
            renderEmpty('No suspicious targets detected', 240)
          ) : (
            <ResponsiveContainer width="100%" height={258}>
              <BarChart
                data={topDomainsData}
                layout="vertical"
                margin={{ top: 4, right: 12, left: 4, bottom: 4 }}
              >
                <CartesianGrid strokeDasharray="2 4" stroke={GRID_COLOR} horizontal={false} />
                <XAxis
                  type="number"
                  tick={AXIS_STYLE}
                  axisLine={{ stroke: GRID_COLOR }}
                  tickLine={false}
                  allowDecimals={false}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  tick={{ ...AXIS_STYLE, fontSize: 9.5 }}
                  axisLine={false}
                  tickLine={false}
                  width={124}
                />
                <Tooltip content={<DomainTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                <Bar dataKey="count" barSize={12} radius={[0, 1, 1, 0]}>
                  {topDomainsData.map((entry) => (
                    <Cell
                      key={entry.fullDomain}
                      fill={entry.risk >= 80 ? SEVERITY_COLORS.CRITICAL : entry.risk >= 55 ? SEVERITY_COLORS.HIGH : SEVERITY_COLORS.MEDIUM}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}

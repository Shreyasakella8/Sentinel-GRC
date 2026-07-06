import React, { useState, useEffect } from 'react';
import { dashboardAPI } from '../utils/api';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { AlertTriangle, Shield, TrendingUp, Activity, Zap, Clock, ChevronRight, RefreshCw } from 'lucide-react';

const PageHeader = ({ title, subtitle, action }) => (
  <div style={{ padding: '28px 32px 0', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
    <div>
      <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22, letterSpacing: '0.02em', color: 'var(--text-primary)' }}>{title}</h1>
      {subtitle && <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4, letterSpacing: '0.05em' }}>{subtitle}</p>}
    </div>
    {action}
  </div>
);

const severityColor = { critical: '#e63946', high: '#f97316', medium: '#f59e0b', low: '#10b981' };

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try {
      const res = await dashboardAPI.getSummary();
      setData(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); const i = setInterval(load, 30000); return () => clearInterval(i); }, []);

  const refresh = () => { setRefreshing(true); load(); };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', flexDirection: 'column', gap: 16 }}>
      <Activity size={32} color="var(--accent-red)" style={{ animation: 'pulse-red 1.5s infinite' }} />
      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '0.1em', fontSize: 12 }}>LOADING INTELLIGENCE...</span>
    </div>
  );

  const c = data?.compliance || {};
  const r = data?.financial_risk || {};
  const trendData = data?.risk_trend || [];
  const topRisks = data?.top_risks || [];
  const threats = data?.recent_threats || [];
  const controls = data?.control_health || [];

  const scoreColor = c.score >= 80 ? 'var(--low)' : c.score >= 60 ? 'var(--medium)' : 'var(--critical)';

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      <PageHeader
        title="Risk Intelligence Dashboard"
        subtitle={`LIVE — Auto-refreshes every 30s — Last update: ${new Date().toLocaleTimeString()}`}
        action={
          <button onClick={refresh} className="btn btn-ghost btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={13} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            Refresh
          </button>
        }
      />

      {/* Top KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, padding: '0 32px', marginBottom: 24 }}>
        <div className="stat-card" style={{ borderColor: r.critical > 0 ? 'rgba(230,57,70,0.4)' : 'var(--border)' }}>
          <div className="label">Total Annual Exposure</div>
          <div className="value" style={{ color: 'var(--accent-red)', fontFamily: 'var(--font-mono)' }}>{r.total_ale_formatted || '£0'}</div>
          <div className="sub">{r.open_risks} open risks — FAIR Monte Carlo</div>
        </div>
        <div className="stat-card">
          <div className="label">Compliance Score</div>
          <div className="value" style={{ color: scoreColor, fontFamily: 'var(--font-mono)' }}>{c.score || 0}%</div>
          <div className="sub">{c.passed}/{c.total_controls} controls passing</div>
        </div>
        <div className="stat-card" style={{ borderColor: r.critical > 0 ? 'rgba(230,57,70,0.3)' : 'var(--border)' }}>
          <div className="label">Critical Risks</div>
          <div className="value" style={{ color: r.critical > 0 ? 'var(--critical)' : 'var(--low)', fontFamily: 'var(--font-mono)' }}>{r.critical || 0}</div>
          <div className="sub">{r.high || 0} high · {r.escalated || 0} escalated</div>
        </div>
        <div className="stat-card" style={{ borderColor: r.board_approval_needed > 0 ? 'rgba(245,158,11,0.3)' : 'var(--border)' }}>
          <div className="label">Board Actions Required</div>
          <div className="value" style={{ color: r.board_approval_needed > 0 ? 'var(--medium)' : 'var(--low)', fontFamily: 'var(--font-mono)' }}>{r.board_approval_needed || 0}</div>
          <div className="sub">{data?.governance?.overdue_findings || 0} audit findings overdue</div>
        </div>
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, padding: '0 32px', marginBottom: 24 }}>
        {/* Risk trend */}
        <div className="panel">
          <div className="panel-header">
            <h3><TrendingUp size={13} style={{ marginRight: 6, verticalAlign: 'middle' }} />Financial Risk Exposure Trend (30 days)</h3>
          </div>
          <div className="panel-body" style={{ padding: '20px 20px 10px' }}>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={trendData.length > 0 ? trendData : [{ date: 'No data', total_ale_gbp: 0 }]}>
                <defs>
                  <linearGradient id="aleGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e63946" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#e63946" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#4a5568', fontSize: 10, fontFamily: 'Space Mono' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#4a5568', fontSize: 10, fontFamily: 'Space Mono' }} axisLine={false} tickLine={false} tickFormatter={v => `£${(v/1000).toFixed(0)}K`} />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #1e2d45', borderRadius: 6, fontFamily: 'Space Mono', fontSize: 11 }}
                  formatter={v => [`£${(v/1000).toFixed(0)}K`, 'ALE']}
                  labelStyle={{ color: '#8899aa' }}
                />
                <Area type="monotone" dataKey="total_ale_gbp" stroke="#e63946" strokeWidth={2} fill="url(#aleGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Control health bar */}
        <div className="panel">
          <div className="panel-header">
            <h3><Shield size={13} style={{ marginRight: 6, verticalAlign: 'middle' }} />Control Health</h3>
          </div>
          <div className="panel-body" style={{ padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 12 }}>
              <div style={{ position: 'relative', width: 90, height: 90 }}>
                <svg width="90" height="90" viewBox="0 0 90 90">
                  <circle cx="45" cy="45" r="36" fill="none" stroke="var(--border)" strokeWidth="8" />
                  <circle cx="45" cy="45" r="36" fill="none" stroke={scoreColor} strokeWidth="8"
                    strokeDasharray={`${(c.score / 100) * 226} 226`}
                    strokeLinecap="round"
                    transform="rotate(-90 45 45)" />
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: scoreColor }}>{c.score || 0}%</span>
                </div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {controls.slice(0, 6).map(ctrl => (
                <div key={ctrl.control_id} style={{ padding: '6px 8px', background: 'var(--bg-surface)', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: ctrl.passed ? 'var(--low)' : 'var(--critical)', flexShrink: 0 }} />
                  <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ctrl.control_id}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, padding: '0 32px' }}>
        {/* Top risks */}
        <div className="panel">
          <div className="panel-header">
            <h3><AlertTriangle size={13} style={{ marginRight: 6, verticalAlign: 'middle' }} />Top Risks by Financial Exposure</h3>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Ref</th>
                  <th>Risk</th>
                  <th>Severity</th>
                  <th>ALE</th>
                  <th>Exploit %</th>
                </tr>
              </thead>
              <tbody>
                {topRisks.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>No open risks — run a control sweep to generate findings</td></tr>
                ) : topRisks.map(risk => (
                  <tr key={risk.risk_ref}>
                    <td className="mono">{risk.risk_ref}</td>
                    <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {risk.escalated && <span style={{ color: 'var(--critical)', marginRight: 4 }}>⚡</span>}
                      {risk.title}
                    </td>
                    <td><span className={`badge badge-${risk.severity}`}>{risk.severity}</span></td>
                    <td className="mono" style={{ color: 'var(--accent-red)' }}>{risk.ale_formatted}</td>
                    <td className="mono">{risk.exploitation_prob}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Threat feed */}
        <div className="panel">
          <div className="panel-header">
            <h3><Zap size={13} style={{ marginRight: 6, verticalAlign: 'middle' }} />Live Threat Intelligence Feed</h3>
          </div>
          <div>
            {threats.length === 0 ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                No threats ingested — trigger a threat feed refresh
              </div>
            ) : threats.map((t, i) => (
              <div key={i} style={{ padding: '12px 20px', borderBottom: '1px solid rgba(30,45,69,0.5)', display: 'flex', gap: 12 }}>
                <div style={{ paddingTop: 3 }}>
                  {t.is_known_exploited
                    ? <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--critical)' }} className="pulse-red" />
                    : <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--medium)' }} />
                  }
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.external_id}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.title}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                    <span className={`badge badge-${t.severity}`}>{t.severity}</span>
                    {t.is_known_exploited && <span className="badge badge-critical">ACTIVELY EXPLOITED</span>}
                    {t.risk_delta_formatted && t.risk_delta_formatted !== '£0' && (
                      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-red)' }}>+{t.risk_delta_formatted}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

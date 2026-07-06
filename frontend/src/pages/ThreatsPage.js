import React, { useState, useEffect } from 'react';
import { threatsAPI } from '../utils/api';
import { Zap, RefreshCw, AlertTriangle, ExternalLink, Shield } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function ThreatsPage() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState('');

  const load = async () => {
    try {
      const res = await threatsAPI.list({ limit: 100 });
      setThreats(res.data.threats);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await threatsAPI.refresh();
      setTimeout(() => { load(); setRefreshing(false); }, 4000);
    } catch { setRefreshing(false); }
  };

  const filtered = threats.filter(t =>
    !filter ||
    t.external_id?.toLowerCase().includes(filter.toLowerCase()) ||
    t.title?.toLowerCase().includes(filter.toLowerCase()) ||
    (t.affected_products || []).some(p => p.toLowerCase().includes(filter.toLowerCase()))
  );

  const exploited = threats.filter(t => t.is_known_exploited);
  const withOurAssets = threats.filter(t => (t.assets_affected || []).length > 0);
  const totalRiskDelta = threats.reduce((s, t) => s + (t.risk_delta_gbp || 0), 0);
  const fmt = v => !v ? '£0' : v >= 1e6 ? `£${(v/1e6).toFixed(1)}M` : v >= 1000 ? `£${(v/1000).toFixed(0)}K` : `£${Math.round(v)}`;

  // CVSS distribution for chart
  const cvssDistribution = [
    { range: '9-10', count: threats.filter(t => t.cvss_score >= 9).length, color: '#e63946' },
    { range: '7-9', count: threats.filter(t => t.cvss_score >= 7 && t.cvss_score < 9).length, color: '#f97316' },
    { range: '4-7', count: threats.filter(t => t.cvss_score >= 4 && t.cvss_score < 7).length, color: '#f59e0b' },
    { range: '0-4', count: threats.filter(t => t.cvss_score > 0 && t.cvss_score < 4).length, color: '#10b981' },
  ];

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      <div style={{ padding: '28px 32px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22 }}>Threat Intelligence Feed</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
            NVD CVEs · CISA KEV · MITRE ATT&CK · Auto-refreshes every 4 hours
          </p>
        </div>
        <button className="btn btn-danger" onClick={handleRefresh} disabled={refreshing} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <RefreshCw size={13} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
          {refreshing ? 'Refreshing Feeds...' : 'Refresh All Feeds'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, padding: '0 32px', marginBottom: 20 }}>
        {[
          { label: 'Total Threats', value: threats.length, color: 'var(--accent-blue)' },
          { label: 'Actively Exploited', value: exploited.length, color: 'var(--critical)', alert: exploited.length > 0 },
          { label: 'Affect Our Assets', value: withOurAssets.length, color: withOurAssets.length > 0 ? 'var(--high)' : 'var(--low)' },
          { label: 'Risk Exposure Delta', value: fmt(totalRiskDelta), color: 'var(--accent-red)' },
        ].map(s => (
          <div key={s.label} className="stat-card" style={{ borderColor: s.alert ? 'rgba(230,57,70,0.4)' : 'var(--border)' }}>
            <div className="label">{s.label}</div>
            <div className="value" style={{ color: s.color, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16, padding: '0 32px', marginBottom: 20 }}>
        <div>
          {exploited.length > 0 && (
            <div className="alert-strip alert-critical" style={{ marginBottom: 12 }}>
              <AlertTriangle size={14} />
              {exploited.length} CVE(s) are ACTIVELY EXPLOITED in the wild (CISA KEV). Immediate remediation required.
            </div>
          )}
          {withOurAssets.length > 0 && (
            <div className="alert-strip alert-warning" style={{ marginBottom: 12 }}>
              <Zap size={14} />
              {withOurAssets.length} threat(s) affect monitored assets. Risk scores have been automatically updated.
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header"><h3>CVSS Distribution</h3></div>
          <div className="panel-body" style={{ padding: '12px 16px 8px' }}>
            <ResponsiveContainer width="100%" height={100}>
              <BarChart data={cvssDistribution} layout="vertical">
                <XAxis type="number" tick={{ fill: '#4a5568', fontSize: 9, fontFamily: 'Space Mono' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="range" tick={{ fill: '#8899aa', fontSize: 10, fontFamily: 'Space Mono' }} axisLine={false} tickLine={false} width={30} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1e2d45', borderRadius: 6, fontFamily: 'Space Mono', fontSize: 10 }} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                  {cvssDistribution.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div style={{ padding: '0 32px', marginBottom: 12 }}>
        <input
          placeholder="Search by CVE ID, product, or description..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ width: 340, fontSize: 12 }}
        />
      </div>

      <div style={{ padding: '0 32px' }}>
        <div className="panel">
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE / ID</th>
                  <th>Title</th>
                  <th>Source</th>
                  <th>CVSS</th>
                  <th>Severity</th>
                  <th>Affects Our Assets</th>
                  <th>Risk Delta</th>
                  <th>Exploited</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading threat feed...</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
                    No threats found. Click "Refresh All Feeds" to ingest latest CVEs from NVD and CISA.
                  </td></tr>
                ) : filtered.map(t => (
                  <tr key={t.id} style={{ background: t.is_known_exploited ? 'rgba(230,57,70,0.04)' : 'transparent' }}>
                    <td>
                      <div className="mono" style={{ color: 'var(--accent-cyan)', fontSize: 12 }}>{t.external_id}</div>
                    </td>
                    <td style={{ maxWidth: 280 }}>
                      <div style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.title}</div>
                    </td>
                    <td>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: t.source === 'cisa_kev' ? 'var(--critical)' : 'var(--text-muted)', textTransform: 'uppercase' }}>
                        {t.source}
                      </span>
                    </td>
                    <td>
                      {t.cvss_score ? (
                        <span className="mono" style={{
                          fontSize: 13, fontWeight: 700,
                          color: t.cvss_score >= 9 ? 'var(--critical)' : t.cvss_score >= 7 ? 'var(--high)' : t.cvss_score >= 4 ? 'var(--medium)' : 'var(--low)'
                        }}>
                          {t.cvss_score.toFixed(1)}
                        </span>
                      ) : '—'}
                    </td>
                    <td><span className={`badge badge-${t.severity || 'medium'}`}>{t.severity}</span></td>
                    <td>
                      {(t.assets_affected || []).length > 0 ? (
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(t.assets_affected || []).map(a => (
                            <span key={a} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', background: 'rgba(249,115,22,0.1)', color: 'var(--high)', border: '1px solid rgba(249,115,22,0.25)', borderRadius: 3, padding: '1px 5px' }}>{a}</span>
                          ))}
                        </div>
                      ) : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                    </td>
                    <td className="mono" style={{ color: t.risk_delta_gbp > 0 ? 'var(--critical)' : 'var(--text-muted)', fontSize: 12 }}>
                      {t.risk_delta_gbp > 0 ? `+${fmt(t.risk_delta_gbp)}` : '—'}
                    </td>
                    <td>
                      {t.is_known_exploited
                        ? <span className="badge badge-critical" style={{ animation: 'pulse-red 2s infinite' }}>ACTIVE</span>
                        : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                      }
                    </td>
                    <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {t.detected_at ? new Date(t.detected_at).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

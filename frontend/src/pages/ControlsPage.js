import React, { useState, useEffect } from 'react';
import { controlsAPI } from '../utils/api';
import { CheckSquare, XSquare, Play, Clock, ChevronDown, ChevronUp, RefreshCw, AlertCircle } from 'lucide-react';

const categoryColors = {
  access_control: '#8b5cf6',
  network_security: '#06b6d4',
  data_protection: '#10b981',
  logging_monitoring: '#f59e0b',
  vulnerability_management: '#e63946',
};

const categoryLabels = {
  access_control: 'Access Control',
  network_security: 'Network Security',
  data_protection: 'Data Protection',
  logging_monitoring: 'Logging & Monitoring',
  vulnerability_management: 'Vulnerability Mgmt',
};

function ControlRow({ ctrl, onRun }) {
  const [expanded, setExpanded] = useState(false);
  const [history, setHistory] = useState(null);
  const [running, setRunning] = useState(false);

  const loadHistory = async () => {
    if (!history) {
      const res = await controlsAPI.history(ctrl.control_id);
      setHistory(res.data);
    }
  };

  const handleExpand = () => {
    setExpanded(!expanded);
    if (!expanded) loadHistory();
  };

  const handleRun = async (e) => {
    e.stopPropagation();
    setRunning(true);
    try {
      await controlsAPI.runControl(ctrl.control_id);
      setTimeout(() => { onRun(); setRunning(false); }, 3000);
    } catch { setRunning(false); }
  };

  const result = ctrl.latest_result;
  const statusColor = !result ? 'var(--text-muted)'
    : result.passed ? 'var(--low)'
    : result.status === 'warning' ? 'var(--medium)'
    : 'var(--critical)';

  const fmt = v => !v ? '£0' : v >= 1e6 ? `£${(v/1e6).toFixed(1)}M` : v >= 1000 ? `£${(v/1000).toFixed(0)}K` : `£${Math.round(v)}`;

  return (
    <>
      <tr style={{ cursor: 'pointer' }} onClick={handleExpand}>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {!result ? (
              <Clock size={14} color="var(--text-muted)" />
            ) : result.passed ? (
              <CheckSquare size={14} color="var(--low)" />
            ) : (
              <XSquare size={14} color="var(--critical)" />
            )}
            <span className="mono" style={{ color: 'var(--accent-cyan)', fontSize: 12 }}>{ctrl.control_id}</span>
          </div>
        </td>
        <td>
          <div style={{ fontWeight: 500 }}>{ctrl.name}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{ctrl.description?.slice(0, 80)}...</div>
        </td>
        <td>
          <span style={{
            fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 8px', borderRadius: 4,
            background: `${categoryColors[ctrl.category] || '#6b7280'}22`,
            color: categoryColors[ctrl.category] || '#6b7280',
            border: `1px solid ${categoryColors[ctrl.category] || '#6b7280'}44`,
          }}>
            {categoryLabels[ctrl.category] || ctrl.category}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {ctrl.iso27001_clause && <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '1px 5px', borderRadius: 3 }}>ISO {ctrl.iso27001_clause}</span>}
            {ctrl.nist_csf && <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '1px 5px', borderRadius: 3 }}>NIST {ctrl.nist_csf}</span>}
            {ctrl.soc2_criteria && <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '1px 5px', borderRadius: 3 }}>SOC2 {ctrl.soc2_criteria}</span>}
          </div>
        </td>
        <td>
          {!result ? (
            <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>NEVER RUN</span>
          ) : (
            <span className={`badge badge-${result.passed ? 'pass' : result.status === 'warning' ? 'warning' : 'fail'}`}>
              {result.status?.toUpperCase()}
            </span>
          )}
        </td>
        <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {result?.executed_at ? new Date(result.executed_at).toLocaleString() : '—'}
        </td>
        <td>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <button
              className="btn btn-ghost btn-sm"
              onClick={handleRun}
              disabled={running}
              style={{ display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Play size={11} style={{ animation: running ? 'spin 1s linear infinite' : 'none' }} />
              {running ? 'Running...' : 'Run'}
            </button>
            {expanded ? <ChevronUp size={14} color="var(--text-muted)" /> : <ChevronDown size={14} color="var(--text-muted)" />}
          </div>
        </td>
      </tr>

      {expanded && (
        <tr>
          <td colSpan={7} style={{ padding: 0, background: 'var(--bg-surface)' }}>
            <div style={{ padding: '16px 24px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              {/* Finding & remediation */}
              <div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', letterSpacing: '0.1em', marginBottom: 10, textTransform: 'uppercase' }}>
                  Latest Finding
                </div>
                {result ? (
                  <>
                    {result.raw_output && result.raw_output.includes('"simulation"') && (
                      <div style={{
                        background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)',
                        borderRadius: 6, padding: '6px 10px', fontSize: 11, fontFamily: 'var(--font-mono)',
                        color: 'var(--medium)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6
                      }}>
                        <AlertCircle size={12} />
                        SIMULATED RESULT — required OS tooling not present in this container, showing representative data
                      </div>
                    )}
                    <div style={{
                      background: result.passed ? 'rgba(16,185,129,0.08)' : 'rgba(230,57,70,0.08)',
                      border: `1px solid ${result.passed ? 'rgba(16,185,129,0.25)' : 'rgba(230,57,70,0.25)'}`,
                      borderRadius: 6, padding: '12px 14px', fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.7, marginBottom: 12
                    }}>
                      {result.finding}
                    </div>
                    {result.evidence_hash && (
                      <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        Evidence hash: <span style={{ color: 'var(--accent-cyan)' }}>{result.evidence_hash?.slice(0, 24)}...</span>
                      </div>
                    )}
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                      Fine exposure if non-compliant: <span style={{ color: 'var(--high)', fontFamily: 'var(--font-mono)' }}>{fmt(ctrl.fine_exposure_gbp)}</span>
                    </div>
                  </>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No results yet — click Run to execute this control.</div>
                )}
              </div>

              {/* Execution history */}
              <div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', letterSpacing: '0.1em', marginBottom: 10, textTransform: 'uppercase' }}>
                  Execution History {history ? `(${history.pass_rate_percent}% pass rate)` : ''}
                </div>
                {history ? (
                  <div style={{ maxHeight: 180, overflow: 'auto' }}>
                    {history.history.slice(0, 10).map((h, i) => (
                      <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0',
                        borderBottom: '1px solid rgba(30,45,69,0.5)'
                      }}>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: h.passed ? 'var(--low)' : 'var(--critical)', flexShrink: 0 }} />
                        <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', minWidth: 140 }}>
                          {new Date(h.executed_at).toLocaleString()}
                        </span>
                        <span className={`badge badge-${h.passed ? 'pass' : 'fail'}`} style={{ fontSize: 9 }}>{h.status}</span>
                        {h.duration_ms && <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>{h.duration_ms}ms</span>}
                      </div>
                    ))}
                    {history.history.length === 0 && <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No history yet</div>}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Loading...</div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ControlsPage() {
  const [controls, setControls] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [catFilter, setCatFilter] = useState('');
  const [runningAll, setRunningAll] = useState(false);

  const load = async () => {
    try {
      const res = await controlsAPI.list();
      setControls(res.data.controls);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const runAll = async () => {
    setRunningAll(true);
    try {
      await Promise.all(controls.map(c => controlsAPI.runControl(c.control_id)));
      setTimeout(() => { load(); setRunningAll(false); }, 5000);
    } catch { setRunningAll(false); }
  };

  const filtered = controls.filter(c => {
    const matchText = !filter || c.name.toLowerCase().includes(filter.toLowerCase()) || c.control_id.toLowerCase().includes(filter.toLowerCase());
    const matchCat = !catFilter || c.category === catFilter;
    return matchText && matchCat;
  });

  const passed = controls.filter(c => c.latest_result?.passed).length;
  const failed = controls.filter(c => c.latest_result && !c.latest_result.passed).length;
  const never = controls.filter(c => !c.latest_result).length;

  const categories = [...new Set(controls.map(c => c.category))];

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      <div style={{ padding: '28px 32px 0', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22 }}>Continuous Controls Monitor</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
            24/7 automated auditor · {controls.length} controls · Sweeps every 6 hours via Celery
          </p>
        </div>
        <button className="btn btn-danger" onClick={runAll} disabled={runningAll} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Play size={14} style={{ animation: runningAll ? 'spin 1s linear infinite' : 'none' }} />
          {runningAll ? 'Running Full Sweep...' : 'Run Full Sweep Now'}
        </button>
      </div>

      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, padding: '0 32px', marginBottom: 20 }}>
        {[
          { label: 'Total Controls', value: controls.length, color: 'var(--accent-blue)' },
          { label: 'Passing', value: passed, color: 'var(--low)' },
          { label: 'Failing', value: failed, color: 'var(--critical)' },
          { label: 'Never Run', value: never, color: 'var(--text-muted)' },
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="label">{s.label}</div>
            <div className="value" style={{ color: s.color, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{ padding: '0 32px', marginBottom: 16, display: 'flex', gap: 10 }}>
        <input
          placeholder="Search controls..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={{ width: 220, fontSize: 12 }}
        />
        <select value={catFilter} onChange={e => setCatFilter(e.target.value)} style={{ fontSize: 12 }}>
          <option value="">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{categoryLabels[c] || c}</option>)}
        </select>
        <button className="btn btn-ghost btn-sm" onClick={load} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      <div style={{ padding: '0 32px' }}>
        <div className="panel">
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Control ID</th>
                  <th>Control Name & Description</th>
                  <th>Category</th>
                  <th>Framework Mapping</th>
                  <th>Status</th>
                  <th>Last Run</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading controls...</td></tr>
                ) : filtered.map(ctrl => (
                  <ControlRow key={ctrl.control_id} ctrl={ctrl} onRun={load} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

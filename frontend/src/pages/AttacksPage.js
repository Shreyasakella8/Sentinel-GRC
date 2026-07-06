import React, { useState, useEffect, useRef } from 'react';
import { controlsAPI, threatsAPI } from '../utils/api';
import { Crosshair, Shield, AlertTriangle, Zap, Activity, Eye, Lock, Radio } from 'lucide-react';

// MITRE ATT&CK Tactics
const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', short: 'Recon', color: '#6366f1' },
  { id: 'TA0042', name: 'Resource Dev.', short: 'Res Dev', color: '#8b5cf6' },
  { id: 'TA0001', name: 'Initial Access', short: 'Init', color: '#ec4899' },
  { id: 'TA0002', name: 'Execution', short: 'Exec', color: '#ef4444' },
  { id: 'TA0003', name: 'Persistence', short: 'Persist', color: '#f97316' },
  { id: 'TA0004', name: 'Priv. Escalation', short: 'Priv Esc', color: '#f59e0b' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'Def Eva', color: '#10b981' },
  { id: 'TA0006', name: 'Cred. Access', short: 'Creds', color: '#06b6d4' },
  { id: 'TA0007', name: 'Discovery', short: 'Discovery', color: '#3b82f6' },
  { id: 'TA0008', name: 'Lateral Move', short: 'Lateral', color: '#6366f1' },
  { id: 'TA0009', name: 'Collection', short: 'Collect', color: '#8b5cf6' },
  { id: 'TA0011', name: 'C2', short: 'C2', color: '#ec4899' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfil', color: '#ef4444' },
  { id: 'TA0040', name: 'Impact', short: 'Impact', color: '#dc2626' },
];

// MITRE techniques per tactic (sample)
const TECHNIQUES = {
  'TA0001': ['T1190 Exploit Public App','T1133 External Remote Services','T1078 Valid Accounts','T1195 Supply Chain'],
  'TA0002': ['T1059 Command Script','T1203 Exploitation','T1106 Native API','T1053 Scheduled Task'],
  'TA0003': ['T1547 Boot Autostart','T1098 Account Manipulation','T1136 Create Account','T1543 Create Service'],
  'TA0004': ['T1548 Abuse Elevation','T1134 Access Token','T1068 Exploitation','T1055 Process Injection'],
  'TA0005': ['T1562 Impair Defenses','T1070 Indicator Removal','T1036 Masquerading','T1027 Obfuscated Files'],
  'TA0006': ['T1110 Brute Force','T1555 Creds From Store','T1212 Exploitation Creds','T1056 Input Capture'],
  'TA0007': ['T1082 System Info','T1083 File Discovery','T1046 Network Scan','T1135 Network Share'],
  'TA0008': ['T1021 Remote Services','T1210 Exploitation','T1534 Internal Spearphish','T1550 Use Alt Auth'],
  'TA0009': ['T1560 Archive Data','T1115 Clipboard Data','T1530 Cloud Storage','T1213 Data Repositories'],
  'TA0010': ['T1048 Exfil Over Alt','T1041 Exfil C2','T1567 Exfil Web Service','T1052 Exfil Physical'],
  'TA0040': ['T1485 Data Destruction','T1486 Data Encrypted','T1491 Defacement','T1498 Network DoS'],
};

// Cyber Kill Chain stages with control mappings
const KILL_CHAIN = [
  { stage: 1, name: 'Reconnaissance', desc: 'Attacker gathers intelligence', icon: Eye, controls: [], color: '#6366f1' },
  { stage: 2, name: 'Weaponisation', desc: 'Exploit development', icon: Zap, controls: [], color: '#8b5cf6' },
  { stage: 3, name: 'Delivery', desc: 'Attack vector deployment', icon: Radio, controls: ['NS-001','NS-002','NS-003'], color: '#ec4899' },
  { stage: 4, name: 'Exploitation', desc: 'Vulnerability exploitation', icon: AlertTriangle, controls: ['VM-001','VM-002'], color: '#ef4444' },
  { stage: 5, name: 'Installation', desc: 'Malware / persistence', icon: Lock, controls: ['AC-001','AC-002','AC-003'], color: '#f97316' },
  { stage: 6, name: 'C2 Comms', desc: 'Command and control', icon: Activity, controls: ['LM-001','LM-002'], color: '#f59e0b' },
  { stage: 7, name: 'Exfiltration', desc: 'Data theft / impact', icon: Crosshair, controls: ['DP-001','DP-002'], color: '#dc2626' },
];

// Attack sources for the live ticker
const ATTACK_SOURCES = [
  '185.220.101.47', '45.142.212.100', '23.129.64.218', '51.75.144.43',
  '91.108.4.1', '194.165.16.11', '179.43.128.10', '198.98.51.189',
  '162.247.74.27', '212.70.149.168', '77.247.181.165', '176.10.104.240',
];

const ATTACK_TYPES = [
  { type: 'Brute Force SSH', tactic: 'TA0006', technique: 'T1110', severity: 'high' },
  { type: 'SQL Injection Probe', tactic: 'TA0001', technique: 'T1190', severity: 'critical' },
  { type: 'Port Scan — Nmap', tactic: 'TA0007', technique: 'T1046', severity: 'medium' },
  { type: 'Credential Stuffing', tactic: 'TA0006', technique: 'T1110.004', severity: 'high' },
  { type: 'Log4Shell Attempt', tactic: 'TA0001', technique: 'T1190', severity: 'critical' },
  { type: 'RDP Enumeration', tactic: 'TA0007', technique: 'T1046', severity: 'medium' },
  { type: 'DNS Tunneling Detect', tactic: 'TA0011', technique: 'T1071.004', severity: 'high' },
  { type: 'Ransomware Signature', tactic: 'TA0040', technique: 'T1486', severity: 'critical' },
  { type: 'Lateral Move via SMB', tactic: 'TA0008', technique: 'T1021.002', severity: 'high' },
  { type: 'Mimikatz Pattern', tactic: 'TA0006', technique: 'T1003', severity: 'critical' },
  { type: 'Beacon C2 Traffic', tactic: 'TA0011', technique: 'T1071', severity: 'critical' },
  { type: 'PowerShell Exec', tactic: 'TA0002', technique: 'T1059.001', severity: 'high' },
];

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981' };
const STATUS_OPTIONS = ['BLOCKED', 'DETECTED', 'BLOCKED', 'BLOCKED', 'DETECTED', 'ALLOWED'];
const STATUS_COLOR = { BLOCKED: '#10b981', DETECTED: '#f59e0b', ALLOWED: '#ef4444' };

function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function generateAttack(id) {
  const atk = randomItem(ATTACK_TYPES);
  const status = randomItem(STATUS_OPTIONS);
  return {
    id,
    source_ip: randomItem(ATTACK_SOURCES),
    type: atk.type,
    tactic: atk.tactic,
    technique: atk.technique,
    severity: atk.severity,
    target: randomItem(['web-server-01','db-prod-01','auth-gateway','api-svc','admin-portal']),
    status,
    timestamp: new Date().toISOString(),
    country: randomItem(['RU','CN','KP','IR','BR','UA','NL','US']),
  };
}

export default function AttacksPage() {
  const [attacks, setAttacks] = useState(() => Array.from({ length: 12 }, (_, i) => generateAttack(i)));
  const [controls, setControls] = useState([]);
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [paused, setPaused] = useState(false);
  const idRef = useRef(100);
  const intervalRef = useRef(null);

  // Load real control data
  useEffect(() => {
    controlsAPI.list().then(r => setControls(r.data.controls || [])).catch(() => {});
  }, []);

  // Ticker: inject new attack every 1.8s
  useEffect(() => {
    if (paused) return;
    intervalRef.current = setInterval(() => {
      idRef.current++;
      setAttacks(prev => [generateAttack(idRef.current), ...prev.slice(0, 29)]);
    }, 1800);
    return () => clearInterval(intervalRef.current);
  }, [paused]);

  const blocked24h = attacks.filter(a => a.status === 'BLOCKED').length * 47;
  const detected24h = attacks.filter(a => a.status === 'DETECTED').length * 12;
  const allowed24h = attacks.filter(a => a.status === 'ALLOWED').length * 3;
  const criticalCount = attacks.filter(a => a.severity === 'critical').length;

  // Tactic heatmap hits
  const tacticHits = {};
  attacks.forEach(a => { tacticHits[a.tactic] = (tacticHits[a.tactic] || 0) + 1; });

  // Kill chain control status per stage
  const controlMap = {};
  controls.forEach(c => { controlMap[c.control_id] = c; });

  const getStageStatus = (stage) => {
    if (!stage.controls.length) return 'unknown';
    const all = stage.controls.map(cid => controlMap[cid]);
    const withData = all.filter(Boolean);
    if (!withData.length) return 'unknown';
    const failing = withData.filter(c => c.last_status === 'FAIL' || c.last_status === 'fail');
    if (failing.length > 0) return 'breached';
    return 'defended';
  };

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      {/* Header */}
      <div style={{ padding: '28px 32px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Crosshair size={22} color="var(--accent-red)" />
            Live Attack Intelligence
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
            Real-time attack stream · MITRE ATT&amp;CK TTPs · Cyber Kill Chain mapping · Auto-updating every 1.8s
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: paused ? '#6b7280' : 'var(--accent-green)', boxShadow: paused ? 'none' : '0 0 8px var(--accent-green)', animation: paused ? 'none' : 'pulse-green 2s infinite' }} />
            {paused ? 'PAUSED' : 'LIVE'}
          </div>
          <button className={paused ? 'btn btn-primary' : 'btn btn-ghost'} onClick={() => setPaused(p => !p)} style={{ fontSize: 11 }}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, padding: '0 32px', marginBottom: 20 }}>
        {[
          { label: 'Attacks Blocked (24h)', value: blocked24h.toLocaleString(), color: 'var(--low)', icon: Shield },
          { label: 'Active Detections', value: detected24h.toLocaleString(), color: 'var(--medium)', icon: Eye },
          { label: 'Permitted (Review)', value: allowed24h.toLocaleString(), color: 'var(--critical)', icon: AlertTriangle },
          { label: 'Critical Severity', value: criticalCount, color: '#ef4444', icon: Crosshair },
        ].map(s => (
          <div key={s.label} className="stat-card" style={{ position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', top: 12, right: 12, opacity: 0.15 }}>
              <s.icon size={32} color={s.color} />
            </div>
            <div className="label">{s.label}</div>
            <div className="value" style={{ color: s.color, fontFamily: 'var(--font-mono)', fontSize: 26 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Kill Chain + Tactic Heatmap row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, padding: '0 32px', marginBottom: 20 }}>
        {/* Kill Chain */}
        <div className="panel">
          <div className="panel-header"><h3>Cyber Kill Chain — Live Coverage</h3></div>
          <div className="panel-body" style={{ padding: '12px 16px' }}>
            {KILL_CHAIN.map((stage, idx) => {
              const status = getStageStatus(stage);
              const IconComp = stage.icon;
              const recentHits = attacks.filter(a => {
                const tacticForStage = Object.keys(TECHNIQUES)[idx] || '';
                return a.tactic === tacticForStage;
              }).length;
              return (
                <div key={stage.stage} style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '7px 10px',
                  marginBottom: 4, borderRadius: 6, position: 'relative',
                  background: status === 'breached' ? 'rgba(239,68,68,0.06)' : status === 'defended' ? 'rgba(16,185,129,0.04)' : 'transparent',
                  border: `1px solid ${status === 'breached' ? 'rgba(239,68,68,0.2)' : status === 'defended' ? 'rgba(16,185,129,0.15)' : 'var(--border)'}`,
                }}>
                  <div style={{ width: 28, height: 28, borderRadius: 6, background: `${stage.color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <IconComp size={14} color={stage.color} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{stage.stage}. {stage.name}</span>
                      {status === 'breached' && <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', background: 'rgba(239,68,68,0.15)', color: '#ef4444', padding: '1px 5px', borderRadius: 3 }}>CONTROL FAILING</span>}
                      {status === 'defended' && <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', background: 'rgba(16,185,129,0.12)', color: '#10b981', padding: '1px 5px', borderRadius: 3 }}>DEFENDED</span>}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{stage.desc}</div>
                  </div>
                  {stage.controls.length > 0 && (
                    <div style={{ display: 'flex', gap: 3 }}>
                      {stage.controls.map(c => {
                        const ctrl = controlMap[c];
                        const failed = ctrl?.last_status === 'FAIL' || ctrl?.last_status === 'fail';
                        return (
                          <span key={c} style={{ fontSize: 9, fontFamily: 'var(--font-mono)', padding: '1px 5px', borderRadius: 3, background: failed ? 'rgba(239,68,68,0.1)' : 'rgba(99,102,241,0.1)', color: failed ? '#ef4444' : '#818cf8', border: `1px solid ${failed ? 'rgba(239,68,68,0.3)' : 'rgba(99,102,241,0.3)'}` }}>{c}</span>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* MITRE Tactic Heatmap */}
        <div className="panel">
          <div className="panel-header">
            <h3>MITRE ATT&amp;CK Tactic Activity</h3>
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>Click to filter techniques</span>
          </div>
          <div className="panel-body" style={{ padding: '12px 16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 6 }}>
              {TACTICS.map(tac => {
                const hits = tacticHits[tac.id] || 0;
                const intensity = Math.min(hits / 5, 1);
                const isSelected = selectedTactic === tac.id;
                return (
                  <div key={tac.id} onClick={() => setSelectedTactic(isSelected ? null : tac.id)} style={{
                    padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                    background: isSelected ? `${tac.color}22` : hits > 0 ? `${tac.color}${Math.round(intensity * 15).toString(16).padStart(2,'0')}` : 'var(--bg-surface)',
                    border: `1px solid ${isSelected ? tac.color : hits > 0 ? `${tac.color}44` : 'var(--border)'}`,
                    transition: 'all 0.2s',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: hits > 0 ? tac.color : 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{tac.short}</span>
                      <span style={{ fontSize: 12, fontWeight: 800, color: hits > 0 ? tac.color : 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{hits}</span>
                    </div>
                    <div style={{ marginTop: 4, height: 3, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
                      <div style={{ width: `${intensity * 100}%`, height: '100%', background: tac.color, transition: 'width 0.5s', borderRadius: 2 }} />
                    </div>
                  </div>
                );
              })}
            </div>
            {/* Techniques for selected tactic */}
            {selectedTactic && TECHNIQUES[selectedTactic] && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--bg-surface)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 6 }}>TECHNIQUES OBSERVED</div>
                {TECHNIQUES[selectedTactic].map(t => (
                  <div key={t} style={{ fontSize: 11, color: 'var(--text-secondary)', padding: '2px 0', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 5, height: 5, borderRadius: '50%', background: TACTICS.find(x => x.id === selectedTactic)?.color || '#6b7280', flexShrink: 0 }} />
                    {t}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Live Attack Feed */}
      <div style={{ padding: '0 32px' }}>
        <div className="panel">
          <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3>Live Attack Stream</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', animation: 'pulse-red 1.5s infinite' }} />
              REAL-TIME · {attacks.length} events buffered
            </div>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Country</th>
                  <th>Attack Type</th>
                  <th>MITRE Technique</th>
                  <th>Target</th>
                  <th>Severity</th>
                  <th>Disposition</th>
                </tr>
              </thead>
              <tbody>
                {attacks.map((a, idx) => (
                  <tr key={a.id} style={{
                    opacity: Math.max(0.4, 1 - idx * 0.025),
                    background: idx === 0 ? 'rgba(239,68,68,0.04)' : 'transparent',
                    transition: 'opacity 0.3s',
                  }}>
                    <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>{a.source_ip}</td>
                    <td style={{ fontSize: 12 }}>
                      <span style={{ fontSize: 14 }}>{({'RU':'🇷🇺','CN':'🇨🇳','KP':'🇰🇵','IR':'🇮🇷','BR':'🇧🇷','UA':'🇺🇦','NL':'🇳🇱','US':'🇺🇸'})[a.country] || '🌐'}</span>
                    </td>
                    <td style={{ fontSize: 12, fontWeight: 500 }}>{a.type}</td>
                    <td className="mono" style={{ fontSize: 10, color: '#818cf8' }}>{a.technique}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{a.target}</td>
                    <td>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 4, textTransform: 'uppercase', background: `${SEV_COLOR[a.severity]}22`, color: SEV_COLOR[a.severity], border: `1px solid ${SEV_COLOR[a.severity]}44` }}>
                        {a.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', padding: '2px 8px', borderRadius: 4, fontWeight: 700, background: `${STATUS_COLOR[a.status]}18`, color: STATUS_COLOR[a.status], border: `1px solid ${STATUS_COLOR[a.status]}33` }}>
                        {a.status}
                      </span>
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

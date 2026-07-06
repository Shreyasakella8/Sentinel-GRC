import React, { useState, useEffect } from 'react';
import { risksAPI } from '../utils/api';
import { AlertTriangle, Plus, ChevronDown, ChevronUp, TrendingUp, RefreshCw, X } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';

const severityColor = { critical: '#e63946', high: '#f97316', medium: '#f59e0b', low: '#10b981' };

function CreateRiskModal({ onClose, onCreated }) {
  const [form, setForm] = useState({
    title: '', description: '', category: 'cyber',
    asset_type: 'server', data_sensitivity: 'internal',
    threat_event_frequency: 2.0, vulnerability_probability: 0.4,
    primary_loss_magnitude_gbp: 250000, secondary_loss_magnitude_gbp: 75000,
    regulatory_fine_exposure_gbp: 0,
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      const res = await risksAPI.create({ ...form,
        threat_event_frequency: parseFloat(form.threat_event_frequency),
        vulnerability_probability: parseFloat(form.vulnerability_probability),
        primary_loss_magnitude_gbp: parseFloat(form.primary_loss_magnitude_gbp),
        secondary_loss_magnitude_gbp: parseFloat(form.secondary_loss_magnitude_gbp),
        regulatory_fine_exposure_gbp: parseFloat(form.regulatory_fine_exposure_gbp),
      });
      setResult(res.data);
    } catch(e) {
      setError(e.response?.data?.detail || 'Failed to create risk');
    } finally { setLoading(false); }
  };

  const fmt = v => v >= 1e6 ? `£${(v/1e6).toFixed(1)}M` : v >= 1000 ? `£${(v/1000).toFixed(0)}K` : `£${v}`;

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.7)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000 }}>
      <div style={{ width:640, maxHeight:'90vh', overflow:'auto', background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:12 }}>
        <div style={{ padding:'20px 24px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div>
            <h2 style={{ fontSize:16, fontWeight:700 }}>New Risk — FAIR Quantitative Assessment</h2>
            <p style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginTop:2 }}>Monte Carlo simulation runs automatically on submit</p>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--text-muted)' }}><X size={18}/></button>
        </div>

        {result ? (
          <div style={{ padding:24 }}>
            <div style={{ marginBottom:16 }} className="alert-strip alert-success">
              ✓ Risk {result.risk_ref} created — FAIR simulation complete ({result.monte_carlo_iterations?.toLocaleString()} iterations)
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12, marginBottom:16 }}>
              {[
                { label:'ALE (Mean)', value: fmt(result.ale_mean_gbp), color:'var(--accent-red)' },
                { label:'ALE (90th %ile)', value: fmt(result.ale_90th_gbp), color:'var(--high)' },
                { label:'Exploit Prob 12m', value: `${Math.round(result.exploitation_probability_12m*100)}%`, color:'var(--medium)' },
              ].map(s => (
                <div key={s.label} style={{ background:'var(--bg-surface)', borderRadius:8, padding:'14px 16px', textAlign:'center' }}>
                  <div style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>{s.label}</div>
                  <div style={{ fontSize:22, fontWeight:800, fontFamily:'var(--font-mono)', color:s.color }}>{s.value}</div>
                </div>
              ))}
            </div>
            <div style={{ background:'var(--bg-surface)', borderRadius:8, padding:16, fontSize:13, color:'var(--text-secondary)', lineHeight:1.7, fontStyle:'italic', marginBottom:16 }}>
              "{result.narrative}"
            </div>
            {result.loss_exceedance_curve && (
              <div style={{ marginBottom:16 }}>
                <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.08em' }}>Loss Exceedance Curve</div>
                <ResponsiveContainer width="100%" height={140}>
                  <AreaChart data={result.loss_exceedance_curve}>
                    <defs>
                      <linearGradient id="lecGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#e63946" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#e63946" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="loss_gbp" tick={{fill:'#4a5568',fontSize:9,fontFamily:'Space Mono'}} tickFormatter={v=>fmt(v)} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:'#4a5568',fontSize:9,fontFamily:'Space Mono'}} axisLine={false} tickLine={false} tickFormatter={v=>`${Math.round(v*100)}%`}/>
                    <Tooltip contentStyle={{background:'#111827',border:'1px solid #1e2d45',borderRadius:6,fontFamily:'Space Mono',fontSize:10}}
                      formatter={(v,n,p)=>[`${Math.round(v*100)}%`,`P(loss > ${fmt(p.payload.loss_gbp)})`]}/>
                    <Area type="monotone" dataKey="probability" stroke="#e63946" strokeWidth={2} fill="url(#lecGrad)"/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
            <div style={{ display:'flex', gap:8 }}>
              <button className="btn btn-primary" onClick={()=>{onCreated(); onClose();}}>View Risk Register</button>
              <button className="btn btn-ghost" onClick={()=>setResult(null)}>Add Another Risk</button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ padding:24 }}>
            {error && <div className="alert-strip alert-critical" style={{ marginBottom:16 }}>{error}</div>}
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:16 }}>
              <div style={{ gridColumn:'1/-1' }}>
                <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.08em' }}>Risk Title *</label>
                <input required value={form.title} onChange={e=>setForm({...form,title:e.target.value})} style={{width:'100%'}} placeholder="e.g. Unpatched PostgreSQL exposes PII database"/>
              </div>
              <div style={{ gridColumn:'1/-1' }}>
                <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.08em' }}>Description</label>
                <textarea value={form.description} onChange={e=>setForm({...form,description:e.target.value})} rows={2} style={{width:'100%', resize:'vertical'}} placeholder="Detailed description of the risk scenario..."/>
              </div>
              {[
                { key:'category', label:'Category', type:'select', options:['cyber','operational','compliance','third_party'] },
                { key:'asset_type', label:'Asset Type', type:'select', options:['server','database','application','network','data','cloud_service','endpoint'] },
                { key:'data_sensitivity', label:'Data Sensitivity', type:'select', options:['public','internal','confidential','restricted'] },
              ].map(f => (
                <div key={f.key}>
                  <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.08em' }}>{f.label}</label>
                  <select value={form[f.key]} onChange={e=>setForm({...form,[f.key]:e.target.value})} style={{width:'100%'}}>
                    {f.options.map(o => <option key={o} value={o}>{o.replace('_',' ')}</option>)}
                  </select>
                </div>
              ))}
            </div>

            <div style={{ background:'var(--bg-surface)', borderRadius:8, padding:16, marginBottom:16 }}>
              <div style={{ fontSize:12, fontWeight:700, color:'var(--accent-cyan)', fontFamily:'var(--font-mono)', marginBottom:12, letterSpacing:'0.05em' }}>
                FAIR RISK PARAMETERS
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                {[
                  { key:'threat_event_frequency', label:'Threat Event Frequency (per year)', hint:'How often a threat actor attempts this vector (e.g. 2 = twice/year)' },
                  { key:'vulnerability_probability', label:'Vulnerability Probability (0–1)', hint:'Probability a threat succeeds if attempted (e.g. 0.4 = 40%)' },
                  { key:'primary_loss_magnitude_gbp', label:'Primary Loss Magnitude (£)', hint:'Direct financial loss from a successful attack' },
                  { key:'secondary_loss_magnitude_gbp', label:'Secondary Loss Magnitude (£)', hint:'Reputational + regulatory costs' },
                  { key:'regulatory_fine_exposure_gbp', label:'Regulatory Fine Exposure (£)', hint:'Maximum GDPR/FCA fine exposure (UK GDPR max: £17.5M)' },
                ].map(f => (
                  <div key={f.key}>
                    <label style={{ display:'block', fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.08em' }}>{f.label}</label>
                    <input type="number" step="any" required value={form[f.key]} onChange={e=>setForm({...form,[f.key]:e.target.value})} style={{width:'100%'}}/>
                    <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:3 }}>{f.hint}</div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display:'flex', gap:8 }}>
              <button type="submit" disabled={loading} className="btn btn-primary">
                {loading ? 'Running Monte Carlo simulation...' : 'Run FAIR Assessment & Create Risk'}
              </button>
              <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export default function RisksPage() {
  const [risks, setRisks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const [filter, setFilter] = useState({ status: '', severity: '' });

  const load = async () => {
    try {
      const res = await risksAPI.list(filter);
      setRisks(res.data.risks);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [filter]);

  const totalALE = risks.reduce((s, r) => s + (r.ale_gbp || 0), 0);
  const fmt = v => v >= 1e6 ? `£${(v/1e6).toFixed(1)}M` : v >= 1000 ? `£${(v/1000).toFixed(0)}K` : `£${Math.round(v)}`;

  return (
    <div className="fade-in" style={{ paddingBottom:40 }}>
      {showCreate && <CreateRiskModal onClose={()=>setShowCreate(false)} onCreated={load}/>}

      <div style={{ padding:'28px 32px 0', display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <h1 style={{ fontFamily:'var(--font-display)', fontWeight:800, fontSize:22 }}>Risk Register</h1>
          <p style={{ color:'var(--text-muted)', fontSize:12, fontFamily:'var(--font-mono)', marginTop:4 }}>
            FAIR Quantitative Risk Assessment · {risks.length} risks · Total ALE: <span style={{ color:'var(--accent-red)', fontWeight:700 }}>{fmt(totalALE)}</span>
          </p>
        </div>
        <button className="btn btn-primary" onClick={()=>setShowCreate(true)}>
          <Plus size={14}/> New Risk Assessment
        </button>
      </div>

      {/* Summary strip */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, padding:'0 32px', marginBottom:20 }}>
        {['critical','high','medium','low'].map(sev => {
          const count = risks.filter(r=>r.severity===sev).length;
          const ale = risks.filter(r=>r.severity===sev).reduce((s,r)=>s+(r.ale_gbp||0),0);
          return (
            <div key={sev} style={{ background:'var(--bg-card)', border:`1px solid ${severityColor[sev]}33`, borderRadius:8, padding:'12px 16px', cursor:'pointer' }}
              onClick={()=>setFilter(f=>({...f, severity: f.severity===sev?'':sev}))}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                <span className={`badge badge-${sev}`}>{sev}</span>
                <span style={{ fontFamily:'var(--font-mono)', fontWeight:800, fontSize:18, color:severityColor[sev] }}>{count}</span>
              </div>
              <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginTop:6 }}>{fmt(ale)} exposure</div>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div style={{ padding:'0 32px', marginBottom:16, display:'flex', gap:10 }}>
        <select value={filter.status} onChange={e=>setFilter(f=>({...f,status:e.target.value}))} style={{ fontSize:12 }}>
          <option value="">All Statuses</option>
          {['open','under_treatment','accepted','transferred','closed'].map(s=><option key={s} value={s}>{s.replace('_',' ')}</option>)}
        </select>
        <select value={filter.severity} onChange={e=>setFilter(f=>({...f,severity:e.target.value}))} style={{ fontSize:12 }}>
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        {(filter.status||filter.severity) && (
          <button className="btn btn-ghost btn-sm" onClick={()=>setFilter({status:'',severity:''})}>
            <X size={12}/> Clear filters
          </button>
        )}
      </div>

      {/* Risk table */}
      <div style={{ padding:'0 32px' }}>
        <div className="panel">
          <div style={{ overflowX:'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Ref</th>
                  <th>Risk Title</th>
                  <th>Severity</th>
                  <th>ALE (Mean)</th>
                  <th>ALE (90th %ile)</th>
                  <th>Exploit Prob.</th>
                  <th>Treatment</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={9} style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>Loading risks...</td></tr>
                ) : risks.length === 0 ? (
                  <tr><td colSpan={9} style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>
                    No risks found. Run a control sweep or create risks manually.
                  </td></tr>
                ) : risks.map(risk => (
                  <React.Fragment key={risk.id}>
                    <tr style={{ cursor:'pointer' }} onClick={()=>setExpanded(expanded===risk.id?null:risk.id)}>
                      <td className="mono" style={{ color:'var(--accent-cyan)' }}>{risk.risk_ref}</td>
                      <td>
                        {risk.escalated && <span title="Escalated" style={{ color:'var(--critical)', marginRight:5 }}>⚡</span>}
                        {risk.board_approval_needed && <span title="Board approval needed" style={{ color:'var(--medium)', marginRight:5 }}>⚠</span>}
                        <span style={{ fontSize:13 }}>{risk.title}</span>
                        {risk.linked_cve && <span className="mono" style={{ marginLeft:6, fontSize:10, color:'var(--accent-blue)', background:'rgba(59,130,246,0.1)', padding:'1px 5px', borderRadius:3 }}>{risk.linked_cve}</span>}
                      </td>
                      <td><span className={`badge badge-${risk.severity}`}>{risk.severity}</span></td>
                      <td className="mono" style={{ color:'var(--accent-red)', fontWeight:700 }}>{risk.ale_formatted}</td>
                      <td className="mono" style={{ color:'var(--high)' }}>{risk.ale_90th_formatted}</td>
                      <td className="mono">{risk.exploitation_probability_12m ? `${Math.round(risk.exploitation_probability_12m*100)}%` : '—'}</td>
                      <td><span style={{ fontSize:12, color:'var(--text-secondary)', textTransform:'capitalize' }}>{risk.treatment || '—'}</span></td>
                      <td><span style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', textTransform:'capitalize' }}>{risk.status?.replace('_',' ')}</span></td>
                      <td style={{ color:'var(--text-muted)' }}>{expanded===risk.id ? <ChevronUp size={14}/> : <ChevronDown size={14}/>}</td>
                    </tr>
                    {expanded === risk.id && (
                      <tr>
                        <td colSpan={9} style={{ padding:0, background:'var(--bg-surface)' }}>
                          <RiskDetail riskId={risk.id} onUpdate={load}/>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function RiskDetail({ riskId, onUpdate }) {
  const [detail, setDetail] = useState(null);
  const [treatment, setTreatment] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    risksAPI.get(riskId).then(r => {
      setDetail(r.data);
      setTreatment(r.data.risk?.treatment || '');
    });
  }, [riskId]);

  if (!detail) return <div style={{ padding:20, fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-muted)' }}>Loading detail...</div>;

  const { risk, score_history } = detail;
  const fmt = v => !v ? '£0' : v >= 1e6 ? `£${(v/1e6).toFixed(1)}M` : v >= 1000 ? `£${(v/1000).toFixed(0)}K` : `£${Math.round(v)}`;

  const handleTreatmentUpdate = async () => {
    setSaving(true);
    try {
      await risksAPI.update(riskId, { treatment, status: treatment === 'accept' ? 'accepted' : 'under_treatment' });
      onUpdate();
    } finally { setSaving(false); }
  };

  return (
    <div style={{ padding:'20px 24px', display:'grid', gridTemplateColumns:'1fr 1fr', gap:20 }}>
      {/* FAIR details */}
      <div>
        <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--accent-cyan)', letterSpacing:'0.1em', marginBottom:12, textTransform:'uppercase' }}>
          FAIR Risk Analysis
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:8, marginBottom:16 }}>
          {[
            { label:'ALE Mean', value:fmt(risk.ale_mean_gbp), color:'var(--accent-red)' },
            { label:'ALE 10th %ile', value:fmt(risk.ale_10th_gbp), color:'var(--low)' },
            { label:'ALE 90th %ile', value:fmt(risk.ale_90th_gbp), color:'var(--high)' },
            { label:'TEF/year', value:risk.threat_event_frequency?.toFixed(1), color:'var(--text-primary)' },
            { label:'Vuln Prob', value:`${Math.round((risk.vulnerability_probability||0)*100)}%`, color:'var(--text-primary)' },
            { label:'Exploit 12m', value:`${Math.round((risk.exploitation_probability_12m||0)*100)}%`, color:'var(--medium)' },
          ].map(s => (
            <div key={s.label} style={{ background:'var(--bg-card)', borderRadius:6, padding:'8px 10px' }}>
              <div style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:3 }}>{s.label}</div>
              <div style={{ fontSize:15, fontWeight:700, fontFamily:'var(--font-mono)', color:s.color }}>{s.value}</div>
            </div>
          ))}
        </div>

        {risk.description && (
          <div style={{ fontSize:13, color:'var(--text-secondary)', lineHeight:1.7, marginBottom:12 }}>{risk.description}</div>
        )}

        <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:12 }}>
          {(risk.frameworks_impacted||[]).map(f => (
            <span key={f} style={{ fontSize:10, fontFamily:'var(--font-mono)', background:'rgba(59,130,246,0.1)', color:'var(--accent-blue)', border:'1px solid rgba(59,130,246,0.2)', borderRadius:3, padding:'2px 6px' }}>{f}</span>
          ))}
        </div>

        {/* Treatment */}
        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          <select value={treatment} onChange={e=>setTreatment(e.target.value)} style={{ fontSize:12, flex:1 }}>
            <option value="">-- Select Treatment --</option>
            {['mitigate','accept','transfer','avoid'].map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>)}
          </select>
          <button className="btn btn-primary btn-sm" onClick={handleTreatmentUpdate} disabled={!treatment||saving}>
            {saving ? 'Saving...' : 'Apply'}
          </button>
        </div>
      </div>

      {/* Score history chart */}
      <div>
        <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--accent-cyan)', letterSpacing:'0.1em', marginBottom:12, textTransform:'uppercase' }}>
          ALE Trend History
        </div>
        {score_history.length > 0 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={score_history}>
              <defs>
                <linearGradient id={`riskGrad${riskId}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#e63946" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#e63946" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{fill:'#4a5568',fontSize:9,fontFamily:'Space Mono'}} axisLine={false} tickLine={false}
                tickFormatter={v=>v?.slice(0,10)}/>
              <YAxis tick={{fill:'#4a5568',fontSize:9,fontFamily:'Space Mono'}} axisLine={false} tickLine={false}
                tickFormatter={v=>fmt(v)}/>
              <Tooltip contentStyle={{background:'#111827',border:'1px solid #1e2d45',borderRadius:6,fontFamily:'Space Mono',fontSize:10}}
                formatter={v=>[fmt(v),'ALE']} labelFormatter={l=>l?.slice(0,10)}/>
              <Area type="monotone" dataKey="ale_gbp" stroke="#e63946" strokeWidth={2} fill={`url(#riskGrad${riskId})`}/>
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ height:160, display:'flex', alignItems:'center', justifyContent:'center', color:'var(--text-muted)', fontSize:12, fontFamily:'var(--font-mono)' }}>
            No historical data yet
          </div>
        )}
        <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:8, fontStyle:'italic' }}>
          Source: {risk.source} {risk.linked_cve ? `· ${risk.linked_cve}` : ''} · Last calculated: {risk.created_at?.slice(0,10)}
        </div>
      </div>
    </div>
  );
}

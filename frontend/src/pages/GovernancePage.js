import React, { useState, useEffect } from 'react';
import { governanceAPI } from '../utils/api';
import { BookOpen, Plus, ChevronRight, CheckCircle, Clock, AlertCircle, X } from 'lucide-react';

const POLICY_STATES = ['draft', 'legal_review', 'ciso_approval', 'published', 'scheduled_review', 'retired'];
const POLICY_STATE_COLORS = {
  draft: '#6b7280', legal_review: '#f59e0b', ciso_approval: '#8b5cf6',
  published: '#10b981', scheduled_review: '#06b6d4', retired: '#4a5568',
};
const POLICY_TRANSITIONS = {
  draft: ['legal_review'],
  legal_review: ['ciso_approval', 'draft'],
  ciso_approval: ['published', 'legal_review'],
  published: ['scheduled_review'],
  scheduled_review: ['draft', 'retired'],
  retired: [],
};

function CreatePolicyModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', category: 'information_security', description: '', content: '' });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await governanceAPI.createPolicy(form);
      onCreated();
      onClose();
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.7)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000 }}>
      <div style={{ width:560, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:12 }}>
        <div style={{ padding:'20px 24px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <h2 style={{ fontSize:16, fontWeight:700 }}>Create Policy</h2>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--text-muted)' }}><X size={18}/></button>
        </div>
        <form onSubmit={handleSubmit} style={{ padding:24 }}>
          <div style={{ marginBottom:14 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase' }}>Policy Title *</label>
            <input required value={form.title} onChange={e=>setForm({...form,title:e.target.value})} style={{width:'100%'}} placeholder="e.g. Password Management Policy"/>
          </div>
          <div style={{ marginBottom:14 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase' }}>Category</label>
            <select value={form.category} onChange={e=>setForm({...form,category:e.target.value})} style={{width:'100%'}}>
              {['information_security','data_protection','access_control','incident_response','business_continuity'].map(c => (
                <option key={c} value={c}>{c.replace(/_/g,' ')}</option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom:14 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase' }}>Description</label>
            <textarea value={form.description} onChange={e=>setForm({...form,description:e.target.value})} rows={2} style={{width:'100%',resize:'vertical'}}/>
          </div>
          <div style={{ marginBottom:20 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase' }}>Policy Content</label>
            <textarea value={form.content} onChange={e=>setForm({...form,content:e.target.value})} rows={5} style={{width:'100%',resize:'vertical'}} placeholder="Full policy text..."/>
          </div>
          <div style={{ display:'flex', gap:8 }}>
            <button type="submit" disabled={loading} className="btn btn-primary">{loading ? 'Creating...' : 'Create Policy (Draft)'}</button>
            <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function PolicyCard({ policy, onUpdate }) {
  const [transitioning, setTransitioning] = useState(false);
  const nextStates = POLICY_TRANSITIONS[policy.status] || [];

  const handleTransition = async (toStatus) => {
    setTransitioning(true);
    try {
      await governanceAPI.transitionPolicy(policy.id, { to_status: toStatus, comment: `Transitioned via platform` });
      onUpdate();
    } catch(e) { alert(e.response?.data?.detail || 'Transition failed'); }
    finally { setTransitioning(false); }
  };

  const stateIndex = POLICY_STATES.indexOf(policy.status);

  return (
    <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:10, padding:'18px 20px', marginBottom:12 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:12 }}>
        <div>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
            <span className="mono" style={{ fontSize:11, color:'var(--accent-cyan)' }}>{policy.policy_ref}</span>
            <span style={{
              fontSize:10, fontFamily:'var(--font-mono)', padding:'2px 8px', borderRadius:4, textTransform:'uppercase',
              background:`${POLICY_STATE_COLORS[policy.status]}22`,
              color: POLICY_STATE_COLORS[policy.status],
              border:`1px solid ${POLICY_STATE_COLORS[policy.status]}44`
            }}>
              {policy.status?.replace(/_/g,' ')}
            </span>
          </div>
          <div style={{ fontWeight:600, fontSize:14 }}>{policy.title}</div>
          <div style={{ fontSize:12, color:'var(--text-muted)', marginTop:2 }}>{policy.category?.replace(/_/g,' ')}</div>
        </div>
        <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', textAlign:'right' }}>
          v{policy.version}<br/>
          {policy.created_at?.slice(0,10)}
        </div>
      </div>

      {/* State machine progress */}
      <div style={{ display:'flex', alignItems:'center', gap:0, marginBottom:14, overflowX:'auto', paddingBottom:4 }}>
        {POLICY_STATES.slice(0,-1).map((state, i) => (
          <React.Fragment key={state}>
            <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:3 }}>
              <div style={{
                width:24, height:24, borderRadius:'50%', display:'flex', alignItems:'center', justifyContent:'center',
                background: i < stateIndex ? 'var(--low)' : i === stateIndex ? POLICY_STATE_COLORS[policy.status] : 'var(--border)',
                flexShrink:0,
              }}>
                {i < stateIndex ? <CheckCircle size={12} color="white"/> : <span style={{ fontSize:9, color:'white', fontWeight:700 }}>{i+1}</span>}
              </div>
              <span style={{ fontSize:8, fontFamily:'var(--font-mono)', color: i === stateIndex ? POLICY_STATE_COLORS[policy.status] : 'var(--text-muted)', whiteSpace:'nowrap', textTransform:'uppercase' }}>
                {state.replace(/_/g,' ')}
              </span>
            </div>
            {i < POLICY_STATES.length - 2 && (
              <div style={{ height:2, flex:1, minWidth:16, background: i < stateIndex ? 'var(--low)' : 'var(--border)', margin:'0 4px', marginBottom:14 }}/>
            )}
          </React.Fragment>
        ))}
      </div>

      {nextStates.length > 0 && (
        <div style={{ display:'flex', gap:6 }}>
          {nextStates.map(next => (
            <button
              key={next}
              className="btn btn-ghost btn-sm"
              disabled={transitioning}
              onClick={() => handleTransition(next)}
              style={{ fontSize:11, color: POLICY_STATE_COLORS[next] || 'var(--text-secondary)', borderColor: `${POLICY_STATE_COLORS[next]}44` || 'var(--border)' }}
            >
              <ChevronRight size={11}/>
              Move to: {next.replace(/_/g,' ')}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function GovernancePage() {
  const [policies, setPolicies] = useState([]);
  const [findings, setFindings] = useState([]);
  const [audits, setAudits] = useState([]);
  const [tab, setTab] = useState('policies');
  const [showCreate, setShowCreate] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [p, f, a] = await Promise.all([
        governanceAPI.listPolicies(),
        governanceAPI.listFindings(),
        governanceAPI.listAudits(),
      ]);
      setPolicies(p.data.policies);
      setFindings(f.data.findings);
      setAudits(a.data.audits);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const tabs = [
    { id:'policies', label:`Policies (${policies.length})` },
    { id:'audits', label:`Audits (${audits.length})` },
    { id:'findings', label:`Findings (${findings.length})` },
  ];

  return (
    <div className="fade-in" style={{ paddingBottom:40 }}>
      {showCreate && <CreatePolicyModal onClose={()=>setShowCreate(false)} onCreated={load}/>}

      <div style={{ padding:'28px 32px 0', display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:24 }}>
        <div>
          <h1 style={{ fontFamily:'var(--font-display)', fontWeight:800, fontSize:22 }}>Governance Workflow Engine</h1>
          <p style={{ color:'var(--text-muted)', fontSize:12, fontFamily:'var(--font-mono)', marginTop:4 }}>
            Policy lifecycle · Audit management · Segregation of Duties enforcement
          </p>
        </div>
        {tab === 'policies' && (
          <button className="btn btn-primary" onClick={()=>setShowCreate(true)}>
            <Plus size={14}/> New Policy
          </button>
        )}
      </div>

      {/* SoD reminder */}
      <div style={{ padding:'0 32px', marginBottom:20 }}>
        <div className="alert-strip alert-info">
          <AlertCircle size={14}/>
          Segregation of Duties is enforced platform-wide: the person who raises a risk cannot close it. Policy transitions require appropriate role approval.
        </div>
      </div>

      {/* Tabs */}
      <div style={{ padding:'0 32px', marginBottom:20 }}>
        <div style={{ display:'flex', gap:0, borderBottom:'1px solid var(--border)' }}>
          {tabs.map(t => (
            <button key={t.id} onClick={()=>setTab(t.id)} style={{
              background:'none', border:'none', borderBottom: tab===t.id ? '2px solid var(--accent-red)' : '2px solid transparent',
              color: tab===t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              padding:'10px 20px', fontSize:13, fontWeight: tab===t.id ? 700 : 400,
              cursor:'pointer', marginBottom:-1, transition:'all 0.15s'
            }}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ padding:'0 32px' }}>
        {tab === 'policies' && (
          <div>
            {loading ? <div style={{ color:'var(--text-muted)', fontSize:12, fontFamily:'var(--font-mono)' }}>Loading...</div>
            : policies.length === 0 ? (
              <div style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>No policies yet. Create your first policy to begin the governance lifecycle.</div>
            ) : (
              policies.map(p => <PolicyCard key={p.id} policy={p} onUpdate={load}/>)
            )}
          </div>
        )}

        {tab === 'audits' && (
          <div className="panel">
            <div style={{ overflowX:'auto' }}>
              <table className="data-table">
                <thead><tr><th>Ref</th><th>Title</th><th>Framework</th><th>Type</th><th>Status</th><th>Scheduled Start</th><th>Scheduled End</th></tr></thead>
                <tbody>
                  {audits.length === 0 ? (
                    <tr><td colSpan={7} style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>No audits scheduled</td></tr>
                  ) : audits.map(a => (
                    <tr key={a.id}>
                      <td className="mono" style={{ color:'var(--accent-cyan)', fontSize:11 }}>{a.audit_ref}</td>
                      <td>{a.title}</td>
                      <td><span className="mono" style={{ fontSize:11 }}>{a.framework}</span></td>
                      <td><span style={{ fontSize:12, color:'var(--text-secondary)', textTransform:'capitalize' }}>{a.audit_type}</span></td>
                      <td><span style={{ fontSize:11, fontFamily:'var(--font-mono)', textTransform:'capitalize', color: a.status==='complete'?'var(--low)':a.status==='in_progress'?'var(--medium)':'var(--text-muted)' }}>{a.status?.replace(/_/g,' ')}</span></td>
                      <td className="mono" style={{ fontSize:11, color:'var(--text-muted)' }}>{a.scheduled_start?.slice(0,10) || '—'}</td>
                      <td className="mono" style={{ fontSize:11, color:'var(--text-muted)' }}>{a.scheduled_end?.slice(0,10) || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === 'findings' && (
          <div className="panel">
            <div style={{ overflowX:'auto' }}>
              <table className="data-table">
                <thead><tr><th>Ref</th><th>Finding</th><th>Severity</th><th>Status</th><th>SLA Breached</th><th>Due Date</th></tr></thead>
                <tbody>
                  {findings.length === 0 ? (
                    <tr><td colSpan={6} style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>No audit findings</td></tr>
                  ) : findings.map(f => (
                    <tr key={f.id}>
                      <td className="mono" style={{ color:'var(--accent-cyan)', fontSize:11 }}>{f.finding_ref}</td>
                      <td>{f.title}</td>
                      <td><span className={`badge badge-${f.severity || 'medium'}`}>{f.severity || 'medium'}</span></td>
                      <td><span style={{ fontSize:11, fontFamily:'var(--font-mono)', textTransform:'capitalize', color: f.status==='closed'?'var(--low)':'var(--text-muted)' }}>{f.status}</span></td>
                      <td>
                        {f.sla_breached
                          ? <span style={{ color:'var(--critical)', fontFamily:'var(--font-mono)', fontSize:11, fontWeight:700 }}>⚠ BREACHED</span>
                          : <span style={{ color:'var(--low)', fontSize:12 }}>✓ On track</span>
                        }
                      </td>
                      <td className="mono" style={{ fontSize:11, color: f.sla_breached ? 'var(--critical)':'var(--text-muted)' }}>{f.remediation_due?.slice(0,10) || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

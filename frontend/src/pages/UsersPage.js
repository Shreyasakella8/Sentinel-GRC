import React, { useState, useEffect, useCallback } from 'react';
import { usersAPI } from '../utils/api';
import {
  Users, Plus, X, Shield, Search, ChevronDown,
  UserCheck, UserX, Key, Trash2, Edit2, Check,
  AlertTriangle, Lock, Eye, FileText, BarChart2,
  Settings, Layers, BookOpen, Activity
} from 'lucide-react';

// ── Role metadata ─────────────────────────────────────────────────────────────
const ROLE_META = {
  ciso:             { color: '#e63946', label: 'CISO',             desc: 'Full platform access',          bg: 'rgba(230,57,70,0.12)'   },
  board_member:     { color: '#8b5cf6', label: 'Board Member',     desc: 'Executive & financial view',    bg: 'rgba(139,92,246,0.12)'  },
  risk_owner:       { color: '#f59e0b', label: 'Risk Owner',       desc: 'Risks, governance & workflow',  bg: 'rgba(245,158,11,0.12)'  },
  internal_auditor: { color: '#06b6d4', label: 'Internal Auditor', desc: 'Evidence vault & audits',       bg: 'rgba(6,182,212,0.12)'   },
  read_only:        { color: '#6b7280', label: 'Read Only',        desc: 'View dashboards only',          bg: 'rgba(107,114,128,0.12)' },
};

// Module permission matrix — which modules each role can access
const PERMISSION_MODULES = [
  { key: 'dashboard',  icon: <BarChart2 size={11}/>,  label: 'Dashboard'  },
  { key: 'risks',      icon: <AlertTriangle size={11}/>, label: 'Risks'   },
  { key: 'controls',   icon: <Shield size={11}/>,      label: 'Controls'  },
  { key: 'evidence',   icon: <Lock size={11}/>,        label: 'Evidence'  },
  { key: 'governance', icon: <BookOpen size={11}/>,    label: 'Governance'},
  { key: 'reports',    icon: <FileText size={11}/>,    label: 'Reports'   },
  { key: 'threats',    icon: <Activity size={11}/>,    label: 'Threats'   },
  { key: 'users',      icon: <Users size={11}/>,       label: 'Users'     },
  { key: 'ai-security',icon: <Layers size={11}/>,      label: 'AI Guard'  },
];

const ROLE_PERMISSIONS = {
  ciso:             ['dashboard','risks','controls','evidence','governance','reports','threats','users','ai-security'],
  board_member:     ['dashboard','reports'],
  risk_owner:       ['dashboard','risks','governance'],
  internal_auditor: ['dashboard','evidence','controls','reports','ai-security'],
  read_only:        ['dashboard'],
};

// ── Reusable confirm dialog ───────────────────────────────────────────────────
function ConfirmDialog({ title, message, confirmLabel, confirmColor = '#e63946', onConfirm, onClose }) {
  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:2000 }}>
      <div style={{ width:400, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:12, padding:28 }}>
        <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:16 }}>
          <div style={{ width:36, height:36, borderRadius:8, background:`${confirmColor}22`, display:'flex', alignItems:'center', justifyContent:'center' }}>
            <AlertTriangle size={18} color={confirmColor}/>
          </div>
          <h3 style={{ fontWeight:700, fontSize:15 }}>{title}</h3>
        </div>
        <p style={{ fontSize:13, color:'var(--text-secondary)', marginBottom:24, lineHeight:1.6 }}>{message}</p>
        <div style={{ display:'flex', gap:10 }}>
          <button className="btn btn-primary" style={{ background:confirmColor, borderColor:confirmColor }} onClick={onConfirm}>{confirmLabel}</button>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

// ── Create user modal ─────────────────────────────────────────────────────────
function CreateUserModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ email:'', full_name:'', password:'', role:'read_only', department:'' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (form.password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true); setError('');
    try {
      await usersAPI.create(form);
      onCreated();
      onClose();
    } catch(err) {
      setError(err.response?.data?.detail || 'Failed to create user');
    } finally { setLoading(false); }
  };

  const selectedRole = ROLE_META[form.role];

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000 }}>
      <div style={{ width:520, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:14, overflow:'hidden' }}>
        {/* Header */}
        <div style={{ padding:'20px 24px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', background:'var(--bg-surface)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:32, height:32, borderRadius:8, background:'rgba(99,102,241,0.15)', display:'flex', alignItems:'center', justifyContent:'center' }}>
              <Plus size={16} color='#6366f1'/>
            </div>
            <div>
              <h2 style={{ fontSize:15, fontWeight:700 }}>Create User Account</h2>
              <p style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>All fields encrypted · Access logged in audit trail</p>
            </div>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', padding:4, borderRadius:6 }}><X size={18}/></button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding:24 }}>
          {error && (
            <div className="alert-strip alert-critical" style={{ marginBottom:16, display:'flex', alignItems:'center', gap:8 }}>
              <AlertTriangle size={14}/> {error}
            </div>
          )}

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:14 }}>
            {[
              { key:'full_name', label:'Full Name', type:'text', placeholder:'Jane Smith' },
              { key:'email',     label:'Email Address', type:'email', placeholder:'jane@company.com' },
            ].map(f => (
              <div key={f.key}>
                <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.06em' }}>{f.label}</label>
                <input type={f.type} required value={form[f.key]} onChange={e=>setForm({...form,[f.key]:e.target.value})} style={{width:'100%'}} placeholder={f.placeholder}/>
              </div>
            ))}
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:14 }}>
            <div>
              <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.06em' }}>Temporary Password</label>
              <input type="password" required value={form.password} onChange={e=>setForm({...form,password:e.target.value})} style={{width:'100%'}} placeholder="Min 8 characters"/>
            </div>
            <div>
              <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.06em' }}>Department</label>
              <input type="text" value={form.department} onChange={e=>setForm({...form,department:e.target.value})} style={{width:'100%'}} placeholder="e.g. Information Security"/>
            </div>
          </div>

          {/* Role selector */}
          <div style={{ marginBottom:20 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.06em' }}>Role & Permissions</label>
            <select value={form.role} onChange={e=>setForm({...form,role:e.target.value})} style={{width:'100%', marginBottom:10}}>
              {Object.entries(ROLE_META).map(([k,v]) => (
                <option key={k} value={k}>{v.label} — {v.desc}</option>
              ))}
            </select>
            {/* Permission preview */}
            {selectedRole && (
              <div style={{ background:'var(--bg-surface)', borderRadius:8, padding:'10px 12px', border:`1px solid ${selectedRole.color}33` }}>
                <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:selectedRole.color, fontWeight:700, marginBottom:8 }}>
                  ACCESS GRANTED TO:
                </div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
                  {PERMISSION_MODULES.map(mod => {
                    const granted = (ROLE_PERMISSIONS[form.role]||[]).includes(mod.key);
                    return (
                      <span key={mod.key} style={{
                        display:'inline-flex', alignItems:'center', gap:4,
                        fontSize:10, fontFamily:'var(--font-mono)', padding:'3px 7px', borderRadius:4,
                        background: granted ? `${selectedRole.color}1a` : 'rgba(255,255,255,0.04)',
                        color: granted ? selectedRole.color : 'var(--text-muted)',
                        border: `1px solid ${granted ? selectedRole.color+'44' : 'var(--border)'}`,
                        opacity: granted ? 1 : 0.4,
                      }}>
                        {granted ? <Check size={9}/> : <X size={9}/>} {mod.label}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div style={{ display:'flex', gap:10 }}>
            <button type="submit" disabled={loading} className="btn btn-primary" style={{ flex:1 }}>
              {loading ? 'Creating...' : '✓ Create User'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Change role modal ─────────────────────────────────────────────────────────
function ChangeRoleModal({ user, onClose, onDone }) {
  const [role, setRole] = useState(user.role);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (role === user.role) { onClose(); return; }
    setLoading(true); setError('');
    try {
      await usersAPI.changeRole(user.id, role);
      onDone();
      onClose();
    } catch(err) {
      setError(err.response?.data?.detail || 'Failed to change role');
    } finally { setLoading(false); }
  };

  const newRoleMeta = ROLE_META[role];

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1500 }}>
      <div style={{ width:460, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:14, overflow:'hidden' }}>
        <div style={{ padding:'18px 22px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', background:'var(--bg-surface)' }}>
          <div>
            <h3 style={{ fontWeight:700, fontSize:14 }}>Change Role — {user.full_name}</h3>
            <p style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)', marginTop:2 }}>{user.email}</p>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer' }}><X size={16}/></button>
        </div>
        <form onSubmit={handleSubmit} style={{ padding:22 }}>
          {error && <div className="alert-strip alert-critical" style={{ marginBottom:14 }}>{error}</div>}
          <div style={{ marginBottom:16 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>New Role</label>
            <select value={role} onChange={e=>setRole(e.target.value)} style={{width:'100%'}}>
              {Object.entries(ROLE_META).map(([k,v]) => (
                <option key={k} value={k}>{v.label} — {v.desc}</option>
              ))}
            </select>
          </div>
          {newRoleMeta && (
            <div style={{ background:newRoleMeta.bg, border:`1px solid ${newRoleMeta.color}44`, borderRadius:8, padding:'10px 12px', marginBottom:16 }}>
              <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:newRoleMeta.color, fontWeight:700, marginBottom:6 }}>PERMISSIONS AFTER CHANGE:</div>
              <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
                {(ROLE_PERMISSIONS[role]||[]).map(p => (
                  <span key={p} style={{ fontSize:10, fontFamily:'var(--font-mono)', background:`${newRoleMeta.color}22`, color:newRoleMeta.color, border:`1px solid ${newRoleMeta.color}44`, borderRadius:3, padding:'2px 6px' }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div style={{ display:'flex', gap:10 }}>
            <button type="submit" disabled={loading || role === user.role} className="btn btn-primary">
              {loading ? 'Saving...' : 'Apply Role Change'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Reset password modal ──────────────────────────────────────────────────────
function ResetPasswordModal({ user, onClose, onDone }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true); setError('');
    try {
      await usersAPI.resetPassword(user.id, password);
      setSuccess(true);
      setTimeout(() => { onDone(); onClose(); }, 1500);
    } catch(err) {
      setError(err.response?.data?.detail || 'Failed to reset password');
    } finally { setLoading(false); }
  };

  return (
    <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.75)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1500 }}>
      <div style={{ width:420, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:14, overflow:'hidden' }}>
        <div style={{ padding:'18px 22px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', background:'var(--bg-surface)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:10 }}>
            <Key size={16} color='#f59e0b'/>
            <div>
              <h3 style={{ fontWeight:700, fontSize:14 }}>Reset Password</h3>
              <p style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{user.email}</p>
            </div>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer' }}><X size={16}/></button>
        </div>
        <form onSubmit={handleSubmit} style={{ padding:22 }}>
          {error && <div className="alert-strip alert-critical" style={{ marginBottom:14 }}>{error}</div>}
          {success && <div className="alert-strip alert-info" style={{ marginBottom:14 }}>✓ Password reset successfully!</div>}
          <div style={{ marginBottom:16 }}>
            <label style={{ display:'block', fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', marginBottom:6, textTransform:'uppercase' }}>New Password</label>
            <input type="password" required value={password} onChange={e=>setPassword(e.target.value)} style={{width:'100%'}} placeholder="Minimum 8 characters" autoFocus/>
          </div>
          <div className="alert-strip alert-info" style={{ marginBottom:16, fontSize:12 }}>
            <Shield size={13}/> This action is logged in the immutable audit trail.
          </div>
          <div style={{ display:'flex', gap:10 }}>
            <button type="submit" disabled={loading || success} className="btn btn-primary" style={{ background:'#f59e0b', borderColor:'#f59e0b' }}>
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-ghost">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Permission matrix cell ────────────────────────────────────────────────────
function PermCell({ granted, color }) {
  return (
    <div style={{
      width:20, height:20, borderRadius:4, display:'flex', alignItems:'center', justifyContent:'center',
      background: granted ? `${color}22` : 'rgba(255,255,255,0.03)',
      border: `1px solid ${granted ? color+'55' : 'rgba(255,255,255,0.08)'}`,
    }}>
      {granted
        ? <Check size={10} color={color} strokeWidth={2.5}/>
        : <X size={9} color='rgba(255,255,255,0.18)' strokeWidth={2}/>
      }
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function UsersPage() {
  const [users, setUsers]           = useState([]);
  const [loading, setLoading]       = useState(true);
  const [search, setSearch]         = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [showCreate, setShowCreate] = useState(false);
  const [roleModal, setRoleModal]   = useState(null);   // user object
  const [pwdModal, setPwdModal]     = useState(null);   // user object
  const [confirm, setConfirm]       = useState(null);   // { type, user }
  const [toast, setToast]           = useState('');

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(''), 3000);
  };

  const load = useCallback(async () => {
    try {
      const res = await usersAPI.list();
      setUsers(res.data.users);
    } catch(e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDeactivate = async (user) => {
    try {
      await usersAPI.deactivate(user.id);
      showToast(`✓ ${user.full_name} deactivated`);
      load();
    } catch(e) { showToast('✗ ' + (e.response?.data?.detail || 'Failed')); }
    setConfirm(null);
  };

  const handleReactivate = async (user) => {
    try {
      await usersAPI.reactivate(user.id);
      showToast(`✓ ${user.full_name} reactivated`);
      load();
    } catch(e) { showToast('✗ ' + (e.response?.data?.detail || 'Failed')); }
    setConfirm(null);
  };

  const handleDelete = async (user) => {
    try {
      await usersAPI.delete(user.id);
      showToast(`✓ ${user.full_name} deleted`);
      load();
    } catch(e) { showToast('✗ ' + (e.response?.data?.detail || 'Failed')); }
    setConfirm(null);
  };

  // Filter users
  const filtered = users.filter(u => {
    const matchSearch = !search ||
      u.full_name.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      (u.department || '').toLowerCase().includes(search.toLowerCase());
    const matchRole = filterRole === 'all' || u.role === filterRole;
    return matchSearch && matchRole;
  });

  return (
    <div className="fade-in" style={{ paddingBottom:60 }}>

      {/* Toast notification */}
      {toast && (
        <div style={{
          position:'fixed', top:20, right:20, zIndex:9999,
          background:'var(--bg-card)', border:'1px solid var(--border)',
          borderRadius:10, padding:'12px 18px', fontSize:13, fontWeight:500,
          boxShadow:'0 8px 32px rgba(0,0,0,0.4)', display:'flex', alignItems:'center', gap:8
        }}>
          {toast}
        </div>
      )}

      {/* Modals */}
      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} onCreated={load}/>}
      {roleModal   && <ChangeRoleModal user={roleModal} onClose={() => setRoleModal(null)} onDone={() => { load(); showToast('✓ Role updated'); }}/>}
      {pwdModal    && <ResetPasswordModal user={pwdModal} onClose={() => setPwdModal(null)} onDone={() => showToast('✓ Password reset')}/>}

      {confirm?.type === 'deactivate' && (
        <ConfirmDialog
          title="Deactivate Account"
          message={`This will immediately revoke all login access for ${confirm.user.full_name} (${confirm.user.email}). They cannot log in until reactivated.`}
          confirmLabel="Deactivate"
          onConfirm={() => handleDeactivate(confirm.user)}
          onClose={() => setConfirm(null)}
        />
      )}
      {confirm?.type === 'reactivate' && (
        <ConfirmDialog
          title="Reactivate Account"
          message={`Restore login access for ${confirm.user.full_name} (${confirm.user.email}) with their previous role and permissions?`}
          confirmLabel="Reactivate"
          confirmColor="#10b981"
          onConfirm={() => handleReactivate(confirm.user)}
          onClose={() => setConfirm(null)}
        />
      )}
      {confirm?.type === 'delete' && (
        <ConfirmDialog
          title="Permanently Delete User"
          message={`This PERMANENTLY deletes ${confirm.user.full_name}. This cannot be undone. Consider deactivating instead to preserve audit trail linkage.`}
          confirmLabel="Delete Permanently"
          onConfirm={() => handleDelete(confirm.user)}
          onClose={() => setConfirm(null)}
        />
      )}

      {/* Page header */}
      <div style={{ padding:'28px 32px 0', display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:24 }}>
        <div>
          <h1 style={{ fontFamily:'var(--font-display)', fontWeight:800, fontSize:22, marginBottom:4 }}>User Management</h1>
          <p style={{ color:'var(--text-muted)', fontSize:12, fontFamily:'var(--font-mono)' }}>
            5-role RBAC · JWT authentication · bcrypt password hashing · Immutable audit trail
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)} style={{ display:'flex', alignItems:'center', gap:7 }}>
          <Plus size={14}/> New User
        </button>
      </div>

      {/* Role summary cards */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:10, padding:'0 32px', marginBottom:24 }}>
        {Object.entries(ROLE_META).map(([role, meta]) => {
          const count = users.filter(u => u.role === role).length;
          const active = users.filter(u => u.role === role && u.is_active).length;
          return (
            <div
              key={role}
              onClick={() => setFilterRole(filterRole === role ? 'all' : role)}
              style={{
                background: filterRole === role ? meta.bg : 'var(--bg-card)',
                border:`1px solid ${filterRole === role ? meta.color+'66' : 'var(--border)'}`,
                borderRadius:10, padding:'14px 16px', cursor:'pointer',
                transition:'all 0.2s ease',
              }}
            >
              <div style={{ fontSize:10, fontFamily:'var(--font-mono)', color:meta.color, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:6 }}>{meta.label}</div>
              <div style={{ fontSize:26, fontWeight:800, fontFamily:'var(--font-mono)', color:meta.color, lineHeight:1 }}>{count}</div>
              <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:5 }}>{active} active</div>
            </div>
          );
        })}
      </div>

      {/* Search and filters */}
      <div style={{ padding:'0 32px', marginBottom:16, display:'flex', gap:12, alignItems:'center' }}>
        <div style={{ flex:1, position:'relative' }}>
          <Search size={14} style={{ position:'absolute', left:11, top:'50%', transform:'translateY(-50%)', color:'var(--text-muted)' }}/>
          <input
            type="text"
            placeholder="Search by name, email or department…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ width:'100%', paddingLeft:34 }}
          />
        </div>
        <select value={filterRole} onChange={e => setFilterRole(e.target.value)} style={{ width:200 }}>
          <option value="all">All Roles</option>
          {Object.entries(ROLE_META).map(([k,v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <div style={{ fontSize:12, color:'var(--text-muted)', fontFamily:'var(--font-mono)', whiteSpace:'nowrap' }}>
          {filtered.length} of {users.length} users
        </div>
      </div>

      {/* RBAC note */}
      <div style={{ padding:'0 32px', marginBottom:16 }}>
        <div className="alert-strip alert-info" style={{ display:'flex', alignItems:'center', gap:8 }}>
          <Shield size={14}/>
          <span>RBAC enforced on every API endpoint via JWT + role claims. All user management actions are appended to the immutable audit log.</span>
        </div>
      </div>

      {/* Users table */}
      <div style={{ padding:'0 32px' }}>
        <div className="panel">
          <div style={{ overflowX:'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Department</th>
                  <th>Status</th>
                  <th>Last Login</th>
                  {/* Permission matrix headers */}
                  {PERMISSION_MODULES.map(m => (
                    <th key={m.key} style={{ textAlign:'center', padding:'8px 6px', fontSize:9, fontFamily:'var(--font-mono)', textTransform:'uppercase', letterSpacing:'0.06em' }} title={m.label}>
                      <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:3 }}>
                        {m.icon}
                        <span style={{ fontSize:8 }}>{m.label.slice(0,4)}</span>
                      </div>
                    </th>
                  ))}
                  <th style={{ textAlign:'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={15} style={{ textAlign:'center', padding:50, color:'var(--text-muted)' }}>Loading users…</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={15} style={{ textAlign:'center', padding:50, color:'var(--text-muted)' }}>No users match your filter</td></tr>
                ) : filtered.map(u => {
                  const meta = ROLE_META[u.role] || { color:'#6b7280', label:u.role, bg:'rgba(107,114,128,0.1)' };
                  const perms = ROLE_PERMISSIONS[u.role] || [];
                  return (
                    <tr key={u.id} style={{ opacity: u.is_active ? 1 : 0.55 }}>
                      {/* User */}
                      <td>
                        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                          <div style={{
                            width:32, height:32, borderRadius:8,
                            background:meta.bg, border:`1px solid ${meta.color}44`,
                            display:'flex', alignItems:'center', justifyContent:'center',
                            fontSize:12, fontWeight:700, color:meta.color, fontFamily:'var(--font-mono)',
                            flexShrink:0,
                          }}>
                            {u.full_name?.split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ fontWeight:600, fontSize:13 }}>{u.full_name}</div>
                            <div style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{u.email}</div>
                          </div>
                        </div>
                      </td>

                      {/* Role badge */}
                      <td>
                        <span style={{
                          fontSize:10, fontFamily:'var(--font-mono)', padding:'3px 9px', borderRadius:5,
                          textTransform:'uppercase', letterSpacing:'0.06em',
                          background:meta.bg, color:meta.color, border:`1px solid ${meta.color}44`,
                        }}>
                          {meta.label}
                        </span>
                      </td>

                      {/* Department */}
                      <td style={{ fontSize:12, color:'var(--text-secondary)' }}>{u.department || '—'}</td>

                      {/* Status */}
                      <td>
                        <span style={{ display:'inline-flex', alignItems:'center', gap:5, fontSize:12 }}>
                          <div style={{
                            width:7, height:7, borderRadius:'50%',
                            background: u.is_active ? '#10b981' : '#e63946',
                            boxShadow: u.is_active ? '0 0 6px rgba(16,185,129,0.5)' : 'none',
                          }}/>
                          {u.is_active ? 'Active' : 'Disabled'}
                          {u.is_superuser && (
                            <span style={{ fontSize:9, fontFamily:'var(--font-mono)', background:'rgba(230,57,70,0.15)', color:'#e63946', border:'1px solid rgba(230,57,70,0.3)', borderRadius:3, padding:'1px 5px' }}>SUPER</span>
                          )}
                        </span>
                      </td>

                      {/* Last login */}
                      <td style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                        {u.last_login ? new Date(u.last_login).toLocaleString('en-GB', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' }) : 'Never'}
                      </td>

                      {/* Permission matrix */}
                      {PERMISSION_MODULES.map(mod => (
                        <td key={mod.key} style={{ textAlign:'center', padding:'8px 6px' }}>
                          <PermCell granted={perms.includes(mod.key)} color={meta.color}/>
                        </td>
                      ))}

                      {/* Actions */}
                      <td style={{ textAlign:'right' }}>
                        <div style={{ display:'flex', gap:6, justifyContent:'flex-end' }}>
                          {/* Change role */}
                          <button
                            title="Change Role"
                            onClick={() => setRoleModal(u)}
                            style={{ background:'rgba(99,102,241,0.12)', border:'1px solid rgba(99,102,241,0.25)', color:'#818cf8', borderRadius:6, padding:'5px 8px', cursor:'pointer', display:'flex', alignItems:'center' }}
                          >
                            <Edit2 size={12}/>
                          </button>

                          {/* Reset password */}
                          <button
                            title="Reset Password"
                            onClick={() => setPwdModal(u)}
                            style={{ background:'rgba(245,158,11,0.12)', border:'1px solid rgba(245,158,11,0.25)', color:'#f59e0b', borderRadius:6, padding:'5px 8px', cursor:'pointer', display:'flex', alignItems:'center' }}
                          >
                            <Key size={12}/>
                          </button>

                          {/* Deactivate / Reactivate */}
                          {u.is_active ? (
                            <button
                              title="Deactivate Account"
                              onClick={() => setConfirm({ type:'deactivate', user:u })}
                              disabled={u.is_superuser}
                              style={{ background:'rgba(230,57,70,0.10)', border:'1px solid rgba(230,57,70,0.25)', color:'#e63946', borderRadius:6, padding:'5px 8px', cursor: u.is_superuser ? 'not-allowed' : 'pointer', display:'flex', alignItems:'center', opacity: u.is_superuser ? 0.4 : 1 }}
                            >
                              <UserX size={12}/>
                            </button>
                          ) : (
                            <button
                              title="Reactivate Account"
                              onClick={() => setConfirm({ type:'reactivate', user:u })}
                              style={{ background:'rgba(16,185,129,0.12)', border:'1px solid rgba(16,185,129,0.3)', color:'#10b981', borderRadius:6, padding:'5px 8px', cursor:'pointer', display:'flex', alignItems:'center' }}
                            >
                              <UserCheck size={12}/>
                            </button>
                          )}

                          {/* Delete */}
                          {!u.is_superuser && (
                            <button
                              title="Delete User"
                              onClick={() => setConfirm({ type:'delete', user:u })}
                              style={{ background:'rgba(107,114,128,0.1)', border:'1px solid rgba(107,114,128,0.2)', color:'var(--text-muted)', borderRadius:6, padding:'5px 8px', cursor:'pointer', display:'flex', alignItems:'center' }}
                            >
                              <Trash2 size={12}/>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Permission matrix legend */}
      <div style={{ padding:'20px 32px 0' }}>
        <div className="panel" style={{ padding:'16px 20px' }}>
          <div style={{ fontSize:11, fontFamily:'var(--font-mono)', color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:12 }}>
            Full Role × Module Permission Matrix
          </div>
          <div style={{ overflowX:'auto' }}>
            <table style={{ borderCollapse:'collapse', fontSize:11 }}>
              <thead>
                <tr>
                  <th style={{ padding:'6px 12px', textAlign:'left', fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-muted)', fontWeight:400 }}>Role</th>
                  {PERMISSION_MODULES.map(m => (
                    <th key={m.key} style={{ padding:'6px 10px', textAlign:'center', fontFamily:'var(--font-mono)', fontSize:9, color:'var(--text-muted)', fontWeight:400 }}>
                      <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:3 }}>
                        {m.icon}
                        <span>{m.label}</span>
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(ROLE_META).map(([role, meta]) => (
                  <tr key={role}>
                    <td style={{ padding:'5px 12px', fontFamily:'var(--font-mono)', fontSize:11 }}>
                      <span style={{ color:meta.color, fontWeight:700 }}>{meta.label}</span>
                    </td>
                    {PERMISSION_MODULES.map(mod => (
                      <td key={mod.key} style={{ padding:'5px 10px', textAlign:'center' }}>
                        <PermCell granted={(ROLE_PERMISSIONS[role]||[]).includes(mod.key)} color={meta.color}/>
                      </td>
                    ))}
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

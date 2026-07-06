import React, { useState, useEffect } from 'react';
import { evidenceAPI } from '../utils/api';
import { Archive, CheckCircle, XCircle, Link, ShieldCheck } from 'lucide-react';

export default function EvidencePage() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState({});
  const [verifyResults, setVerifyResults] = useState({});

  useEffect(() => {
    evidenceAPI.list().then(r => { setEntries(r.data.entries); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const verify = async (entryRef) => {
    setVerifying(v => ({ ...v, [entryRef]: true }));
    try {
      const res = await evidenceAPI.verify(entryRef);
      setVerifyResults(r => ({ ...r, [entryRef]: res.data }));
    } catch (e) {
      setVerifyResults(r => ({ ...r, [entryRef]: { integrity_valid: false, message: 'Verification failed' } }));
    } finally {
      setVerifying(v => ({ ...v, [entryRef]: false }));
    }
  };

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      <div style={{ padding: '28px 32px 0', marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22 }}>Legal-Grade Evidence Vault</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
          Tamper-evident · SHA-256 hashed · HMAC signed · Blockchain-style chained · {entries.length} entries
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, padding: '0 32px', marginBottom: 20 }}>
        {[
          { label: 'Total Evidence Entries', value: entries.length, color: 'var(--accent-blue)' },
          { label: 'Chain Integrity Valid', value: entries.filter(e => e.chain_valid !== false).length, color: 'var(--low)' },
          { label: 'Integrity Failures', value: entries.filter(e => e.chain_valid === false).length, color: 'var(--critical)' },
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="label">{s.label}</div>
            <div className="value" style={{ color: s.color, fontFamily: 'var(--font-mono)' }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ padding: '0 32px' }}>
        <div style={{ marginBottom: 12 }} className="alert-strip alert-info">
          <ShieldCheck size={14} />
          Each evidence entry is SHA-256 hashed and HMAC-signed. Entries are blockchain-chained — tampering with any entry invalidates all subsequent entries. This package is legally defensible in an ISO 27001 audit or FCA examination.
        </div>

        <div className="panel">
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Entry Ref</th>
                  <th>Control ID</th>
                  <th>Type</th>
                  <th>Summary</th>
                  <th>Frameworks</th>
                  <th>Content Hash</th>
                  <th>Chain</th>
                  <th>Collected</th>
                  <th>Verify</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>Loading evidence vault...</td></tr>
                ) : entries.length === 0 ? (
                  <tr><td colSpan={9} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No evidence yet — run controls to populate the vault</td></tr>
                ) : entries.map(e => {
                  const vr = verifyResults[e.entry_ref];
                  return (
                    <tr key={e.id}>
                      <td className="mono" style={{ color: 'var(--accent-cyan)', fontSize: 11 }}>{e.entry_ref || `EVD-${e.id}`}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{e.control_id}</td>
                      <td><span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{e.evidence_type}</span></td>
                      <td style={{ maxWidth: 200, fontSize: 12 }}>{(e.summary || '').slice(0, 60)}{e.summary?.length > 60 ? '...' : ''}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(e.frameworks_covered || '').split(',').filter(Boolean).map(f => (
                            <span key={f} style={{ fontSize: 9, fontFamily: 'var(--font-mono)', background: 'rgba(59,130,246,0.1)', color: 'var(--accent-blue)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 3, padding: '1px 4px' }}>{f.trim()}</span>
                          ))}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{e.content_hash?.slice(0, 12)}...</td>
                      <td>
                        {e.chain_valid !== false
                          ? <CheckCircle size={14} color="var(--low)" />
                          : <XCircle size={14} color="var(--critical)" />
                        }
                      </td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {e.collected_at ? new Date(e.collected_at).toLocaleDateString() : '—'}
                      </td>
                      <td>
                        {vr ? (
                          vr.integrity_valid
                            ? <span style={{ fontSize: 10, color: 'var(--low)', fontFamily: 'var(--font-mono)' }}>✓ VALID</span>
                            : <span style={{ fontSize: 10, color: 'var(--critical)', fontFamily: 'var(--font-mono)' }}>✗ FAIL</span>
                        ) : (
                          <button
                            className="btn btn-ghost btn-sm"
                            style={{ fontSize: 10 }}
                            disabled={verifying[e.entry_ref]}
                            onClick={() => verify(e.entry_ref)}
                          >
                            {verifying[e.entry_ref] ? '...' : 'Verify'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

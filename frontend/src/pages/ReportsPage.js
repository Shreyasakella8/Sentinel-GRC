import React, { useState, useEffect } from 'react';
import { reportsAPI } from '../utils/api';
import { FileText, Download, Loader, Users, Search, Code } from 'lucide-react';

const REPORT_TYPES = [
  {
    id: 'board',
    label: 'Board Executive Report',
    icon: Users,
    color: '#8b5cf6',
    description: 'Financial risk exposure in GBP, compliance posture score, top 5 risks, trend vs last quarter. Non-technical. Designed for C-suite and board meetings.',
    audience: 'Board Members / C-Suite',
    generate: reportsAPI.generateBoard,
    includes: ['Total ALE in £', 'Compliance score %', 'Top 5 risks by exposure', 'Risk trend chart', 'Board action items'],
  },
  {
    id: 'auditor',
    label: 'ISO 27001 Auditor Report',
    icon: Search,
    color: '#06b6d4',
    description: 'Full control evidence, framework clause mapping, non-conformities with ISO 27001 references, remediation status. Formatted to audit standards.',
    audience: 'ISO 27001 Auditors / FCA Examiners',
    generate: reportsAPI.generateAuditor,
    includes: ['All control evidence', 'Framework clause mapping', 'Non-conformities', 'Evidence chain hashes', 'Remediation status'],
  },
  {
    id: 'technical',
    label: 'Technical Security Report',
    icon: Code,
    color: '#10b981',
    description: 'Raw control runner findings, system configurations, remediation steps with code snippets, evidence hashes. For the security engineering team.',
    audience: 'Security Engineers / DevSecOps',
    generate: reportsAPI.generateTechnical,
    includes: ['Raw control outputs', 'Config snapshots', 'Remediation commands', 'CVE mappings', 'Evidence hashes'],
  },
];

export default function ReportsPage() {
  const [generating, setGenerating] = useState({});
  const [generated, setGenerated] = useState({});
  const [reports, setReports] = useState([]);
  const [apiBase] = useState(process.env.REACT_APP_API_URL || 'http://localhost:8000');

  useEffect(() => {
    reportsAPI.list().then(r => setReports(r.data.reports)).catch(() => {});
  }, []);

  const generate = async (type) => {
    setGenerating(g => ({ ...g, [type.id]: true }));
    try {
      const res = await type.generate();
      setGenerated(g => ({ ...g, [type.id]: res.data }));
      // Refresh list
      const list = await reportsAPI.list();
      setReports(list.data.reports);
    } catch(e) {
      alert('Report generation failed: ' + (e.response?.data?.detail || e.message));
    } finally {
      setGenerating(g => ({ ...g, [type.id]: false }));
    }
  };

  return (
    <div className="fade-in" style={{ paddingBottom: 40 }}>
      <div style={{ padding: '28px 32px 0', marginBottom: 24 }}>
        <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 22 }}>Three-Tier Reporting Engine</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4 }}>
          One button. Three completely different reports from the same data. PDF with org letterhead.
        </p>
      </div>

      {/* Report generators */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, padding: '0 32px', marginBottom: 32 }}>
        {REPORT_TYPES.map(type => {
          const isGenerating = generating[type.id];
          const result = generated[type.id];
          return (
            <div key={type.id} style={{
              background: 'var(--bg-card)',
              border: `1px solid ${type.color}33`,
              borderRadius: 12, padding: '24px',
              display: 'flex', flexDirection: 'column',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <div style={{ width: 40, height: 40, borderRadius: 8, background: `${type.color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <type.icon size={18} color={type.color} />
                </div>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 14 }}>{type.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{type.audience}</div>
                </div>
              </div>

              <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: 14, flex: 1 }}>
                {type.description}
              </p>

              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Includes:</div>
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {type.includes.map(item => (
                    <li key={item} style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 5, height: 5, borderRadius: '50%', background: type.color, flexShrink: 0 }} />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              {result ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div className="alert-strip alert-success" style={{ fontSize: 11 }}>
                    ✓ Report generated: {result.filename}
                  </div>
                  <a
                    href={`${apiBase}${result.url}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-primary"
                    style={{ justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <Download size={13} /> Download Report
                  </a>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => { setGenerated(g => ({ ...g, [type.id]: null })); generate(type); }}
                    style={{ justifyContent: 'center' }}
                  >
                    Regenerate
                  </button>
                </div>
              ) : (
                <button
                  className="btn"
                  style={{
                    background: type.color, color: 'white',
                    justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 6,
                    opacity: isGenerating ? 0.7 : 1
                  }}
                  onClick={() => generate(type)}
                  disabled={isGenerating}
                >
                  {isGenerating ? (
                    <><Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> Generating PDF...</>
                  ) : (
                    <><FileText size={13} /> Generate {type.label.split(' ')[0]} Report</>
                  )}
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Past reports */}
      <div style={{ padding: '0 32px' }}>
        <h2 style={{ fontSize: 14, fontWeight: 700, marginBottom: 14, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Generated Reports Archive
        </h2>
        <div className="panel">
          {reports.length === 0 ? (
            <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No reports generated yet. Use the buttons above to generate your first report.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Download</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.filename}>
                    <td className="mono" style={{ fontSize: 12 }}>{r.filename}</td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                        {r.filename.includes('board') ? 'Board' : r.filename.includes('auditor') ? 'Auditor' : 'Technical'}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.size_kb} KB</td>
                    <td>
                      <a href={`${apiBase}${r.url}`} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                        <Download size={11} /> Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

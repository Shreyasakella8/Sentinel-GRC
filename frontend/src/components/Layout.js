import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import {
  LayoutDashboard, Shield, AlertTriangle, CheckSquare,
  Archive, BookOpen, FileText, Zap, Users, LogOut,
  ChevronLeft, ChevronRight, Activity, Brain
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/dashboard',  label: 'Dashboard',        icon: LayoutDashboard, permission: 'dashboard' },
  { path: '/risks',      label: 'Risk Register',    icon: AlertTriangle,   permission: 'risks' },
  { path: '/controls',   label: 'Controls',         icon: CheckSquare,     permission: 'controls' },
  { path: '/evidence',   label: 'Evidence Vault',   icon: Archive,         permission: 'evidence' },
  { path: '/governance', label: 'Governance',       icon: BookOpen,        permission: 'governance' },
  { path: '/reports',    label: 'Reports',          icon: FileText,        permission: 'reports' },
  { path: '/threats',    label: 'Threat Intel',     icon: Zap,             permission: 'threats' },
  { path: '/users',      label: 'Users',            icon: Users,           permission: 'users' },
  { path: '/ai-security', label: 'AI Security',      icon: Brain,           permission: 'threats' },
];

const ROLE_COLORS = {
  ciso: '#e63946',
  board_member: '#8b5cf6',
  risk_owner: '#f59e0b',
  internal_auditor: '#06b6d4',
  read_only: '#6b7280',
};

export default function Layout() {
  const { user, logout, hasPermission } = useAuth();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);

  const handleLogout = () => { logout(); navigate('/login'); };

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar */}
      <aside style={{
        width: collapsed ? 64 : 240,
        minWidth: collapsed ? 64 : 240,
        background: 'var(--bg-surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width 0.2s, min-width 0.2s',
        overflow: 'hidden',
      }}>
        {/* Logo */}
        <div style={{
          padding: collapsed ? '20px 0' : '20px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: collapsed ? 'center' : 'space-between',
          gap: 10,
        }}>
          {!collapsed && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield size={20} color="var(--accent-red)" />
                <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: 16, letterSpacing: '0.05em', color: 'var(--text-primary)' }}>
                  SENTINEL
                </span>
              </div>
              <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', letterSpacing: '0.15em', marginTop: 2 }}>
                GRC PLATFORM v1.0
              </div>
            </div>
          )}
          {collapsed && <Shield size={20} color="var(--accent-red)" />}
          <button
            onClick={() => setCollapsed(!collapsed)}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', padding: 4, display: 'flex', alignItems: 'center' }}
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        {/* Live indicator */}
        {!collapsed && (
          <div style={{ padding: '8px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Activity size={12} color="var(--accent-green)" />
            <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)', letterSpacing: '0.1em' }}>
              MONITORING ACTIVE
            </span>
          </div>
        )}

        {/* Nav items */}
        <nav style={{ flex: 1, padding: '12px 0', overflowY: 'auto' }}>
          {NAV_ITEMS.filter(item => hasPermission(item.permission)).map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: collapsed ? '11px 0' : '11px 20px',
                justifyContent: collapsed ? 'center' : 'flex-start',
                fontSize: 13,
                fontWeight: 500,
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                background: isActive ? 'var(--bg-hover)' : 'transparent',
                borderLeft: isActive ? '2px solid var(--accent-red)' : '2px solid transparent',
                transition: 'all 0.15s',
                textDecoration: 'none',
              })}
            >
              <item.icon size={16} style={{ minWidth: 16 }} />
              {!collapsed && item.label}
            </NavLink>
          ))}
        </nav>

        {/* User info */}
        <div style={{ borderTop: '1px solid var(--border)', padding: collapsed ? '16px 0' : '16px 20px' }}>
          {!collapsed && (
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user?.full_name}
              </div>
              <div style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                color: ROLE_COLORS[user?.role] || 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                marginTop: 2,
              }}>
                {user?.role?.replace(/_/g, ' ')}
              </div>
            </div>
          )}
          <button
            onClick={handleLogout}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, width: '100%',
              background: 'none', border: 'none', color: 'var(--text-muted)',
              padding: collapsed ? '4px 0' : '4px 0', fontSize: 13,
              justifyContent: collapsed ? 'center' : 'flex-start',
              cursor: 'pointer',
            }}
          >
            <LogOut size={14} />
            {!collapsed && 'Sign Out'}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg-deep)' }}>
        <Outlet />
      </main>
    </div>
  );
}

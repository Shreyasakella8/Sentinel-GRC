import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import RisksPage from './pages/RisksPage';
import ControlsPage from './pages/ControlsPage';
import EvidencePage from './pages/EvidencePage';
import GovernancePage from './pages/GovernancePage';
import ReportsPage from './pages/ReportsPage';
import ThreatsPage from './pages/ThreatsPage';
import UsersPage from './pages/UsersPage';
import AISecurityPage from './pages/AISecurityPage';

const ProtectedRoute = ({ children, permission }) => {
  const { user, hasPermission } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (permission && !hasPermission(permission)) {
    return (
      <div style={{ padding:'60px', textAlign:'center', color:'var(--critical)' }}>
        <h2>Access Denied</h2>
        <p style={{ color:'var(--text-muted)', marginTop:8 }}>
          Your role ({user.role}) does not have permission to access this module.
        </p>
      </div>
    );
  }
  return children;
};

const AppRoutes = () => {
  const { user } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"   element={<ProtectedRoute permission="dashboard"><DashboardPage /></ProtectedRoute>} />
        <Route path="risks"       element={<ProtectedRoute permission="risks"><RisksPage /></ProtectedRoute>} />
        <Route path="controls"    element={<ProtectedRoute permission="controls"><ControlsPage /></ProtectedRoute>} />
        <Route path="evidence"    element={<ProtectedRoute permission="evidence"><EvidencePage /></ProtectedRoute>} />
        <Route path="governance"  element={<ProtectedRoute permission="governance"><GovernancePage /></ProtectedRoute>} />
        <Route path="reports"     element={<ProtectedRoute permission="reports"><ReportsPage /></ProtectedRoute>} />
        <Route path="threats"     element={<ProtectedRoute permission="threats"><ThreatsPage /></ProtectedRoute>} />
        <Route path="users"       element={<ProtectedRoute permission="users"><UsersPage /></ProtectedRoute>} />
        <Route path="ai-security" element={<ProtectedRoute permission="threats"><AISecurityPage /></ProtectedRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}

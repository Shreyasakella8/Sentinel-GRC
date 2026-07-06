import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from '../utils/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sentinel_user')); } catch { return null; }
  });
  const [loading, setLoading] = useState(false);

  const login = async (email, password) => {
    setLoading(true);
    try {
      const res = await authAPI.login(email, password);
      const { access_token, ...userData } = res.data;
      localStorage.setItem('sentinel_token', access_token);
      localStorage.setItem('sentinel_user', JSON.stringify(userData));
      setUser(userData);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.response?.data?.detail || 'Login failed' };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_user');
    setUser(null);
  };

  const hasPermission = (permission) => {
    if (!user) return false;
    const PERMISSIONS = {
      ciso: ['dashboard','risks','controls','evidence','governance','reports','threats','admin','audit','users','ai-security'],
      board_member: ['dashboard','reports'],
      risk_owner: ['dashboard','risks','governance'],
      internal_auditor: ['dashboard','evidence','audit','controls','reports','ai-security'],
      read_only: ['dashboard'],
    };
    return (PERMISSIONS[user.role] || []).includes(permission);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

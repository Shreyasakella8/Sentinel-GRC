import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  timeout: 30000,
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 → redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sentinel_token');
      localStorage.removeItem('sentinel_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export const authAPI = {
  login: (email, password) => {
    const form = new FormData();
    form.append('username', email);
    form.append('password', password);
    return api.post('/auth/login', form);
  },
  me: () => api.get('/auth/me'),
};

export const dashboardAPI = {
  getSummary: () => api.get('/dashboard/summary'),
};

export const risksAPI = {
  list: (params) => api.get('/risks/', { params }),
  get: (id) => api.get(`/risks/${id}`),
  create: (data) => api.post('/risks/', data),
  update: (id, data) => api.patch(`/risks/${id}`, data),
};

export const controlsAPI = {
  list: () => api.get('/controls/'),
  runControl: (id) => api.post(`/controls/${id}/run`),
  history: (id) => api.get(`/controls/history/${id}`),
};

export const evidenceAPI = {
  list: (params) => api.get('/evidence/', { params }),
  verify: (entryRef) => api.get(`/evidence/verify/${entryRef}`),
};

export const reportsAPI = {
  list: () => api.get('/reports/list'),
  generateBoard: () => api.post('/reports/board'),
  generateAuditor: () => api.post('/reports/auditor'),
  generateTechnical: () => api.post('/reports/technical'),
};

export const threatsAPI = {
  list: (params) => api.get('/threats/', { params }),
  refresh: () => api.post('/threats/refresh'),
};

export const governanceAPI = {
  listPolicies: () => api.get('/governance/policies'),
  createPolicy: (data) => api.post('/governance/policies', data),
  transitionPolicy: (id, data) => api.post(`/governance/policies/${id}/transition`, data),
  listAudits: () => api.get('/governance/audits'),
  listFindings: () => api.get('/governance/findings'),
};

export const usersAPI = {
  list:          ()                    => api.get('/users/'),
  create:        (data)               => api.post('/users/', data),
  changeRole:    (id, role)           => api.patch(`/users/${id}/role`, { role }),
  deactivate:    (id)                 => api.patch(`/users/${id}/deactivate`),
  reactivate:    (id)                 => api.patch(`/users/${id}/reactivate`),
  resetPassword: (id, new_password)   => api.patch(`/users/${id}/reset-password`, { new_password }),
  delete:        (id)                 => api.delete(`/users/${id}`),
};

export default api;

export const aiSecurityAPI = {
  scan:              (text, context='user_input', session_id=null) =>
                       api.post('/ai-security/scan', { text, context, session_id }),
  scanOutput:        (text, session_id=null) =>
                       api.post('/ai-security/scan-output', { text, session_id }),
  getLogs:           (blocked_only=false, limit=100) =>
                       api.get('/ai-security/logs', { params: { blocked_only, limit } }),
  getStats:          () => api.get('/ai-security/stats'),
  listAssessments:   () => api.get('/ai-security/assessments'),
  createAssessment:  (data) => api.post('/ai-security/assessments', data),
  listPolicies:      () => api.get('/ai-security/policies'),
  createPolicy:      (data) => api.post('/ai-security/policies', data),
};

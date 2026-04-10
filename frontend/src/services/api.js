const runtimeHostname = typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || `http://${runtimeHostname}:8000/api/detection`;
const INSTALLATION_ID_KEY = 'phisguard_installation_id';
const LEGACY_INSTALLATION_ID_KEY = 'installation_id';

function buildUrl(path) {
  return `${API_BASE_URL.replace(/\/$/, '')}/${path.replace(/^\//, '')}`;
}

function createInstallationId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `phg-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export function getInstallationId() {
  let installationId = localStorage.getItem(INSTALLATION_ID_KEY) || '';
  if (!installationId) {
    // Reuse legacy key so older data remains linked to the same installation.
    installationId = localStorage.getItem(LEGACY_INSTALLATION_ID_KEY) || '';
    if (installationId) {
      localStorage.setItem(INSTALLATION_ID_KEY, installationId);
    }
  }
  if (!installationId) {
    installationId = createInstallationId();
    localStorage.setItem(INSTALLATION_ID_KEY, installationId);
  }
  return installationId;
}

function getCookie(name) {
  const cookieValue = document.cookie
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${name}=`));
  if (!cookieValue) return '';
  return decodeURIComponent(cookieValue.split('=').slice(1).join('='));
}

function extractErrorMessage(data) {
  if (!data) return 'Request failed.';
  if (typeof data === 'string') return data;
  if (typeof data.error === 'string') return data.error;
  if (typeof data.detail === 'string') return data.detail;
  if (typeof data.message === 'string') return data.message;

  if (typeof data === 'object') {
    const flattened = Object.values(data).flat().filter(Boolean).join(' ');
    if (flattened) return flattened;
  }

  return 'Request failed.';
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : await response.text();

  if (!response.ok) {
    const error = new Error(extractErrorMessage(data));
    error.response = { data, status: response.status };
    throw error;
  }

  return { data };
}

async function request(path, { method = 'GET', body, query } = {}) {
  const headers = {};
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method.toUpperCase())) {
    const csrfToken = getCookie('csrftoken');
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }
  }

  let resolvedPath = path;
  if (query && typeof query === 'object') {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => {
      if (value !== undefined && value !== null && String(value).length > 0) {
        params.set(key, String(value));
      }
    });
    const queryString = params.toString();
    if (queryString) {
      resolvedPath = `${path}?${queryString}`;
    }
  }

  const response = await fetch(buildUrl(resolvedPath), {
    method,
    headers,
    credentials: 'include',
    cache: method === 'GET' ? 'no-store' : 'default',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  return parseResponse(response);
}

export const detectionAPI = {
  analyzeEmail(payload) {
    const resolvedUserEmail = (payload.user_email || '').trim().toLowerCase();
    return request('analyze/', {
      method: 'POST',
      body: {
        ...payload,
        user_email: resolvedUserEmail,
        installation_id: getInstallationId(),
      },
    });
  },

  getHistory({ page = 1, pageSize = 50 } = {}) {
    return request('history/', { query: { page, page_size: pageSize } });
  },

  getDetail(id) {
    return request(`history/${id}/`);
  },

  getStats() {
    return request('stats/');
  },

  getAdminUsers() {
    return request('admin/users/');
  },

  getAdminSession() {
    return request('admin/session/');
  },

  getAdminAnalytics(days = 30) {
    return request('admin/analytics/', { query: { days } });
  },

  getAdminAlerts(days = 30) {
    return request('admin/alerts/', { query: { days } });
  },

  getAdminLogs(limit = 100) {
    return request('admin/logs/', { query: { limit } });
  },

  getAdminReportDownloadUrl(days = 30) {
    const params = new URLSearchParams({ days: String(days) });
    return buildUrl(`admin/reports/download/?${params.toString()}`);
  },

  getAnalystAnalytics(days = 30) {
    return request('analyst/analytics/', { query: { days } });
  },

  getAnalystFlaggedCases(status = '') {
    return request('analyst/flagged-cases/', { query: { status } });
  },

  reviewAnalystFlaggedCase(id, payload) {
    return request(`analyst/flagged-cases/${id}/review/`, {
      method: 'PATCH',
      body: payload,
    });
  },

  getModelVersions() {
    return request('admin/model-versions/');
  },

  createModelVersion(payload) {
    return request('admin/model-versions/', {
      method: 'POST',
      body: payload,
    });
  },

  activateModelVersion(id) {
    return request(`admin/model-versions/${id}/activate/`, {
      method: 'POST',
      body: {},
    });
  },

  getRules(category = '') {
    return request('admin/rules/', { query: { category } });
  },

  createRule(payload) {
    return request('admin/rules/', {
      method: 'POST',
      body: payload,
    });
  },

  updateRule(id, payload) {
    return request(`admin/rules/${id}/`, {
      method: 'PATCH',
      body: payload,
    });
  },
};
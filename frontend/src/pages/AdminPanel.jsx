import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { detectionAPI } from '../services/api';

const defaultAnalytics = {
  daily_threats: [],
  category_attacks: [],
  user_stats: [],
  user_overview: {
    active_users: 0,
    inactive_users: 0,
  },
  top_targeted_users: [],
  top_keywords: [],
  suspicious_domains: [],
  insights: {
    phishing_trend_pct: 0,
    direction: 'flat',
    summary: '',
  },
  summary: {
    total_analyzed: 0,
    total_users: 0,
    active_rules: 0,
    phishing_detected: 0,
    suspicious_emails: 0,
    safe_emails: 0,
    avg_risk_score: 0,
  },
};

export default function AdminPanel() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [days, setDays] = useState(30);
  const adminLoginUrl = `${window.location.protocol}//${window.location.hostname}:8000/admin/login/`;

  const [analytics, setAnalytics] = useState(defaultAnalytics);
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [performance, setPerformance] = useState({
    processed_last_24h: 0,
    avg_risk_last_24h: 0,
    high_risk_last_24h: 0,
  });

  const [ruleForm, setRuleForm] = useState({
    name: '',
    category: 'keyword',
    severity: 'medium',
    pattern: '',
    weight: 10,
    description: '',
  });

  const [activeTab, setActiveTab] = useState('overview');

  const loadAll = useCallback(async (selectedDays = days) => {
    setLoading(true);
    setError('');
    try {
      const [sessionRes, analyticsRes, ruleRes, alertsRes, logsRes] = await Promise.all([
        detectionAPI.getAdminSession(),
        detectionAPI.getAdminAnalytics(selectedDays),
        detectionAPI.getRules(),
        detectionAPI.getAdminAlerts(selectedDays),
        detectionAPI.getAdminLogs(100),
      ]);

      setIsAdmin(Boolean(sessionRes?.data?.authenticated && sessionRes?.data?.is_admin));

      setAnalytics(analyticsRes.data || defaultAnalytics);
      setRules(Array.isArray(ruleRes.data) ? ruleRes.data : []);
      setAlerts(Array.isArray(alertsRes.data?.alerts) ? alertsRes.data.alerts : []);
      setLogs(Array.isArray(logsRes.data?.logs) ? logsRes.data.logs : []);
      setPerformance(logsRes.data?.performance || {
        processed_last_24h: 0,
        avg_risk_last_24h: 0,
        high_risk_last_24h: 0,
      });
    } catch (e) {
      setError(e?.message || 'Unable to load admin panel data.');
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    loadAll(days);
  }, [days, loadAll]);

  const summaryCards = useMemo(() => [
    { label: 'Total Analyzed', value: analytics.summary.total_analyzed, color: 'text-blue-300', bg: 'bg-blue-500/20' },
    { label: 'Phishing Detected', value: analytics.summary.phishing_detected, color: 'text-red-300', bg: 'bg-red-500/20' },
    { label: 'Suspicious', value: analytics.summary.suspicious_emails, color: 'text-yellow-300', bg: 'bg-yellow-500/20' },
    { label: 'Safe', value: analytics.summary.safe_emails, color: 'text-green-300', bg: 'bg-green-500/20' },
    { label: 'Avg Risk Score', value: `${analytics.summary.avg_risk_score}%`, color: 'text-purple-300', bg: 'bg-purple-500/20' },
  ], [analytics.summary]);

  const handleCreateRule = async (event) => {
    event.preventDefault();
    if (!isAdmin) {
      window.open(adminLoginUrl, '_blank', 'noopener,noreferrer');
      return;
    }
    try {
      await detectionAPI.createRule({
        ...ruleForm,
        weight: Number(ruleForm.weight),
        is_active: true,
      });
      setRuleForm({
        name: '',
        category: 'keyword',
        severity: 'medium',
        pattern: '',
        weight: 10,
        description: '',
      });
      loadAll(days);
    } catch (e) {
      setError(e?.message || 'Failed to create rule.');
    }
  };

  const handleToggleRule = async (rule) => {
    if (!isAdmin) {
      setError('Admin login required to update rules.');
      return;
    }
    try {
      await detectionAPI.updateRule(rule.id, { is_active: !rule.is_active });
      loadAll(days);
    } catch (e) {
      setError(e?.message || 'Failed to update rule.');
    }
  };

  if (loading) {
    return <div className="text-slate-300">Loading admin panel...</div>;
  }

  const tabClasses = (tab) =>
    `px-4 py-2 rounded-lg text-sm font-medium transition-all ${
      activeTab === tab
        ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-300/30'
        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
    }`;

  const handleDownloadReport = () => {
    if (!isAdmin) {
      window.open(adminLoginUrl, '_blank', 'noopener,noreferrer');
      return;
    }
    const url = detectionAPI.getAdminReportDownloadUrl(days);
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="py-2 space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white">Admin Dashboard</h2>
        <p className="text-slate-300 text-sm mt-1">System overview, threat patterns, user analytics, and rule management.</p>
      </div>

      {error && <p className="text-red-300 text-sm">{error}</p>}

      {/* Controls */}
      <div className="flex gap-3 items-center flex-wrap">
        <label className="text-sm text-slate-300">Time Window:</label>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-slate-900 border border-slate-700 text-slate-200 rounded px-3 py-1.5 text-sm"
        >
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={60}>60 days</option>
          <option value={90}>90 days</option>
        </select>
        <button
          onClick={() => loadAll(days)}
          className="bg-cyan-500 text-slate-950 text-sm font-medium px-3 py-1.5 rounded hover:bg-cyan-400"
        >
          Refresh
        </button>
        <button
          onClick={handleDownloadReport}
          className="text-slate-950 text-sm font-medium px-3 py-1.5 rounded bg-yellow-400 hover:bg-yellow-300"
        >
          Download CSV Report
        </button>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 flex-wrap">
        {['overview', 'users', 'threats', 'rules', 'alerts', 'logs'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={tabClasses(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* ===== OVERVIEW TAB ===== */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {analytics.insights?.summary && (
            <div className="bg-indigo-500/15 border border-indigo-400/30 rounded-xl p-4">
              <p className="text-indigo-200 text-sm font-medium">Advanced Insight</p>
              <p className="text-slate-100 mt-1">{analytics.insights.summary}</p>
            </div>
          )}

          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {summaryCards.map((card) => (
              <div key={card.label} className={`${card.bg} border border-slate-700 rounded-xl p-3`}>
                <div className={`text-2xl font-bold ${card.color}`}>{card.value}</div>
                <div className="text-xs text-slate-400 mt-1">{card.label}</div>
              </div>
            ))}
          </div>

          {/* Daily Threats Chart */}
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Daily Threat Trends</h3>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={analytics.daily_threats}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="day" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                <YAxis tick={{ fill: '#cbd5e1', fontSize: 11 }} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="phishing" stroke="#ef4444" strokeWidth={2} name="Phishing" />
                <Line type="monotone" dataKey="suspicious" stroke="#f59e0b" strokeWidth={2} name="Suspicious" />
                <Line type="monotone" dataKey="safe" stroke="#10b981" strokeWidth={2} name="Safe" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Category Trends */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
              <h3 className="font-semibold text-slate-100 mb-3">Threat Categories</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={analytics.category_attacks}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="category" tick={{ fill: '#cbd5e1', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#cbd5e1', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#06b6d4" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* ===== USER ANALYSIS TAB ===== */}
      {activeTab === 'users' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">Total Users</p>
              <p className="text-2xl font-bold text-slate-100">{analytics.summary.total_users}</p>
            </div>
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">Active Users ({days}d)</p>
              <p className="text-2xl font-bold text-emerald-200">{analytics.user_overview.active_users}</p>
            </div>
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">Inactive Users ({days}d)</p>
              <p className="text-2xl font-bold text-amber-200">{analytics.user_overview.inactive_users}</p>
            </div>
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-4">User Risk Analysis (Top 10 by Risk)</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-300 border-b border-slate-700">
                    <th className="py-2 px-3 font-medium">User Email</th>
                    <th className="py-2 px-3 font-medium">Total Analyzed</th>
                    <th className="py-2 px-3 font-medium">Phishing</th>
                    <th className="py-2 px-3 font-medium">Suspicious</th>
                    <th className="py-2 px-3 font-medium">Avg Risk</th>
                    <th className="py-2 px-3 font-medium">Risk Tier</th>
                  </tr>
                </thead>
                <tbody>
                  {analytics.user_stats.map((user, idx) => (
                    <tr key={idx} className="border-b border-slate-800 hover:bg-slate-800/50">
                      <td className="py-2 px-3 text-slate-100 text-xs">{user.user_email || 'unknown-user'}</td>
                      <td className="py-2 px-3 text-slate-200">{user.total_analyses}</td>
                      <td className="py-2 px-3 text-red-300">{user.phishing_count}</td>
                      <td className="py-2 px-3 text-yellow-300">{user.suspicious_count}</td>
                      <td className="py-2 px-3 text-slate-200">{user.avg_risk}%</td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-2 py-1 rounded text-xs font-semibold ${
                            user.risk_tier === 'high'
                              ? 'bg-red-500/20 text-red-200'
                              : user.risk_tier === 'medium'
                              ? 'bg-yellow-500/20 text-yellow-200'
                              : 'bg-green-500/20 text-green-200'
                          }`}
                        >
                          {user.risk_tier.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-slate-400 mt-3">Total unique users: {analytics.summary.total_users}</p>
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Most Targeted Users (Phishing Emails)</h3>
            <div className="space-y-2">
              {analytics.top_targeted_users.length === 0 && (
                <p className="text-sm text-slate-400">No phishing-targeted users found in current data.</p>
              )}
              {analytics.top_targeted_users.map((user, idx) => (
                <div key={idx} className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-800 px-3 py-2">
                  <span className="text-xs text-slate-100">{user.user_email || 'unknown-user'}</span>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-red-300">Phishing: {user.phishing_count}</span>
                    <span className="text-yellow-300">Suspicious: {user.suspicious_count}</span>
                    <span className="text-slate-200">Avg Risk: {user.avg_risk}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ===== THREAT PATTERNS TAB ===== */}
      {activeTab === 'threats' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Keywords */}
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Top Phishing Keywords</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {analytics.top_keywords.length === 0 && (
                <p className="text-sm text-slate-400">No keyword data available.</p>
              )}
              {analytics.top_keywords.map((item, idx) => (
                <div key={idx} className="flex justify-between items-center bg-slate-800 rounded px-3 py-2">
                  <span className="text-sm text-slate-100 truncate">{item.keyword}</span>
                  <span className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded">{item.count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Suspicious Domains */}
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Suspicious Domains Found</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {analytics.suspicious_domains.length === 0 && (
                <p className="text-sm text-slate-400">No domain data available.</p>
              )}
              {analytics.suspicious_domains.map((item, idx) => (
                <div key={idx} className="flex justify-between items-center bg-slate-800 rounded px-3 py-2">
                  <code className="text-xs text-slate-100 truncate">{item.domain}</code>
                  <span className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ===== RULE MANAGEMENT TAB ===== */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          {/* Add New Rule */}
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Add New Rule</h3>
            <form onSubmit={handleCreateRule} className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                value={ruleForm.name}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="Rule name"
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                required
                disabled={!isAdmin}
              />
              <input
                value={ruleForm.pattern}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, pattern: e.target.value }))}
                placeholder="Pattern (regex or keyword)"
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                disabled={!isAdmin}
              />
              <select
                value={ruleForm.category}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, category: e.target.value }))}
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                disabled={!isAdmin}
              >
                <option value="keyword">keyword</option>
                <option value="url">url</option>
                <option value="sender">sender</option>
                <option value="attachment">attachment</option>
                <option value="content">content</option>
              </select>
              <select
                value={ruleForm.severity}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, severity: e.target.value }))}
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                disabled={!isAdmin}
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
              </select>
              <input
                type="number"
                min={1}
                max={100}
                value={ruleForm.weight}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, weight: e.target.value }))}
                placeholder="Weight (1-100)"
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                disabled={!isAdmin}
              />
              <input
                value={ruleForm.description}
                onChange={(e) => setRuleForm((prev) => ({ ...prev, description: e.target.value }))}
                placeholder="Description"
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-2 text-sm"
                disabled={!isAdmin}
              />
              <button
                type="submit"
                className={`md:col-span-2 text-slate-950 px-4 py-2.5 rounded text-sm font-medium ${
                  isAdmin ? 'bg-cyan-500 hover:bg-cyan-400' : 'bg-amber-400 hover:bg-amber-300'
                }`}
              >
                {isAdmin ? 'Create Rule' : 'Add Rules'}
              </button>
            </form>
          </div>

          {/* Rules List */}
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-3">Active Rules ({analytics.summary.active_rules})</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {rules.length === 0 && (
                <p className="text-sm text-slate-400">No rules created yet.</p>
              )}
              {rules.map((rule) => (
                <div key={rule.id} className="flex items-center justify-between bg-slate-800 border border-slate-700 rounded px-4 py-3">
                  <div className="flex-1">
                    <p className="text-sm text-slate-100 font-medium">{rule.name}</p>
                    <p className="text-xs text-slate-400">
                      {rule.category} • {rule.severity} • weight {rule.weight}
                    </p>
                  </div>
                  <button
                    onClick={() => handleToggleRule(rule)}
                    className={`text-xs px-3 py-1.5 rounded font-medium transition-colors ${
                      !isAdmin
                        ? 'bg-slate-600 text-slate-300 cursor-not-allowed'
                        : rule.is_active
                        ? 'bg-emerald-500/20 text-emerald-200 hover:bg-emerald-500/30'
                        : 'bg-slate-600 text-slate-100 hover:bg-slate-500'
                    }`}
                    disabled={!isAdmin}
                  >
                    {rule.is_active ? '✓ Active' : 'Inactive'}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">Processed Last 24h</p>
              <p className="text-2xl font-bold text-cyan-200">{performance.processed_last_24h}</p>
            </div>
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">Avg Risk Last 24h</p>
              <p className="text-2xl font-bold text-amber-200">{performance.avg_risk_last_24h}%</p>
            </div>
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-4">
              <p className="text-xs text-slate-400">High Risk Last 24h</p>
              <p className="text-2xl font-bold text-rose-200">{performance.high_risk_last_24h}</p>
            </div>
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <h3 className="font-semibold text-slate-100 mb-4">Alerts & Notifications</h3>
            <div className="space-y-3">
              {alerts.length === 0 && <p className="text-sm text-slate-400">No alerts generated.</p>}
              {alerts.map((alert, idx) => (
                <div
                  key={idx}
                  className={`rounded-lg border p-3 ${
                    alert.severity === 'high'
                      ? 'bg-red-500/15 border-red-400/40'
                      : alert.severity === 'medium'
                      ? 'bg-yellow-500/15 border-yellow-400/40'
                      : 'bg-slate-800 border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-slate-100">{alert.title}</p>
                    <div className="flex items-center gap-2 flex-wrap justify-end">
                      {alert.type && (
                        <span className="text-[10px] uppercase tracking-[0.2em] text-cyan-200 bg-cyan-500/10 border border-cyan-400/20 rounded px-2 py-1">
                          {alert.type.replace(/_/g, ' ')}
                        </span>
                      )}
                      <span className="text-xs uppercase tracking-wide text-slate-300">{alert.severity}</span>
                    </div>
                  </div>
                  <p className="text-sm text-slate-300 mt-1">{alert.message}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-slate-400">
                    {alert.metric_value !== undefined && <span>Metric: {alert.metric_value}</span>}
                    {alert.generated_at && <span>{new Date(alert.generated_at).toLocaleString()}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
          <h3 className="font-semibold text-slate-100 mb-4">Anonymized Logs & History</h3>
          <div className="overflow-x-auto max-h-120">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-300 border-b border-slate-700">
                  <th className="py-2 px-3">Time</th>
                  <th className="py-2 px-3">Installation</th>
                  <th className="py-2 px-3">Sender</th>
                  <th className="py-2 px-3">Subject</th>
                  <th className="py-2 px-3">Verdict</th>
                  <th className="py-2 px-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((row) => (
                  <tr key={row.id} className="border-b border-slate-800 hover:bg-slate-800/40">
                    <td className="py-2 px-3 text-slate-300 text-xs">{new Date(row.analyzed_at).toLocaleString()}</td>
                    <td className="py-2 px-3 text-slate-200 text-xs">{row.installation_id}</td>
                    <td className="py-2 px-3 text-slate-200 text-xs">{row.sender_email}</td>
                    <td className="py-2 px-3 text-slate-200 max-w-xs truncate">{row.subject || '(No Subject)'}</td>
                    <td className="py-2 px-3 text-slate-100">{row.verdict}</td>
                    <td className="py-2 px-3 text-slate-200">{row.risk_score}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

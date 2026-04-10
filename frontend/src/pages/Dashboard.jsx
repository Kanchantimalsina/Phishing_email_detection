import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { detectionAPI } from '../services/api';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend } from 'recharts';

const statCards = [
  { key: 'total_analyzed',    label: 'Emails Analyzed',   bg: 'bg-blue-50',   num: 'text-blue-600',   border: 'border-blue-200' },
  { key: 'phishing_detected', label: 'Phishing Detected', bg: 'bg-red-50',    num: 'text-red-600',    border: 'border-red-200' },
  { key: 'suspicious_emails', label: 'Suspicious',        bg: 'bg-yellow-50', num: 'text-yellow-600', border: 'border-yellow-200' },
  { key: 'safe_emails',       label: 'Safe Emails',       bg: 'bg-green-50',  num: 'text-green-600',  border: 'border-green-200' },
  { key: 'average_risk_score',label: 'Avg Risk Score',    bg: 'bg-purple-50', num: 'text-purple-600', border: 'border-purple-200', suffix: '%' },
];

const badgeCls = {
  phishing:   'bg-red-100 text-red-700 px-2 py-0.5 rounded-full text-xs font-semibold',
  suspicious: 'bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded-full text-xs font-semibold',
  safe:       'bg-green-100 text-green-700 px-2 py-0.5 rounded-full text-xs font-semibold',
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    detectionAPI.getStats().then(r => setStats(r.data)).catch(() => {});
    detectionAPI.getHistory({ page: 1, pageSize: 100 }).then((r) => {
      const payload = r.data;
      const items = Array.isArray(payload) ? payload : (Array.isArray(payload?.results) ? payload.results : []);
      setHistory(items);
    }).catch(() => {});
  }, []);

  const recent = history.slice(0, 6);

  const pieData = stats ? [
    { name: 'Phishing',   value: stats.phishing_detected, color: '#ef4444' },
    { name: 'Suspicious', value: stats.suspicious_emails, color: '#f59e0b' },
    { name: 'Safe',       value: stats.safe_emails,       color: '#10b981' },
  ] : [];

  const vectorCounts = history.reduce((acc, item) => {
    const indicators = item.indicators || [];
    indicators.forEach((ind) => {
      acc[ind.category] = (acc[ind.category] || 0) + 1;
    });
    return acc;
  }, {});

  const threatIntelData = [
    { name: 'Link-based', count: vectorCounts.url || 0 },
    { name: 'Keyword-based', count: vectorCounts.keyword || 0 },
    { name: 'Sender-based', count: vectorCounts.sender || 0 },
    { name: 'Attachment-based', count: vectorCounts.attachment || 0 },
  ];

  const phishingRatio = stats && stats.total_analyzed > 0
    ? Math.round(((stats.phishing_detected + stats.suspicious_emails) / stats.total_analyzed) * 100)
    : 0;
  const recentRiskCount = history.filter((item) => item.verdict === 'phishing' || item.risk_score >= 80).length;
  const userRiskNotice =
    phishingRatio >= 25 || recentRiskCount >= 3
      ? {
          title: 'User risky behavior alert',
          message: 'Recent activity shows repeated high-risk or suspicious email patterns. Review sender domains, avoid attachments, and verify any urgent requests before responding.',
          tone: 'high',
        }
      : history.some((item) => item.verdict === 'suspicious')
      ? {
          title: 'Suspicious activity detected',
          message: 'One or more recent messages were flagged as suspicious. Pause before clicking links or sharing credentials.',
          tone: 'medium',
        }
      : null;

  return (
    <div className="py-2">
      <h2 className="text-3xl font-bold text-white">Security Operations Center</h2>
      <p className="text-slate-300 text-sm mb-6">Live phishing telemetry from your local extension installation.</p>

      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
          {statCards.map(card => (
            <div key={card.key} className="bg-slate-900/80 border border-slate-700 rounded-xl p-4 text-center shadow-lg">
              <div className={`text-3xl font-bold ${card.num}`}>
                {stats[card.key]}{card.suffix || ''}
              </div>
              <div className="text-xs text-slate-400 mt-1">{card.label}</div>
            </div>
          ))}
        </div>
      )}

      <div className="bg-linear-to-r from-rose-500/20 to-amber-500/20 border border-rose-300/30 rounded-xl p-4 mb-6 flex items-center justify-between">
        <div>
          <p className="text-sm text-rose-100 font-semibold">Threat Ratio</p>
          <p className="text-2xl text-white font-bold">{phishingRatio}% flagged (Phishing + Suspicious)</p>
        </div>
        <Link to="/analyze" className="bg-rose-500 text-white px-4 py-2 rounded-lg text-sm no-underline hover:bg-rose-600 transition-colors">Scan New Email</Link>
      </div>

      {userRiskNotice && (
        <div className={`mb-6 rounded-xl border p-4 ${userRiskNotice.tone === 'high' ? 'bg-red-500/10 border-red-300/30' : 'bg-yellow-500/10 border-yellow-300/30'}`}>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-300 mb-1">Security Notification</p>
          <p className="text-lg font-semibold text-white">{userRiskNotice.title}</p>
          <p className="text-sm text-slate-200 mt-1">{userRiskNotice.message}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {stats && stats.total_analyzed > 0 && (
          <div className="bg-slate-900/80 rounded-xl p-6 shadow-sm border border-slate-700">
            <h3 className="font-semibold text-slate-100 mb-4">Risk Overview</h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        <div className="bg-slate-900/80 rounded-xl p-6 shadow-sm border border-slate-700">
          <h3 className="font-semibold text-slate-100 mb-4">Quick Actions</h3>
          <div className="flex flex-col gap-3">
            <Link to="/analyze" className="bg-cyan-500 text-slate-950 px-4 py-2.5 rounded-lg hover:bg-cyan-400 font-medium transition-colors text-sm text-center no-underline">
              Analyze Current Message
            </Link>
            <Link to="/history" className="bg-slate-800 text-slate-100 px-4 py-2.5 rounded-lg hover:bg-slate-700 font-medium transition-colors text-sm text-center no-underline border border-slate-600">
              Review History Log
            </Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="bg-slate-900/80 rounded-xl p-6 shadow-sm border border-slate-700">
          <h3 className="font-semibold text-slate-100 mb-4">Threat Intelligence</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={threatIntelData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" tick={{ fill: '#cbd5e1', fontSize: 12 }} />
              <YAxis tick={{ fill: '#cbd5e1', fontSize: 12 }} allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#06b6d4" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-slate-900/80 rounded-xl p-6 shadow-sm border border-slate-700">
          <h3 className="font-semibold text-slate-100 mb-4">Education Hub: How To Stay Safe</h3>
          <ul className="text-sm text-slate-200 space-y-3 list-disc pl-5">
            <li>Never trust urgency alone. Verify through official channels before acting.</li>
            <li>Hover links and validate domains before clicking.</li>
            <li>Avoid opening executable or archive attachments from unknown senders.</li>
            <li>Use MFA and never share OTP, PIN, or password by email.</li>
            <li>Report suspected phishing to your mail provider immediately.</li>
          </ul>
        </div>
      </div>

      {recent.length > 0 && (
        <div className="bg-slate-900/80 rounded-xl p-6 shadow-sm border border-slate-700">
          <h3 className="font-semibold text-slate-100 mb-4">Recent Analyses</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-slate-300 text-left">
                  <th className="pb-2 font-medium">Subject</th>
                  <th className="pb-2 font-medium">Verdict</th>
                  <th className="pb-2 font-medium">Risk</th>
                  <th className="pb-2 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(item => (
                  <tr key={item.id} className="border-b border-slate-800 hover:bg-slate-800/80">
                    <td className="py-2 text-slate-100">{item.subject || 'No Subject'}</td>
                    <td className="py-2">
                      <span className={badgeCls[item.verdict] || badgeCls.safe}>{item.verdict}</span>
                    </td>
                    <td className="py-2 text-slate-200">{item.risk_score}%</td>
                    <td className="py-2 text-slate-400">{new Date(item.analyzed_at).toLocaleDateString()}</td>
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

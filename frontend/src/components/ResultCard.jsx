import React from 'react';

const CATEGORY_ICONS = {
  url: '🔗', keyword: '⚠️', sender: '👤', attachment: '📎', content: '📄'
};

const verdictConfig = {
  phishing:   { bgClass: 'bg-red-50 border border-red-300',       textClass: 'text-red-600',    icon: '🚨', label: 'PHISHING DETECTED' },
  suspicious: { bgClass: 'bg-yellow-50 border border-yellow-300', textClass: 'text-yellow-600', icon: '⚠️', label: 'SUSPICIOUS EMAIL' },
  safe:       { bgClass: 'bg-green-50 border border-green-300',   textClass: 'text-green-600',  icon: '✅', label: 'EMAIL APPEARS SAFE' },
};

const severityBorderCls = {
  high:   'border-l-4 border-l-red-500',
  medium: 'border-l-4 border-l-yellow-500',
  low:    'border-l-4 border-l-blue-500',
};

const severityBadgeCls = {
  high:   'bg-red-500 text-white text-xs px-2 py-0.5 rounded font-semibold',
  medium: 'bg-yellow-500 text-white text-xs px-2 py-0.5 rounded font-semibold',
  low:    'bg-blue-500 text-white text-xs px-2 py-0.5 rounded font-semibold',
};

const recPriorityCls = {
  1: 'border-l-4 border-l-red-400 bg-red-50',
  2: 'border-l-4 border-l-yellow-400 bg-yellow-50',
  3: 'border-l-4 border-l-green-400 bg-green-50',
};

export default function ResultCard({ result }) {
  const {
    verdict,
    risk_score = 0,
    ml_confidence = 0,
    indicators = [],
    recommendations = [],
    urls_found = [],
  } = result || {};

  const vc = verdictConfig[verdict] || verdictConfig.safe;
  const riskColor = risk_score >= 60 ? '#ef4444' : risk_score >= 30 ? '#f59e0b' : '#10b981';
  const securityNotice =
    risk_score >= 80 || verdict === 'phishing'
      ? {
          bgClass: 'bg-red-500/10 border-red-300/40',
          title: 'High-risk phishing detected',
          message: 'Treat this message as malicious. Do not click links, open attachments, or reply with sensitive information.',
        }
      : verdict === 'suspicious'
      ? {
          bgClass: 'bg-yellow-500/10 border-yellow-300/40',
          title: 'User risky behavior alert',
          message: 'This message shows risky behavior patterns. Verify the sender and inspect all links before taking action.',
        }
      : null;

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
      {securityNotice && (
        <div className={`${securityNotice.bgClass} border-b px-5 py-4`}>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500 mb-1">Security Notification</p>
          <p className="text-sm font-semibold text-slate-900">{securityNotice.title}</p>
          <p className="text-sm text-slate-700 mt-1">{securityNotice.message}</p>
        </div>
      )}

      {/* Verdict Banner */}
      <div className={`${vc.bgClass} px-5 py-4 flex items-center gap-3`}>
        <span className="text-3xl">{vc.icon}</span>
        <span className={`text-lg font-bold ${vc.textClass}`}>{vc.label}</span>
      </div>

      {/* Risk Score */}
      <div className="px-5 py-4 border-b border-slate-100">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-medium text-slate-700">Risk Score</span>
          <span className="text-xl font-bold" style={{ color: riskColor }}>{risk_score}%</span>
        </div>
        <div className="w-full bg-slate-100 rounded-full h-2.5">
          <div
            className="h-2.5 rounded-full transition-all"
            style={{ width: `${risk_score}%`, background: riskColor }}
          />
        </div>
        <div className="flex justify-between text-xs text-slate-400 mt-1">
          <span>0% Safe</span>
          <span>ML Confidence: {(ml_confidence * 100).toFixed(1)}%</span>
          <span>100% Phishing</span>
        </div>
      </div>

      {/* Suspicious Indicators */}
      {indicators.length > 0 && (
        <div className="px-5 py-4 border-b border-slate-100">
          <h4 className="text-sm font-semibold text-slate-700 mb-3">🚩 Suspicious Indicators ({indicators.length})</h4>
          <div className="flex flex-col gap-2">
            {indicators.map((ind, i) => (
              <div key={i} className={`${severityBorderCls[ind.severity] || ''} bg-slate-50 rounded-r-lg px-3 py-2`}>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs font-semibold text-slate-600">
                    {CATEGORY_ICONS[ind.category]} {ind.category.toUpperCase()}
                  </span>
                  <span className={severityBadgeCls[ind.severity] || severityBadgeCls.low}>
                    {ind.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-slate-600">{ind.description}</p>
                {ind.value && (
                  <code className="text-xs bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded mt-1 block truncate">
                    {ind.value.substring(0, 80)}
                  </code>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* URLs Found */}
      {urls_found && urls_found.length > 0 && (
        <div className="px-5 py-4 border-b border-slate-100">
          <h4 className="text-sm font-semibold text-slate-700 mb-3">🔗 URLs Found ({urls_found.length})</h4>
          <div className="flex flex-col gap-1">
            {urls_found.slice(0, 5).map((url, i) => (
              <code key={i} className="text-xs bg-slate-100 text-slate-600 px-2 py-1 rounded block truncate">
                {url.substring(0, 80)}{url.length > 80 ? '...' : ''}
              </code>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="px-5 py-4">
          <h4 className="text-sm font-semibold text-slate-700 mb-3">🛡️ Security Recommendations</h4>
          <div className="flex flex-col gap-2">
            {recommendations.map((rec, i) => (
              <div key={i} className={`${recPriorityCls[rec.priority] || recPriorityCls.low} rounded-r-lg px-3 py-2`}>
                <p className="text-xs font-semibold text-slate-700">{rec.title}</p>
                <p className="text-xs text-slate-600 mt-0.5">{rec.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

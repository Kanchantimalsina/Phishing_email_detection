import React, { useCallback, useEffect, useState } from 'react';
import { detectionAPI } from '../services/api';
import ResultCard from '../components/ResultCard';

const badgeCls = {
  phishing:   'bg-red-100 text-red-700 px-2 py-0.5 rounded-full text-xs font-semibold',
  suspicious: 'bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded-full text-xs font-semibold',
  safe:       'bg-green-100 text-green-700 px-2 py-0.5 rounded-full text-xs font-semibold',
};

export default function History() {
  const [history, setHistory] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  const loadHistory = useCallback(async (silent = false) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const r = await detectionAPI.getHistory({ page: 1, pageSize: 200 });
      const payload = r.data;
      const items = Array.isArray(payload) ? payload : (Array.isArray(payload?.results) ? payload.results : []);
      const count = typeof payload?.count === 'number' ? payload.count : items.length;

      setHistory(items);
      setTotalCount(count);
      setLoadError('');
    } catch {
      setLoadError('Unable to load history from database.');
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    loadHistory();

    const intervalId = setInterval(() => {
      loadHistory(true);
    }, 5000);

    return () => clearInterval(intervalId);
  }, [loadHistory]);

  const filtered = history.filter((item) => {
    const verdictMatch = filter === 'all' ? true : item.verdict === filter;
    const searchTarget = `${item.subject || ''} ${item.sender_email || ''} ${(item.reasons || []).join(' ')}`.toLowerCase();
    const searchMatch = search.trim().length === 0 ? true : searchTarget.includes(search.trim().toLowerCase());
    return verdictMatch && searchMatch;
  });

  const handleSelect = async (id) => {
    const res = await detectionAPI.getDetail(id);
    setSelected(res.data);
  };

  if (loading) return <div className="py-2"><p className="text-slate-500">Loading history...</p></div>;

  return (
    <div className="py-2">
      <h2 className="text-2xl font-bold text-white">History Console</h2>
      <p className="text-slate-300 text-sm mb-6">{totalCount} emails analyzed</p>
      {loadError && <p className="text-red-300 text-sm mb-4">{loadError}</p>}

      {/* Filter Bar */}
      <div className="flex gap-2 mb-4 flex-wrap">
        {['all', 'phishing', 'suspicious', 'safe'].map(v => (
          <button
            key={v}
            onClick={() => setFilter(v)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${
              filter === v
                ? 'bg-cyan-400/20 text-cyan-100 border border-cyan-300/40'
                : 'bg-slate-900 text-slate-300 border border-slate-700 hover:border-slate-500'
            }`}
          >
            {v.charAt(0).toUpperCase() + v.slice(1)}
          </button>
        ))}
      </div>

      <div className="mb-6">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by subject, sender, or reason..."
          className="w-full md:w-96 bg-slate-900 border border-slate-700 text-slate-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* List */}
        <div className="flex flex-col gap-3 max-h-150 overflow-y-auto pr-1">
          {filtered.length === 0 && <p className="text-slate-400 text-sm">No results found.</p>}
          {filtered.map(item => (
            <div
              key={item.id}
              onClick={() => handleSelect(item.id)}
              className={`bg-slate-900 border rounded-xl p-4 cursor-pointer transition-all hover:shadow-md ${
                selected?.id === item.id ? 'border-cyan-400 shadow-md' : 'border-slate-700'
              }`}
            >
              <div className="flex justify-between items-center mb-1">
                <span className={badgeCls[item.verdict] || badgeCls.safe}>{item.verdict}</span>
                <span className="text-xs text-slate-400">{new Date(item.analyzed_at).toLocaleDateString()}</span>
              </div>
              <div className="font-medium text-slate-100 text-sm truncate">{item.subject || '(No Subject)'}</div>
              <div className="flex justify-between items-center text-xs text-slate-400 mt-1">
                <span>Risk: {item.risk_score}%</span>
                <span>{item.source}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Detail */}
        {selected && (
          <div className="bg-slate-900 rounded-xl p-6 shadow-sm border border-slate-700">
            <div className="mb-4">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="font-semibold text-slate-100">{selected.subject || '(No Subject)'}</h3>
                  <p className="text-sm text-slate-400 mt-0.5">From: {selected.sender_email || 'Unknown'}</p>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="bg-slate-800 text-slate-300 px-3 py-1.5 rounded-lg hover:bg-slate-700 text-sm font-medium transition-colors border border-slate-600"
                >
                  ✕ Close
                </button>
              </div>
            </div>
            <ResultCard result={selected} />
          </div>
        )}
      </div>
    </div>
  );
}

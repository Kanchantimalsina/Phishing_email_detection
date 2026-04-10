import React, { useEffect, useState } from 'react';
import { detectionAPI } from '../services/api';
import ResultCard from '../components/ResultCard';

const USER_EMAIL_KEY = 'phisguard_user_email';

export default function Analyze() {
  const [formData, setFormData] = useState({
    user_email: '',
    sender: '',
    subject: '',
    body: '',
    analysis_mode: 'hybrid',
  });

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Handle prefilled data from extension
  useEffect(() => {
    const storedUserEmail = (localStorage.getItem(USER_EMAIL_KEY) || '').trim().toLowerCase();

    const params = new URLSearchParams(window.location.search);
    const prefill = params.get('prefill');
    if (prefill) {
      try {
        const json = decodeURIComponent(prefill);
        const data = JSON.parse(atob(json));
        setFormData((prev) => ({
          ...prev,
          user_email: storedUserEmail,
          sender: data.sender || '',
          subject: data.subject || '',
          body: data.body || '',
        }));
      } catch {
        console.error('Could not decode prefill data');
      }
      return;
    }

    if (storedUserEmail) {
      setFormData((prev) => ({ ...prev, user_email: storedUserEmail }));
    }
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    const nextValue = name === 'user_email' ? value.trim().toLowerCase() : value;
    setFormData((prev) => ({ ...prev, [name]: nextValue }));

    if (name === 'user_email') {
      if (nextValue) {
        localStorage.setItem(USER_EMAIL_KEY, nextValue);
      } else {
        localStorage.removeItem(USER_EMAIL_KEY);
      }
    }
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await detectionAPI.analyzeEmail(formData);
      setResult(response.data);
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setFormData({
      user_email: formData.user_email,
      sender: '',
      subject: '',
      body: '',
      analysis_mode: 'hybrid',
    });
    setResult(null);
    setError('');
  };

  return (
    <div className="py-2">
      <h2 className="text-3xl font-bold text-white">Email Analysis</h2>
      <p className="text-slate-300 text-sm mb-6">Paste an email to scan for phishing threats.</p>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Form */}
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <label className="block text-sm font-medium text-slate-200 mb-2">Your Email (for user analytics)</label>
            <input
              type="email"
              name="user_email"
              value={formData.user_email}
              onChange={handleChange}
              placeholder="you@company.com"
              className="w-full bg-slate-800 border border-slate-700 text-slate-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <label className="block text-sm font-medium text-slate-200 mb-2">Sender Email</label>
            <input
              type="email"
              name="sender"
              value={formData.sender}
              onChange={handleChange}
              placeholder="sender@example.com"
              className="w-full bg-slate-800 border border-slate-700 text-slate-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <label className="block text-sm font-medium text-slate-200 mb-2">Subject</label>
            <input
              type="text"
              name="subject"
              value={formData.subject}
              onChange={handleChange}
              placeholder="Email subject"
              className="w-full bg-slate-800 border border-slate-700 text-slate-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-5">
            <label className="block text-sm font-medium text-slate-200 mb-2">Email Body</label>
            <textarea
              name="body"
              value={formData.body}
              onChange={handleChange}
              placeholder="Paste the full email content here..."
              rows={8}
              className="w-full bg-slate-800 border border-slate-700 text-slate-100 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>

          <div className="flex gap-3">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-cyan-500 text-slate-950 font-bold py-2.5 px-4 rounded-lg hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Analyzing...' : 'Analyze Email'}
            </button>
            <button
              type="button"
              onClick={handleClear}
              disabled={loading}
              className="flex-1 bg-slate-700 text-slate-100 font-bold py-2.5 px-4 rounded-lg hover:bg-slate-600 disabled:opacity-50 transition-colors"
            >
              Clear
            </button>
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 text-red-200 text-sm">
              {error}
            </div>
          )}
        </form>

        {/* Result */}
        <div>
          {result && (
            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Analysis Result</h3>
              <ResultCard result={result} />
            </div>
          )}
          {!result && !loading && (
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 text-center text-slate-400">
              <p>Submit an email to see the analysis result.</p>
            </div>
          )}
          {loading && (
            <div className="bg-slate-900/80 border border-slate-700 rounded-xl p-6 text-center text-slate-300">~
              <p>Processing your email...</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

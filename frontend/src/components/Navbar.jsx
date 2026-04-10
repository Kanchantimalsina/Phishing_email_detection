import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { detectionAPI } from '../services/api';

export default function Navbar() {
  const location = useLocation();
  const adminLoginUrl = `${window.location.protocol}//${window.location.hostname}:8000/admin/login/`;
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    let isMounted = true;
    detectionAPI
      .getAdminSession()
      .then((res) => {
        if (isMounted) {
          setIsAdmin(Boolean(res?.data?.authenticated && res?.data?.is_admin));
        }
      })
      .catch(() => {
        if (isMounted) {
          setIsAdmin(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [location.pathname]);

  const navLink = (path) =>
    `no-underline px-3.5 py-1.5 rounded-md text-sm transition-all ${
      location.pathname === path
        ? 'bg-cyan-400/20 text-cyan-200 border border-cyan-300/30'
        : 'text-slate-300 hover:bg-slate-800 hover:text-white border border-transparent'
    }`;

  return (
    <nav className="backdrop-blur-md bg-slate-950/70 px-6 flex items-center h-16 gap-8 sticky top-0 z-50 shadow-lg border-b border-slate-700/60">
      <Link to="/dashboard" className="flex items-center gap-2 no-underline text-white text-xl font-bold">
        <span className="text-2xl">🛡️</span>
        <span>PhishGuard</span>
      </Link>

      <div className="ml-auto flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Link to="/dashboard" className={navLink('/dashboard')}>Dashboard</Link>
          <Link to="/admin-panel" className={navLink('/admin-panel')}>Admin Panel</Link>
          <Link to="/analyze" className={navLink('/analyze')}>Analyze</Link>
          <Link to="/history" className={navLink('/history')}>History</Link>
        </div>

        <div className="flex items-center gap-3">
          {isAdmin ? (
            <span className="bg-emerald-500/15 border border-emerald-400/40 text-emerald-200 rounded px-2 py-1 text-xs">
              Admin session active
            </span>
          ) : (
            <a
              href={adminLoginUrl}
              target="_blank"
              rel="noreferrer"
              className="bg-slate-900 border border-slate-700 text-slate-200 rounded px-2 py-1 text-xs no-underline hover:bg-slate-800"
            >
              Admin Login
            </a>
          )}
        </div>
      </div>
    </nav>
  );
}

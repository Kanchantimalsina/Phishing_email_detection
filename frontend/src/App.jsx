import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import AdminPanel from './pages/AdminPanel';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import History from './pages/History';
import './App.css';

export default function App() {
  return (
    <Router>
      <div className="flex flex-col min-h-screen relative page-enter">
        <div className="pointer-events-none fixed inset-0 -z-10">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(56,189,248,0.15),transparent_40%),radial-gradient(circle_at_80%_20%,rgba(249,115,22,0.12),transparent_35%),linear-gradient(160deg,#020617,#0f172a_55%,#111827)]" />
          <div className="absolute top-20 left-8 h-44 w-44 rounded-full border border-cyan-300/20" />
          <div className="absolute bottom-20 right-12 h-52 w-52 rounded-full border border-amber-300/20" />
        </div>
        <Navbar />
        <main className="flex-1 p-5 md:p-6 max-w-7xl mx-auto w-full">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/admin-panel" element={<AdminPanel />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/history" element={<History />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

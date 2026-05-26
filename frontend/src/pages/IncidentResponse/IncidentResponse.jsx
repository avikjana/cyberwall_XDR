import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { useAuth } from '../../context/AuthContext';
import { ShieldAlert, Plus, Trash2, Ban } from 'lucide-react';

const IncidentResponse = () => {
  const [rules, setRules] = useState([]);
  const [ipAddress, setIpAddress] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [duration, setDuration] = useState('60');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const fetchDebounceRef = useRef(null);

  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  // Debounced fetchRules — prevents rapid-fire API calls when multiple IPs are blocked quickly
  const debouncedFetchRules = useCallback(() => {
    if (fetchDebounceRef.current) {
      clearTimeout(fetchDebounceRef.current);
    }
    fetchDebounceRef.current = setTimeout(() => {
      fetchRules();
    }, 500);
  }, []);

  useEffect(() => {
    fetchRules();

    const socket = io('/', { path: '/socket.io' });
    socket.emit('join_soc');

    socket.on('block_ip', () => {
      debouncedFetchRules(); // Debounced instead of immediate
    });

    socket.on('unblock_ip', () => {
      debouncedFetchRules(); // Debounced instead of immediate
    });

    return () => {
      if (fetchDebounceRef.current) {
        clearTimeout(fetchDebounceRef.current);
      }
      socket.disconnect();
    };
  }, [debouncedFetchRules]);

  const fetchRules = async () => {
    try {
      const res = await axios.get('/api/rules');
      if (res.data.success) {
        setRules(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleBlock = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);

    if (!isAdmin) {
      setError('Access Denied: Only SOC Admins can configure firewall rules.');
      setSubmitting(false);
      return;
    }

    try {
      const res = await axios.post('/api/rules/block', {
        ip: ipAddress,
        reason: blockReason,
        duration: parseInt(duration)
      });

      if (res.data.success) {
        setSuccess(`Successfully blocklisted IP: ${ipAddress}`);
        setIpAddress('');
        setBlockReason('');
        fetchRules();
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to submit firewall rule');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUnblock = async (ip) => {
    if (!isAdmin) {
      alert('Access Denied: Only SOC Admins can remove firewall rules.');
      return;
    }

    try {
      const res = await axios.delete(`/api/rules/unblock/${ip}`);
      if (res.data.success) {
        setSuccess(`Successfully unblocked IP: ${ip}`);
        fetchRules();
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to remove firewall rule');
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Configure rule form */}
      <div className="glass-card p-6 rounded-2xl h-fit">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Ban className="w-5 h-5 text-red-500" />
          <span>Provision Blocklist Rule</span>
        </h3>

        {error && <div className="p-3 mb-4 rounded-lg bg-red-950/40 border border-red-900 text-red-400 text-xs">{error}</div>}
        {success && <div className="p-3 mb-4 rounded-lg bg-emerald-950/30 border border-emerald-900 text-emerald-400 text-xs">{success}</div>}

        <form onSubmit={handleBlock} className="space-y-4">
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">IPv4 Address</label>
            <input
              type="text"
              required
              disabled={!isAdmin}
              placeholder="e.g. 185.120.44.12"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">Incident Reason / Context</label>
            <input
              type="text"
              required
              disabled={!isAdmin}
              placeholder="Port scan threshold exceeded"
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">Block Duration</label>
            <select
              value={duration}
              disabled={!isAdmin}
              onChange={(e) => setDuration(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 text-slate-300 px-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm disabled:opacity-50 appearance-none"
            >
              <option value="15" className="bg-slate-950">15 Minutes</option>
              <option value="60" className="bg-slate-950">1 Hour</option>
              <option value="1440" className="bg-slate-950">24 Hours</option>
              <option value="10080" className="bg-slate-950">7 Days</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={submitting || !isAdmin}
            className="w-full py-2.5 mt-2 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white font-bold rounded-xl transition-all duration-300 shadow-danger-glow disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <Plus className="w-4 h-4" />
            <span>Apply Firewall Rule</span>
          </button>
        </form>

        {!isAdmin && (
          <p className="text-[10px] text-slate-500 font-mono mt-4 text-center">
            ⚠️ Analyst view is read-only. Ask SOC manager for rules configuration privilege.
          </p>
        )}
      </div>

      {/* Rules list */}
      <div className="lg:col-span-2 glass-card p-6 rounded-2xl">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-cyan-400" />
          <span>Active IP Blocking Rules</span>
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border text-slate-400 pb-2">
                <th className="pb-2">Blocked IP</th>
                <th className="pb-2">Trigger Incident</th>
                <th className="pb-2">Operator</th>
                <th className="pb-2">Expires At</th>
                {isAdmin && <th className="pb-2 text-right">Action</th>}
              </tr>
            </thead>
            <tbody>
              {rules.length > 0 ? (
                rules.map((rule) => (
                  <tr key={rule._id} className="border-b border-slate-900/60 text-slate-300 hover:bg-slate-900/10">
                    <td className="py-3 font-bold text-red-400">{rule.ip}</td>
                    <td className="py-3 max-w-[200px] truncate">{rule.reason}</td>
                    <td className="py-3">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400">
                        {rule.addedBy}
                      </span>
                    </td>
                    <td className="py-3 text-slate-500 text-[10px]">
                      {rule.expiresAt ? new Date(rule.expiresAt).toLocaleTimeString() : 'Permanent'}
                    </td>
                    {isAdmin && (
                      <td className="py-3 text-right">
                        <button
                          onClick={() => handleUnblock(rule.ip)}
                          className="p-1.5 text-slate-400 hover:text-emerald-400 rounded-lg hover:bg-slate-800 transition-all"
                          title="Lift Block Rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={isAdmin ? 5 : 4} className="text-center py-6 text-slate-500">
                    No active firewall blocklists.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default IncidentResponse;

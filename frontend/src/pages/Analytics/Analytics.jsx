import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart3, PieChart as PieIcon, HelpCircle } from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  PieChart, 
  Pie, 
  Cell, 
  Legend 
} from 'recharts';

const COLORS = ['#06b6d4', '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6'
};

const Analytics = () => {
  const [protocols, setProtocols] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const [severities, setSeverities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalyticsData();
  }, []);

  const fetchAnalyticsData = async () => {
    setLoading(true);
    try {
      const [protoRes, attRes, sevRes] = await Promise.all([
        axios.get('/api/analytics/protocols'),
        axios.get('/api/analytics/top-attackers'),
        axios.get('/api/analytics/severity')
      ]);

      if (protoRes.data.success) setProtocols(protoRes.data.data);
      if (attRes.data.success) setAttackers(attRes.data.data);
      if (sevRes.data.success) setSeverities(sevRes.data.data);
    } catch (err) {
      console.error("Failed to load analytics: ", err);
    } finally {
      setLoading(false);
    }
  };

  const severityPieData = severities.map(item => ({
    name: item.severity.toUpperCase(),
    value: item.count,
    color: SEVERITY_COLORS[item.severity] || '#64748b'
  }));

  const protocolBarData = protocols.map(item => ({
    name: item.protocol,
    Packets: item.count,
    Bandwidth: Math.round(item.bytes / 1024) // KB
  }));

  return (
    <div className="space-y-6">
      {loading ? (
        <div className="glass-card p-12 rounded-2xl text-center text-slate-500 font-mono">
          Compiling network traffic analytics models...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Chart 1: Protocols distribution */}
          <div className="glass-card p-6 rounded-2xl">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-cyan-400" />
              <span>Bandwidth Distribution by Protocol (KB)</span>
            </h3>
            <div className="h-64">
              {protocols.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={protocolBarData}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f1f5f9' }} />
                    <Bar dataKey="Bandwidth" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-slate-600 text-xs">No protocol data recorded.</div>
              )}
            </div>
          </div>

          {/* Chart 2: Threat Severity splits */}
          <div className="glass-card p-6 rounded-2xl">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <PieIcon className="w-5 h-5 text-cyan-400" />
              <span>Incident Severity Breakdown</span>
            </h3>
            <div className="h-64 flex items-center justify-center">
              {severities.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {severityPieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f1f5f9' }} />
                    <Legend verticalAlign="bottom" height={36} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-slate-600 text-xs">No incident classifications registered.</div>
              )}
            </div>
          </div>

          {/* Chart 3: Top Attacking hosts bar chart */}
          <div className="glass-card p-6 rounded-2xl md:col-span-2">
            <h3 className="text-lg font-bold text-white mb-4">Top 10 Security Threat Actors (Source IPs)</h3>
            <div className="h-72">
              {attackers.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackers} layout="vertical">
                    <XAxis type="number" stroke="#64748b" fontSize={11} />
                    <YAxis dataKey="ip" type="category" stroke="#64748b" fontSize={10} width={100} />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f1f5f9' }} />
                    <Bar dataKey="count" fill="#ef4444" name="Incidents Blocked" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-slate-600 text-xs">No attacking hosts recorded.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Analytics;

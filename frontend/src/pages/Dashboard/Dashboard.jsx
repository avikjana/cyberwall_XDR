import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { 
  AlertOctagon, 
  Activity, 
  Ban, 
  ShieldCheck, 
  Cpu, 
  HardDrive, 
  TrendingUp 
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalTraffic: 0,
    activeThreats: 0,
    totalBlocked: 0,
    systemStatus: { cpu: 12, ram: 45, disk: 38 }
  });
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [liveTraffic, setLiveTraffic] = useState([]);
  const [timelineData, setTimelineData] = useState([]);

  useEffect(() => {
    // Fetch initial statistical payloads
    fetchOverviewStats();
    fetchTimelineData();
    fetchRecentAlerts();

    // Setup Socket connection
    const socket = io('/', { path: '/socket.io' }); // Will resolve via nginx or local proxy

    socket.emit('join_soc');

    socket.on('new_alert', (alert) => {
      setLiveAlerts(prev => [alert, ...prev.slice(0, 9)]);
      setStats(prev => ({ ...prev, activeThreats: prev.activeThreats + 1 }));
    });

    socket.on('new_traffic', (traffic) => {
      setLiveTraffic(prev => [traffic, ...prev.slice(0, 9)]);
      setStats(prev => ({ ...prev, totalTraffic: prev.totalTraffic + 1 }));
    });

    socket.on('block_ip', () => {
      setStats(prev => ({ ...prev, totalBlocked: prev.totalBlocked + 1 }));
    });

    socket.on('unblock_ip', () => {
      setStats(prev => ({ ...prev, totalBlocked: Math.max(0, prev.totalBlocked - 1) }));
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const fetchOverviewStats = async () => {
    try {
      const res = await axios.get('/api/analytics/overview');
      if (res.data.success) {
        setStats(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchTimelineData = async () => {
    try {
      const res = await axios.get('/api/analytics/timeline');
      if (res.data.success) {
        setTimelineData(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchRecentAlerts = async () => {
    try {
      const res = await axios.get('/api/alerts?limit=10');
      if (res.data.success) {
        setLiveAlerts(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top statistics banners */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-cyan-500">
          <div>
            <p className="text-xs text-slate-400 font-mono uppercase tracking-wider">Total Traffic Logs</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{stats.totalTraffic.toLocaleString()}</h3>
          </div>
          <div className="p-3 bg-cyan-950/40 text-cyan-400 rounded-xl">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 2 */}
        <div className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-red-500">
          <div>
            <p className="text-xs text-slate-400 font-mono uppercase tracking-wider">Active Threat Indicators</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{stats.activeThreats}</h3>
          </div>
          <div className="p-3 bg-red-950/40 text-red-400 rounded-xl">
            <AlertOctagon className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 3 */}
        <div className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-amber-500">
          <div>
            <p className="text-xs text-slate-400 font-mono uppercase tracking-wider">Blocked IPs</p>
            <h3 className="text-2xl font-bold mt-1 text-white">{stats.totalBlocked}</h3>
          </div>
          <div className="p-3 bg-amber-950/40 text-amber-400 rounded-xl">
            <Ban className="w-6 h-6" />
          </div>
        </div>

        {/* Metric 4 */}
        <div className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-emerald-500">
          <div>
            <p className="text-xs text-slate-400 font-mono uppercase tracking-wider">IDS Engine Health</p>
            <h3 className="text-lg font-bold mt-2 text-emerald-400">OPERATIONAL</h3>
          </div>
          <div className="p-3 bg-emerald-950/40 text-emerald-400 rounded-xl">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Main Charts & Live Feed Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Timeline Bandwidth Chart */}
        <div className="glass-card p-6 rounded-2xl lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-cyan-400" />
              <span>Real-Time Network Volume</span>
            </h3>
            <span className="text-[10px] font-mono text-cyan-400">LIVE FEED</span>
          </div>
          <div className="h-64">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f1f5f9' }} />
                  <Area type="monotone" dataKey="packets" stroke="#06b6d4" fillOpacity={1} fill="url(#colorTraffic)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm font-mono">
                Awaiting telemetry streams...
              </div>
            )}
          </div>
        </div>

        {/* System Health Gauges */}
        <div className="glass-card p-6 rounded-2xl space-y-6">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <span>XDR Node Performance</span>
          </h3>

          <div className="space-y-4">
            {/* CPU Monitor */}
            <div>
              <div className="flex justify-between text-sm font-mono mb-1">
                <span className="text-slate-400">IDS Processor (CPU)</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.cpu}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div 
                  className="bg-cyan-500 h-2.5 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.cpu}%` }}
                ></div>
              </div>
            </div>

            {/* RAM Monitor */}
            <div>
              <div className="flex justify-between text-sm font-mono mb-1">
                <span className="text-slate-400">SOC Buffer (RAM)</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.ram}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div 
                  className="bg-cyan-500 h-2.5 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.ram}%` }}
                ></div>
              </div>
            </div>

            {/* Disk Storage */}
            <div>
              <div className="flex justify-between text-sm font-mono mb-1">
                <span className="text-slate-400">Incident Logs Partition</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.disk}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div 
                  className="bg-cyan-500 h-2.5 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.disk}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Alert Streams */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat List Card */}
        <div className="glass-card p-6 rounded-2xl">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-red-500" />
            <span>Recent Incident Events</span>
          </h3>
          <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
            {liveAlerts.length > 0 ? (
              liveAlerts.map((alert) => (
                <div 
                  key={alert._id || Math.random()} 
                  className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 transition-all flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                        alert.severity === 'critical' ? 'bg-red-950 text-red-400 border border-red-800' :
                        alert.severity === 'high' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="text-sm font-bold text-slate-100">{alert.threatType}</span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{alert.description}</p>
                    <div className="flex items-center gap-4 mt-2 text-[10px] text-slate-500 font-mono">
                      <span>SRC: {alert.sourceIp}</span>
                      <span>DST: {alert.destIp}</span>
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
              ))
            ) : (
              <p className="text-slate-500 text-sm font-mono text-center py-6">No threat alerts detected.</p>
            )}
          </div>
        </div>

        {/* Live Packet Logs Feed */}
        <div className="glass-card p-6 rounded-2xl">
          <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Real-time Traffic Telemetry</span>
          </h3>
          <div className="overflow-x-auto max-h-96 overflow-y-auto pr-2">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-cyber-border text-slate-400 pb-2">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Proto</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Dest IP</th>
                  <th className="pb-2 text-right">Size</th>
                </tr>
              </thead>
              <tbody>
                {liveTraffic.length > 0 ? (
                  liveTraffic.map((traffic) => (
                    <tr key={traffic._id || Math.random()} className="border-b border-slate-900/60 hover:bg-slate-900/20 text-slate-300">
                      <td className="py-2 text-[10px] text-slate-500">{new Date(traffic.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-bold text-cyan-400">
                          {traffic.protocol}
                        </span>
                      </td>
                      <td className="py-2 truncate max-w-[120px]">{traffic.sourceIp}</td>
                      <td className="py-2 truncate max-w-[120px]">{traffic.destIp}</td>
                      <td className="py-2 text-right text-slate-500">{traffic.packetSize} B</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="text-center py-6 text-slate-500">Awaiting packet logs...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

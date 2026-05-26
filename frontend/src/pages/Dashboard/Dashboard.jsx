import React, { useState, useEffect, useMemo, useRef } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { motion } from 'framer-motion';
import { 
  AlertOctagon, 
  Activity, 
  Ban, 
  ShieldCheck, 
  Cpu, 
  TrendingUp,
  Sparkles,
  Zap
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import ThreeDMap from '../../components/ThreeDMap';
import AIAssistantPanel from '../../components/AIAssistantPanel';

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

  const pendingTrafficRef = useRef([]);
  const pendingAlertRef = useRef([]);
  const flushIntervalRef = useRef(null);

  useEffect(() => {
    fetchOverviewStats();
    fetchTimelineData();
    fetchRecentAlerts();

    const token = localStorage.getItem('token');
    const socket = io('/', { 
      path: '/socket.io',
      auth: { token }
    });
    socket.emit('join_soc');

    socket.on('new_alert', (alert) => {
      pendingAlertRef.current.push(alert);
    });

    socket.on('new_traffic', (traffic) => {
      pendingTrafficRef.current.push(traffic);
    });

    socket.on('block_ip', () => {
      setStats(prev => ({ ...prev, totalBlocked: prev.totalBlocked + 1 }));
    });

    socket.on('unblock_ip', () => {
      setStats(prev => ({ ...prev, totalBlocked: Math.max(0, prev.totalBlocked - 1) }));
    });

    flushIntervalRef.current = setInterval(() => {
      if (pendingAlertRef.current.length > 0) {
        const newAlerts = pendingAlertRef.current;
        pendingAlertRef.current = [];
        setLiveAlerts(prev => [...newAlerts, ...prev].slice(0, 15));
        setStats(prev => ({ ...prev, activeThreats: prev.activeThreats + newAlerts.length }));
      }

      if (pendingTrafficRef.current.length > 0) {
        const newTraffic = pendingTrafficRef.current;
        pendingTrafficRef.current = [];
        setLiveTraffic(prev => [...newTraffic, ...prev].slice(0, 15));
        setStats(prev => ({ ...prev, totalTraffic: prev.totalTraffic + newTraffic.length }));
      }
    }, 1000);

    return () => {
      clearInterval(flushIntervalRef.current);
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
      const res = await axios.get('/api/alerts?limit=15');
      if (res.data.success) {
        setLiveAlerts(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const memoizedTimelineData = useMemo(() => timelineData, [timelineData]);

  // Framer Motion entry animations
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100 } }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* HUD Header */}
      <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
        <div>
          <h2 className="text-2xl font-bold font-sans tracking-wide bg-gradient-to-r from-white via-cyan-200 to-cyan-500 bg-clip-text text-transparent">
            NEURAL MISSION CONTROLLER 2040
          </h2>
          <p className="text-xs font-mono text-cyan-400/80">CORE STATUS: ENHANCED CYBER SHIELD ENGAGED</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-cyan-400 text-xs font-mono">
          <Zap className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>AUTONOMOUS IDS RESPONSE: ON</span>
        </div>
      </div>

      {/* Top statistics banners */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <motion.div 
          variants={itemVariants}
          whileHover={{ scale: 1.02 }}
          className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-cyan-500 shadow-lg relative overflow-hidden group"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/0 to-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
          <div>
            <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Total Traffic Logs</p>
            <h3 className="text-2xl font-bold mt-1 text-white font-mono tracking-tight">{stats.totalTraffic.toLocaleString()}</h3>
          </div>
          <div className="p-3 bg-cyan-950/40 text-cyan-400 rounded-xl border border-cyan-800/30">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
        </motion.div>

        {/* Metric 2 */}
        <motion.div 
          variants={itemVariants}
          whileHover={{ scale: 1.02 }}
          className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-red-500 shadow-lg relative overflow-hidden group"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-red-500/0 to-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
          <div>
            <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Active Threats</p>
            <h3 className="text-2xl font-bold mt-1 text-white font-mono tracking-tight">{stats.activeThreats}</h3>
          </div>
          <div className="p-3 bg-red-950/40 text-red-400 rounded-xl border border-red-800/30">
            <AlertOctagon className="w-5 h-5" />
          </div>
        </motion.div>

        {/* Metric 3 */}
        <motion.div 
          variants={itemVariants}
          whileHover={{ scale: 1.02 }}
          className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-amber-500 shadow-lg relative overflow-hidden group"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-amber-500/0 to-amber-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
          <div>
            <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Blocked Attackers</p>
            <h3 className="text-2xl font-bold mt-1 text-white font-mono tracking-tight">{stats.totalBlocked}</h3>
          </div>
          <div className="p-3 bg-amber-950/40 text-amber-400 rounded-xl border border-amber-800/30">
            <Ban className="w-5 h-5" />
          </div>
        </motion.div>

        {/* Metric 4 */}
        <motion.div 
          variants={itemVariants}
          whileHover={{ scale: 1.02 }}
          className="glass-card p-5 rounded-2xl flex items-center justify-between border-l-4 border-emerald-500 shadow-lg relative overflow-hidden group"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/0 to-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
          <div>
            <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">AI Defensive Health</p>
            <h3 className="text-sm font-bold mt-2 text-emerald-400 flex items-center gap-1.5 font-mono">
              <Sparkles className="w-3.5 h-3.5 text-emerald-400 animate-spin-slow" />
              OPTIMAL
            </h3>
          </div>
          <div className="p-3 bg-emerald-950/40 text-emerald-400 rounded-xl border border-emerald-800/30">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </motion.div>
      </div>

      {/* Interactive Threat Map & Performance Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Animated Threat Vector Map */}
        <motion.div variants={itemVariants} className="lg:col-span-2">
          <ThreeDMap alerts={liveAlerts} />
        </motion.div>

        {/* CPU/Memory Performance Indicators */}
        <motion.div variants={itemVariants} className="glass-card p-6 rounded-2xl space-y-6 flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Node Processing Capacity</span>
            </h3>
            <p className="text-[10px] font-mono text-slate-400 mt-1">REAL-TIME CPU & HEAP ALLOCATION</p>
          </div>

          <div className="space-y-4">
            {/* CPU Monitor */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-400">IDS/IPS CPU load</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.cpu}%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                <div 
                  className="bg-gradient-to-r from-cyan-600 to-cyan-400 h-2 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.cpu}%` }}
                ></div>
              </div>
            </div>

            {/* RAM Monitor */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-400">Redis cache usage</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.ram}%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                <div 
                  className="bg-gradient-to-r from-cyan-600 to-cyan-400 h-2 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.ram}%` }}
                ></div>
              </div>
            </div>

            {/* Disk Storage */}
            <div>
              <div className="flex justify-between text-xs font-mono mb-1">
                <span className="text-slate-400">MongoDB telemetry partition</span>
                <span className="text-cyan-400 font-semibold">{stats.systemStatus.disk}%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                <div 
                  className="bg-gradient-to-r from-cyan-600 to-cyan-400 h-2 rounded-full transition-all duration-500" 
                  style={{ width: `${stats.systemStatus.disk}%` }}
                ></div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Main Charts & Live Feed Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Timeline Bandwidth Chart */}
        <motion.div variants={itemVariants} className="glass-card p-6 rounded-2xl lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>Real-Time Bandwidth Ingestion</span>
            </h3>
            <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">LIVE ENGINE</span>
          </div>
          <div className="h-60">
            {memoizedTimelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={memoizedTimelineData}>
                  <defs>
                    <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} fontStyle="monospace" />
                  <YAxis stroke="#475569" fontSize={10} fontStyle="monospace" />
                  <Tooltip contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', color: '#f1f5f9' }} />
                  <Area type="monotone" dataKey="packets" stroke="#06b6d4" fillOpacity={1} fill="url(#colorTraffic)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-600 text-xs font-mono">
                Awaiting telemetry streams...
              </div>
            )}
          </div>
        </motion.div>

        {/* AI Assistant Chat Panel */}
        <motion.div variants={itemVariants}>
          <AIAssistantPanel recentAlerts={liveAlerts} />
        </motion.div>
      </div>

      {/* Threat Alert Streams & Packet Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat List Card */}
        <motion.div variants={itemVariants} className="glass-card p-6 rounded-2xl">
          <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-red-500" />
            <span>Incident Alert Stream (ClickHouse Replica)</span>
          </h3>
          <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
            {liveAlerts.length > 0 ? (
              liveAlerts.map((alert) => (
                <div 
                  key={alert._id || `alert-${alert.timestamp}-${alert.sourceIp}`} 
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-900 hover:border-slate-800/80 transition-all flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                        alert.severity === 'critical' ? 'bg-red-950/80 text-red-400 border border-red-800' :
                        alert.severity === 'high' ? 'bg-orange-950/80 text-orange-400 border border-orange-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="text-xs font-bold text-slate-200">{alert.threatType}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">{alert.description}</p>
                    <div className="flex items-center gap-4 mt-2 text-[9px] text-slate-500 font-mono">
                      <span>SRC: {alert.sourceIp}</span>
                      <span>DST: {alert.destIp}</span>
                    </div>
                  </div>
                  <span className="text-[9px] text-slate-500 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
              ))
            ) : (
              <p className="text-slate-600 text-xs font-mono text-center py-6">No threat alerts detected.</p>
            )}
          </div>
        </motion.div>

        {/* Live Packet Logs Feed */}
        <motion.div variants={itemVariants} className="glass-card p-6 rounded-2xl">
          <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>Raw Packet Traffic Telemetry</span>
          </h3>
          <div className="overflow-x-auto max-h-96 overflow-y-auto pr-2">
            <table className="w-full text-left text-[11px] font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 pb-2">
                  <th className="pb-2">TIME</th>
                  <th className="pb-2">PROTO</th>
                  <th className="pb-2">SOURCE IP</th>
                  <th className="pb-2">DEST IP</th>
                  <th className="pb-2 text-right">SIZE</th>
                </tr>
              </thead>
              <tbody>
                {liveTraffic.length > 0 ? (
                  liveTraffic.map((traffic) => (
                    <tr key={traffic._id || `traffic-${traffic.timestamp}-${traffic.sourceIp}`} className="border-b border-slate-900/60 hover:bg-slate-900/10 text-slate-300">
                      <td className="py-2 text-[10px] text-slate-500">{new Date(traffic.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2">
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[9px] font-bold text-cyan-400">
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
                    <td colSpan="5" className="text-center py-6 text-slate-600">Awaiting packet logs...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
};

export default Dashboard;

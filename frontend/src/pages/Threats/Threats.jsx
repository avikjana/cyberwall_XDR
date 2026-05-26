import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { AlertCircle, ShieldAlert, CheckCircle, Search, ExternalLink } from 'lucide-react';

const Threats = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ status: '', severity: '', threatType: '' });
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [noteText, setNoteText] = useState('');

  useEffect(() => {
    fetchAlerts();

    const socket = io('/', { path: '/socket.io' });
    socket.emit('join_soc');

    socket.on('new_alert', (newAlert) => {
      setAlerts(prev => [newAlert, ...prev]);
    });

    socket.on('alert_updated', (updatedAlert) => {
      setAlerts(prev => prev.map(a => a._id === updatedAlert._id ? updatedAlert : a));
      setSelectedAlert(prev => prev?._id === updatedAlert._id ? updatedAlert : prev);
    });

    return () => {
      socket.disconnect();
    };
  }, [filters]);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const queryParams = new URLSearchParams();
      if (filters.status) queryParams.append('status', filters.status);
      if (filters.severity) queryParams.append('severity', filters.severity);
      if (filters.threatType) queryParams.append('threatType', filters.threatType);

      const res = await axios.get(`/api/alerts?${queryParams.toString()}`);
      if (res.data.success) {
        setAlerts(res.data.data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledge = async (id) => {
    try {
      const res = await axios.put(`/api/alerts/${id}/acknowledge`, { notes: noteText });
      if (res.data.success) {
        setNoteText('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleResolve = async (id) => {
    try {
      const res = await axios.put(`/api/alerts/${id}/resolve`, { notes: noteText });
      if (res.data.success) {
        setNoteText('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const filteredAlerts = alerts.filter(alert => 
    alert.sourceIp.includes(searchTerm) || 
    alert.threatType.toLowerCase().includes(searchTerm.toLowerCase()) || 
    alert.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Alerts Directory */}
      <div className="lg:col-span-2 space-y-4">
        {/* Filters Header */}
        <div className="glass-card p-4 rounded-xl flex flex-wrap gap-4 items-center justify-between">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search by IP, type, or message..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 pl-11 pr-4 py-2 rounded-xl transition-all duration-300 outline-none text-sm"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={filters.severity}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
              className="bg-slate-950/60 border border-slate-800 text-slate-300 px-3 py-2 rounded-xl text-xs outline-none focus:border-cyber-accent"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              className="bg-slate-950/60 border border-slate-800 text-slate-300 px-3 py-2 rounded-xl text-xs outline-none focus:border-cyber-accent"
            >
              <option value="">All Statuses</option>
              <option value="active">Active</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Alerts List */}
        <div className="space-y-3">
          {loading ? (
            <div className="glass-card p-8 rounded-xl text-center text-slate-500 font-mono">
              Loading threat intelligence alerts...
            </div>
          ) : filteredAlerts.length > 0 ? (
            filteredAlerts.map(alert => (
              <div
                key={alert._id}
                onClick={() => setSelectedAlert(alert)}
                className={`glass-card p-4 rounded-xl cursor-pointer hover:neon-cyan-glow transition-all duration-300 border-l-4 ${
                  selectedAlert?._id === alert._id ? 'border-r-2 border-r-cyber-accent' : ''
                } ${
                  alert.severity === 'critical' ? 'border-l-red-500' :
                  alert.severity === 'high' ? 'border-l-orange-500' :
                  alert.severity === 'medium' ? 'border-l-amber-500' :
                  'border-l-cyan-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase ${
                      alert.status === 'active' ? 'bg-red-950 text-red-400 border border-red-900' :
                      alert.status === 'acknowledged' ? 'bg-amber-950 text-amber-400 border border-amber-900' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-900'
                    }`}>
                      {alert.status}
                    </span>
                    <h4 className="font-bold text-slate-200 text-sm">{alert.threatType}</h4>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {new Date(alert.timestamp).toLocaleString()}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1.5 truncate">{alert.description}</p>
                <div className="flex items-center gap-4 mt-2.5 text-[10px] text-slate-500 font-mono">
                  <span>Source: <strong className="text-slate-300">{alert.sourceIp}</strong></span>
                  <span>Destination: <strong className="text-slate-300">{alert.destIp}</strong></span>
                </div>
              </div>
            ))
          ) : (
            <div className="glass-card p-8 rounded-xl text-center text-slate-500 font-mono">
              No alert logs found matching filters.
            </div>
          )}
        </div>
      </div>

      {/* Threat Inspection Details Sidebar */}
      <div className="glass-card p-6 rounded-2xl h-fit">
        {selectedAlert ? (
          <div className="space-y-6">
            <div>
              <div className="flex items-center justify-between">
                <span className={`text-[10px] px-2.5 py-0.5 rounded font-mono font-bold uppercase ${
                  selectedAlert.severity === 'critical' ? 'bg-red-950 text-red-400 border border-red-800' :
                  selectedAlert.severity === 'high' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                  'bg-slate-800 text-slate-300'
                }`}>
                  {selectedAlert.severity} Severity
                </span>
                <span className="text-xs font-mono text-slate-500">ID: {selectedAlert._id.slice(-6)}</span>
              </div>
              <h3 className="text-xl font-bold text-white mt-3">{selectedAlert.threatType}</h3>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">{selectedAlert.description}</p>
            </div>

            <div className="border-t border-cyber-border pt-4 space-y-3 text-xs">
              <h4 className="font-bold text-slate-300 uppercase font-mono tracking-wider text-[10px]">Flow Attributes</h4>
              <div className="grid grid-cols-2 gap-3 font-mono">
                <div>
                  <span className="text-slate-500 text-[10px] block">SOURCE IP</span>
                  <span className="text-slate-300">{selectedAlert.sourceIp}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">DESTINATION IP</span>
                  <span className="text-slate-300">{selectedAlert.destIp}</span>
                </div>
              </div>
            </div>

            {selectedAlert.packetDetails && (
              <div className="border-t border-cyber-border pt-4">
                <h4 className="font-bold text-slate-300 uppercase font-mono tracking-wider text-[10px] mb-2">RAW Payload Frame</h4>
                <pre className="p-3 bg-slate-950/80 rounded-xl border border-slate-900 text-[10px] text-cyan-400 overflow-x-auto max-h-40 font-mono">
                  {JSON.stringify(selectedAlert.packetDetails, null, 2)}
                </pre>
              </div>
            )}

            {/* Threat Intelligence Integrations placeholders */}
            <div className="border-t border-cyber-border pt-4 space-y-2">
              <h4 className="font-bold text-slate-300 uppercase font-mono tracking-wider text-[10px]">Threat Intelligence Lookups</h4>
              <div className="grid grid-cols-3 gap-2">
                <a
                  href={`https://www.virustotal.com/gui/ip-address/${selectedAlert.sourceIp}`}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 bg-slate-900 border border-slate-800 text-[10px] font-mono text-center rounded-lg text-slate-400 hover:text-cyan-400 hover:border-cyan-800/50 transition-all flex items-center justify-center gap-1"
                >
                  VirusTotal <ExternalLink className="w-3 h-3" />
                </a>
                <a
                  href={`https://www.abuseipdb.com/check/${selectedAlert.sourceIp}`}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 bg-slate-900 border border-slate-800 text-[10px] font-mono text-center rounded-lg text-slate-400 hover:text-cyan-400 hover:border-cyan-800/50 transition-all flex items-center justify-center gap-1"
                >
                  AbuseIPDB <ExternalLink className="w-3 h-3" />
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/ip/${selectedAlert.sourceIp}`}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 bg-slate-900 border border-slate-800 text-[10px] font-mono text-center rounded-lg text-slate-400 hover:text-cyan-400 hover:border-cyan-800/50 transition-all flex items-center justify-center gap-1"
                >
                  AlienVault <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>

            <div className="border-t border-cyber-border pt-4 space-y-3">
              <h4 className="font-bold text-slate-300 uppercase font-mono tracking-wider text-[10px]">SOC Action Center</h4>
              {selectedAlert.notes && (
                <div className="p-3 bg-slate-900/60 border border-slate-800 text-xs rounded-xl text-slate-400">
                  <span className="font-bold text-slate-300 text-[10px] block font-mono mb-1">INVESTIGATION NOTES:</span>
                  {selectedAlert.notes}
                </div>
              )}
              
              {selectedAlert.status !== 'resolved' && (
                <div className="space-y-3">
                  <textarea
                    placeholder="Enter analytical review notes..."
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 p-2.5 rounded-xl text-xs outline-none focus:border-cyber-accent resize-none h-20"
                  />
                  <div className="grid grid-cols-2 gap-2">
                    {selectedAlert.status === 'active' && (
                      <button
                        onClick={() => handleAcknowledge(selectedAlert._id)}
                        className="py-2 px-3 bg-amber-950/30 hover:bg-amber-950/60 text-amber-400 border border-amber-900 hover:border-amber-800 text-xs font-bold rounded-xl transition-all"
                      >
                        Acknowledge
                      </button>
                    )}
                    <button
                      onClick={() => handleResolve(selectedAlert._id)}
                      className="py-2 px-3 bg-emerald-950/30 hover:bg-emerald-950/60 text-emerald-400 border border-emerald-900 hover:border-emerald-800 text-xs font-bold rounded-xl transition-all col-span-2 first-of-type:col-span-1"
                    >
                      Resolve Incident
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="h-96 flex flex-col items-center justify-center text-center text-slate-500 font-mono">
            <ShieldAlert className="w-12 h-12 text-slate-700 mb-3" />
            <p className="text-sm">Select an incident from directory list to query detailed payload attributes</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Threats;

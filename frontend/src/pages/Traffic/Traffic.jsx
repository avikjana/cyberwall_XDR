import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';
import { Play, Pause, Activity, Search } from 'lucide-react';

const Traffic = () => {
  const [traffic, setTraffic] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [protocolFilter, setProtocolFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Use ref for pause state so socket handler always reads current value
  // without needing to be a dependency (which causes socket reconnection)
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  // ─── Single socket connection — no dependency on isPaused ─────────────
  useEffect(() => {
    fetchInitialTraffic();

    const token = localStorage.getItem('token');
    const socket = io('/', { 
      path: '/socket.io',
      auth: { token }
    });
    socket.emit('join_soc');

    socket.on('new_traffic', (newPacket) => {
      // Read from ref instead of closure — always has the latest value
      if (!isPausedRef.current) {
        setTraffic(prev => [newPacket, ...prev.slice(0, 99)]); // Maintain max 100 rows in UI
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []); // Fixed: was [isPaused], creating a new socket on every pause toggle

  const fetchInitialTraffic = async () => {
    try {
      const res = await axios.get('/api/traffic?limit=50');
      if (res.data.success) {
        setTraffic(res.data.data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // ─── Memoized filtered traffic — only recomputes when inputs change ──
  const filteredTraffic = useMemo(() => {
    return traffic.filter(item => {
      const matchesProto = protocolFilter ? item.protocol === protocolFilter : true;
      const matchesSearch = searchTerm 
        ? item.sourceIp.includes(searchTerm) || item.destIp.includes(searchTerm)
        : true;
      return matchesProto && matchesSearch;
    });
  }, [traffic, protocolFilter, searchTerm]);

  return (
    <div className="space-y-6">
      {/* Search and Stream Controls */}
      <div className="glass-card p-4 rounded-xl flex flex-wrap gap-4 items-center justify-between">
        <div className="flex items-center gap-4 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search source or destination IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 pl-11 pr-4 py-2 rounded-xl transition-all duration-300 outline-none text-sm"
            />
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-slate-950/60 border border-slate-800 text-slate-300 px-3 py-2 rounded-xl text-xs outline-none focus:border-cyber-accent"
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="DNS">DNS</option>
          </select>
        </div>

        <button
          onClick={() => setIsPaused(!isPaused)}
          className={`flex items-center gap-2 py-2 px-4 rounded-xl border text-xs font-bold transition-all duration-300 ${
            isPaused
              ? 'bg-emerald-950/30 border-emerald-900 text-emerald-400 hover:bg-emerald-950/50'
              : 'bg-amber-950/30 border-amber-900 text-amber-400 hover:bg-amber-950/50'
          }`}
        >
          {isPaused ? (
            <>
              <Play className="w-4 h-4" />
              <span>Resume Stream</span>
            </>
          ) : (
            <>
              <Pause className="w-4 h-4" />
              <span>Pause Stream</span>
            </>
          )}
        </button>
      </div>

      {/* Traffic Table */}
      <div className="glass-card rounded-2xl overflow-hidden border border-cyber-border">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border bg-slate-900/60 text-slate-400 font-semibold">
                <th className="p-4">Timestamp</th>
                <th className="p-4">Protocol</th>
                <th className="p-4">Source Address</th>
                <th className="p-4">Source Port</th>
                <th className="p-4">Destination Address</th>
                <th className="p-4">Dest Port</th>
                <th className="p-4 text-right">Size</th>
                <th className="p-4">Flags / Payload details</th>
              </tr>
            </thead>
            <tbody>
              {filteredTraffic.length > 0 ? (
                filteredTraffic.map((pkt) => (
                  <tr key={pkt._id || `pkt-${pkt.timestamp}-${pkt.sourceIp}-${pkt.destPort}`} className="border-b border-slate-900/40 hover:bg-slate-900/20 text-slate-300">
                    <td className="p-4 text-slate-500 text-[11px]">
                      {new Date(pkt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        pkt.protocol === 'TCP' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' :
                        pkt.protocol === 'UDP' ? 'bg-indigo-950 text-indigo-400 border border-indigo-900' :
                        pkt.protocol === 'DNS' ? 'bg-purple-950 text-purple-400 border border-purple-900' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="p-4 font-semibold text-slate-200">{pkt.sourceIp}</td>
                    <td className="p-4 text-slate-400">{pkt.sourcePort || '-'}</td>
                    <td className="p-4 font-semibold text-slate-200">{pkt.destIp}</td>
                    <td className="p-4 text-slate-400">{pkt.destPort || '-'}</td>
                    <td className="p-4 text-right text-slate-500">{pkt.packetSize} B</td>
                    <td className="p-4 text-slate-400 max-w-[200px] truncate">
                      {pkt.flags && <span className="text-[10px] bg-slate-900 px-1 py-0.5 rounded border border-slate-800 mr-2">Flags: {pkt.flags}</span>}
                      {pkt.dnsQuery && <span className="text-[10px] text-cyan-400 font-mono">Q: {pkt.dnsQuery}</span>}
                      {!pkt.flags && !pkt.dnsQuery && <span className="text-slate-600">-</span>}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="8" className="text-center p-8 text-slate-500 font-mono">
                    Awaiting telemetry packet streams...
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

export default Traffic;

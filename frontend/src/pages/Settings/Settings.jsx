import React, { useState } from 'react';
import { Settings as SettingsIcon, Sliders, Shield, Zap, RefreshCw } from 'lucide-react';

const Settings = () => {
  const [portThreshold, setPortThreshold] = useState(15);
  const [synThreshold, setSynThreshold] = useState(40);
  const [dnsThreshold, setDnsThreshold] = useState(60);
  const [virustotalKey, setVirustotalKey] = useState('••••••••••••••••••••••••••••••••');
  const [abuseipKey, setAbuseipKey] = useState('••••••••••••••••••••••••••••••••');
  
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="glass-card p-6 rounded-2xl">
        <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-cyan-400" />
          <span>SOC Platform & Threat Detection Config</span>
        </h3>

        {saved && (
          <div className="p-3 mb-4 rounded-lg bg-emerald-950/30 border border-emerald-900 text-emerald-400 text-xs font-mono font-semibold">
            SUCCESS: IDS thresholds and API secret configurations synced successfully.
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-6">
          {/* Section 1: Thresholds */}
          <div className="space-y-4">
            <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-cyber-border pb-2">
              <Sliders className="w-4 h-4" />
              <span>IDS Scan & Flood Detection Thresholds</span>
            </h4>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase font-mono">Port Scan Threshold (Probed ports)</label>
                <input
                  type="number"
                  value={portThreshold}
                  onChange={(e) => setPortThreshold(parseInt(e.target.value))}
                  className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl outline-none focus:border-cyber-accent text-sm"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase font-mono">SYN Flood Threshold (Packets/5s)</label>
                <input
                  type="number"
                  value={synThreshold}
                  onChange={(e) => setSynThreshold(parseInt(e.target.value))}
                  className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl outline-none focus:border-cyber-accent text-sm"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase font-mono">DNS Tunnel Length (Chars)</label>
                <input
                  type="number"
                  value={dnsThreshold}
                  onChange={(e) => setDnsThreshold(parseInt(e.target.value))}
                  className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl outline-none focus:border-cyber-accent text-sm"
                />
              </div>
            </div>
          </div>

          {/* Section 2: Integrations */}
          <div className="space-y-4">
            <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-cyber-border pb-2">
              <Zap className="w-4 h-4" />
              <span>Third-party Threat Intelligence APIs</span>
            </h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase font-mono">VirusTotal Public API Key</label>
                <input
                  type="text"
                  value={virustotalKey}
                  onChange={(e) => setVirustotalKey(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl outline-none focus:border-cyber-accent text-sm"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1.5 uppercase font-mono">AbuseIPDB API Key</label>
                <input
                  type="text"
                  value={abuseipKey}
                  onChange={(e) => setAbuseipKey(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 text-slate-200 px-4 py-2.5 rounded-xl outline-none focus:border-cyber-accent text-sm"
                />
              </div>
            </div>
          </div>

          {/* Section 3: Diagnostic */}
          <div className="space-y-4">
            <h4 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-cyber-border pb-2">
              <Shield className="w-4 h-4" />
              <span>Firewall Engine Diagnostics</span>
            </h4>
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-2 text-xs font-mono text-slate-400">
              <div className="flex justify-between"><span className="text-slate-500">Capture Device:</span><span>eth0 (promiscuous mode)</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Blocking Subsystem:</span><span>iptables kernel netfilter driver</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Sniffer Engine Type:</span><span>Scapy Asynchronous Sniff Loop</span></div>
              <div className="flex justify-between"><span className="text-slate-500">IPC Method:</span><span>Bi-directional HTTP WebSockets</span></div>
            </div>
          </div>

          <button
            type="submit"
            className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl transition-all duration-300 shadow-cyan-glow text-sm"
          >
            Apply Config Changes
          </button>
        </form>
      </div>
    </div>
  );
};

export default Settings;

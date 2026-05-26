import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Send, Cpu, ShieldAlert, Sparkles, Database } from 'lucide-react';

const AIAssistantPanel = ({ recentAlerts = [] }) => {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: "Neural XDR SOC Analyst Agent 2040 online. Send telemetry alerts or query custom network security recommendations.",
      timestamp: new Date()
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const getAIResponse = (query) => {
    const q = query.toLowerCase();
    
    // Check if user clicked or typed about recent alerts
    if (q.includes('alert') || q.includes('recent') || q.includes('threat')) {
      if (recentAlerts.length === 0) {
        return "I've scanned the logs. Current active threat levels are nominal. No active incident alerts found in MongoDB.";
      }
      const top = recentAlerts[0];
      return `Telemetry Analysis: The most critical recent alert is a [${top.threatType}] from Source IP [${top.sourceIp}] targeting IP [${top.destIp}]. Severity: [${top.severity.toUpperCase()}]. AI Confidence: 89.2%. Recommended Action: Enable auto-blocking rules for ${top.sourceIp} and inspect packet headers for anomalous SYN flag payloads.`;
    }

    if (q.includes('harden') || q.includes('rule') || q.includes('block')) {
      return "Zero Trust Security Recommendations:\n1. Upgrade firewall rule defaults to BLOCK for suspicious Port Scan behaviors.\n2. Configure temporary 10-minute bans on IPs exceeding 40 SYN packets per window.\n3. Integrate AbuseIPDB to cross-reference known malicious ASNs.";
    }

    if (q.includes('anomaly') || q.includes('ai') || q.includes('isolation')) {
      return "AI Engine Status: Streaming Isolation Forest is modeling features (packets/sec, unique ports, packet sizes) in 10-second intervals. Normal baseline: mean 5.2 pps, variance 2.1. Deviations > 3.0 std-dev are automatically flagged as anomalies.";
    }

    return "Query parsed. I can assist you with MITRE ATT&CK mappings, firewall policies, IP reputation analysis, or explanation of recent packet spikes. What system log would you like to audit?";
  };

  const handleSend = (textToSend) => {
    if (!textToSend.trim()) return;

    const userMsg = {
      sender: 'user',
      text: textToSend,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMsg]);
    setInputText('');
    setIsTyping(true);

    setTimeout(() => {
      const responseText = getAIResponse(textToSend);
      const aiMsg = {
        sender: 'ai',
        text: responseText,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, aiMsg]);
      setIsTyping(false);
    }, 1200);
  };

  const suggestions = [
    { label: "Analyze Recent Threats", query: "Explain recent alerts" },
    { label: "Harden Firewall Rules", query: "How to harden rules" },
    { label: "AI Engine Metrics", query: "Explain AI anomaly model" }
  ];

  return (
    <div className="glass-card flex flex-col h-[400px] rounded-2xl border border-slate-800 overflow-hidden">
      {/* Header */}
      <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="text-xs font-mono font-bold tracking-widest text-cyan-400">AUTONOMOUS SOC AI AGENT</span>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/60">
          <Sparkles className="w-3 h-3 text-cyan-400" />
          <span className="text-[9px] font-mono text-cyan-400">GPT-XDR ACTIVE</span>
        </div>
      </div>

      {/* Message Feed */}
      <div className="flex-1 p-4 overflow-y-auto space-y-3 font-mono text-xs max-h-64">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`p-2.5 rounded-xl border max-w-[85%] ${
              msg.sender === 'ai'
                ? 'bg-slate-900/60 border-slate-800/80 text-cyan-300 mr-auto'
                : 'bg-cyan-950/40 border-cyan-800/40 text-cyan-100 ml-auto'
            }`}
          >
            <div className="flex items-center gap-1.5 mb-1 opacity-60 text-[9px]">
              {msg.sender === 'ai' ? <Cpu className="w-3 h-3" /> : <Terminal className="w-3 h-3" />}
              <span>{msg.sender === 'ai' ? 'NEURAL_XDR_AGENT' : 'ANALYST'}</span>
            </div>
            <p className="whitespace-pre-line leading-relaxed">{msg.text}</p>
          </div>
        ))}
        {isTyping && (
          <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-cyan-400 mr-auto max-w-[50px] flex justify-center gap-1 animate-pulse">
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce"></span>
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce delay-100"></span>
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce delay-200"></span>
          </div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Suggestions Row */}
      <div className="px-4 py-2 border-t border-slate-900 bg-slate-950/20 flex flex-wrap gap-1.5">
        {suggestions.map((s, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(s.query)}
            className="text-[10px] px-2 py-1 bg-slate-900 border border-slate-800 hover:border-cyan-800 text-slate-400 hover:text-cyan-400 rounded-lg font-mono transition-all"
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <div className="p-3 bg-slate-950/40 border-t border-slate-900 flex gap-2">
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend(inputText)}
          placeholder="Ask SOC AI Agent..."
          className="flex-1 bg-slate-900 border border-slate-800 focus:border-cyan-800 focus:outline-none rounded-xl px-3 py-1.5 text-xs text-white font-mono placeholder-slate-600"
        />
        <button
          onClick={() => handleSend(inputText)}
          className="p-2 bg-cyan-950 hover:bg-cyan-900 text-cyan-400 border border-cyan-800/80 rounded-xl transition-all"
        >
          <Send className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};

export default AIAssistantPanel;

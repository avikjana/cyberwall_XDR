import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, ShieldAlert } from 'lucide-react';

const ThreeDMap = ({ alerts = [] }) => {
  const canvasRef = useRef(null);
  const [beams, setBeams] = useState([]);

  // Generate a random laser beam whenever a new alert arrives
  useEffect(() => {
    if (alerts.length > 0) {
      const latest = alerts[0];
      const newBeam = {
        id: Date.now(),
        src: { x: Math.random() * 300 + 50, y: Math.random() * 100 + 50 },
        dst: { x: 220, y: 180 }, // Center target node
        type: latest.threatType,
        ip: latest.sourceIp,
        severity: latest.severity
      };
      setBeams(prev => [...prev, newBeam].slice(-5));
    }
  }, [alerts]);

  // Canvas-based global rotating grid background for the 3D feel
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationId;
    let rotation = 0;

    const resize = () => {
      canvas.width = canvas.parentElement.clientWidth || 400;
      canvas.height = 300;
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      rotation += 0.003;

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const radius = 100;

      // Draw futuristic coordinate grid rings
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.08)';
      ctx.lineWidth = 1;
      for (let r = 40; r < 200; r += 40) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Draw rotating longitude lines (creating a sphere coordinate effect)
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.12)';
      for (let i = 0; i < 6; i++) {
        const angle = rotation + (i * Math.PI) / 6;
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, radius, radius * Math.abs(Math.sin(angle)), 0, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Draw central shield target
      ctx.fillStyle = 'rgba(6, 182, 212, 0.1)';
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.6)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(centerX, centerY, 15, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      // Outer active ring
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.3)';
      ctx.setLineDash([5, 15]);
      ctx.beginPath();
      ctx.arc(centerX, centerY, 50, rotation * 2, rotation * 2 + Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      animationId = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div className="relative w-full h-[320px] bg-slate-950/40 rounded-2xl border border-slate-800/80 overflow-hidden flex items-center justify-center">
      {/* Background canvas grid */}
      <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none" />

      {/* Cyber radar scan overlay */}
      <div className="absolute inset-0 bg-gradient-to-t from-cyan-500/0 via-cyan-500/5 to-cyan-500/0 animate-pulse pointer-events-none" style={{ animationDuration: '4s' }} />

      {/* Title */}
      <div className="absolute top-4 left-6 flex items-center gap-2">
        <Globe className="w-4 h-4 text-cyan-400 animate-spin-slow" />
        <span className="text-xs font-mono font-bold tracking-widest text-cyan-400">GLOBAL ATTACK TELEMETRY MAP</span>
      </div>

      {/* Active attack vectors */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none">
        <defs>
          <linearGradient id="laser-red" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.2" />
          </linearGradient>
          <linearGradient id="laser-orange" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#f97316" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.2" />
          </linearGradient>
        </defs>
        <AnimatePresence>
          {beams.map(beam => {
            const grad = beam.severity === 'critical' || beam.severity === 'high' ? 'url(#laser-red)' : 'url(#laser-orange)';
            return (
              <React.Fragment key={beam.id}>
                {/* Attacker node */}
                <motion.circle
                  cx={beam.src.x}
                  cy={beam.src.y}
                  r={6}
                  fill={beam.severity === 'critical' ? '#ef4444' : '#f97316'}
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: [1, 1.8, 1], opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 1 }}
                />
                {/* Threat type text overlay */}
                <motion.text
                  x={beam.src.x + 10}
                  y={beam.src.y - 5}
                  fill="#94a3b8"
                  fontSize="9"
                  fontFamily="monospace"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                >
                  {beam.ip} ({beam.type})
                </motion.text>
                {/* Laser beam path */}
                <motion.line
                  x1={beam.src.x}
                  y1={beam.src.y}
                  x2={beam.dst.x}
                  y2={beam.dst.y}
                  stroke={grad}
                  strokeWidth={2}
                  strokeDasharray="8 4"
                  initial={{ strokeDashoffset: 100, opacity: 0 }}
                  animate={{ strokeDashoffset: 0, opacity: [0.2, 1, 0.2] }}
                  exit={{ opacity: 0 }}
                  transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
                />
              </React.Fragment>
            );
          })}
        </AnimatePresence>
      </svg>

      {/* Target status tag */}
      <div className="absolute bottom-4 right-6 bg-slate-900/80 border border-slate-700/60 rounded px-3 py-1 flex items-center gap-2">
        <ShieldAlert className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
        <span className="text-[10px] font-mono text-slate-300">SHIELD TARGET: SOC_HOST (192.168.1.100)</span>
      </div>
    </div>
  );
};

export default ThreeDMap;

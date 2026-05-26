import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Shield, Lock, Mail, User, AlertCircle } from 'lucide-react';

const AuthPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { login, register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      if (isLogin) {
        await login(email, password);
      } else {
        await register(username, email, password, role);
      }
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication failed. Please verify credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4 relative overflow-hidden bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-cyber-bg to-cyber-bg">
      {/* Background Matrix/Hex Deco */}
      <div className="absolute inset-0 opacity-[0.02] bg-[linear-gradient(to_right,#808080_1px,transparent_1px),linear-gradient(to_bottom,#808080_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none"></div>

      <div className="w-full max-w-md glass-card rounded-2xl p-8 relative z-10 shadow-cyan-glow border border-slate-700/80">
        <div className="flex flex-col items-center mb-8">
          <div className="p-3 bg-cyan-950 text-cyber-accent rounded-2xl mb-4 border border-cyan-800/50 neon-cyan-glow">
            <Shield className="w-8 h-8 animate-pulse" />
          </div>
          <h2 className="text-3xl font-extrabold text-white tracking-wider text-center">
            CYBERWALL XDR
          </h2>
          <p className="text-slate-400 text-xs mt-2 uppercase tracking-widest font-mono">SOC Portal Gateway</p>
        </div>

        {error && (
          <div className="p-3 mb-4 rounded-lg bg-red-950/40 border border-red-900 text-red-400 text-sm flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {!isLogin && (
            <div>
              <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">Username</label>
              <div className="relative">
                <User className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  required
                  placeholder="analyst_zero"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent text-slate-200 pl-11 pr-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
              <input
                type="email"
                required
                placeholder="analyst@cyberwall.io"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent text-slate-200 pl-11 pr-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">Security Password</label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-3 w-4 h-4 text-slate-500" />
              <input
                type="password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent text-slate-200 pl-11 pr-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm"
              />
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-mono font-semibold text-slate-400 mb-1.5 uppercase">SOC Operating Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent text-slate-300 px-4 py-2.5 rounded-xl transition-all duration-300 outline-none text-sm appearance-none"
              >
                <option value="analyst" className="bg-slate-950">Tier 1 SOC Analyst</option>
                <option value="admin" className="bg-slate-950">SOC Manager (Admin)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 mt-6 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-xl transition-all duration-300 shadow-cyan-glow hover:shadow-cyan-glow/80 active:scale-[0.98]"
          >
            {submitting ? 'Verifying Gateway...' : isLogin ? 'Access SOC Dashboard' : 'Provision Analyst Profile'}
          </button>
        </form>

        <div className="mt-6 text-center text-xs">
          <button
            onClick={() => setIsLogin(!isLogin)}
            className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4"
          >
            {isLogin ? 'Provision new analyst credentials' : 'Already provisioned? Authenticate here'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default AuthPage;

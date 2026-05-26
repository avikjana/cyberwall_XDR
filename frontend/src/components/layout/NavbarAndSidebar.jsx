import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { 
  Shield, 
  LayoutDashboard, 
  AlertOctagon, 
  Activity, 
  BarChart3, 
  Ban, 
  Settings, 
  LogOut,
  User
} from 'lucide-react';

const NavbarAndSidebar = ({ children }) => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Threat Center', path: '/threats', icon: AlertOctagon },
    { name: 'Live Traffic', path: '/traffic', icon: Activity },
    { name: 'Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Incident Control', path: '/incident-response', icon: Ban },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-cyber-bg">
      {/* Sidebar */}
      <aside className="w-64 glass-card border-r border-cyber-border flex flex-col justify-between">
        <div>
          {/* Logo Header */}
          <div className="p-6 flex items-center gap-3 border-b border-cyber-border">
            <div className="p-2 bg-cyan-950 text-cyber-accent rounded-xl neon-cyan-glow">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="font-extrabold text-lg leading-tight tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-white to-cyan-400">
                CYBERWALL
              </h1>
              <span className="text-[10px] text-cyan-400 font-mono tracking-widest uppercase">XDR PLATFORM</span>
            </div>
          </div>

          {/* Navigation links */}
          <nav className="p-4 space-y-1">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-950/60 to-slate-900 text-cyan-400 border-l-4 border-cyber-accent font-medium shadow-cyan-glow'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border-l-4 border-transparent'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* User Footer Profile */}
        <div className="p-4 border-t border-cyber-border bg-slate-950/40">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-bold uppercase">
                {user?.username?.[0] || 'U'}
              </div>
              <div className="truncate w-32">
                <p className="text-sm font-semibold text-slate-200 truncate">{user?.username}</p>
                <span className="text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded-full font-mono font-semibold uppercase">
                  {user?.role}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-red-950/30 hover:bg-red-950/60 text-red-400 border border-red-900/50 hover:border-red-800 rounded-xl transition-all duration-300 text-sm font-semibold"
          >
            <LogOut className="w-4 h-4" />
            <span>Terminate Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 glass-card border-b border-cyber-border px-8 flex items-center justify-between z-10">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white capitalize">
              {location.pathname === '/' ? 'System Overview' : location.pathname.substring(1).replace('-', ' ')}
            </h2>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-950/30 border border-emerald-900 text-emerald-400 text-xs font-mono font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span>FIREWALL ONLINE</span>
            </div>
            <div className="text-right text-xs text-slate-400 font-mono">
              <p>UTC: {new Date().toISOString().substring(0, 10)}</p>
            </div>
          </div>
        </header>

        {/* Content Box */}
        <main className="flex-1 overflow-y-auto p-8 bg-gradient-to-b from-[#0d1425] to-cyber-bg">
          {children}
        </main>
      </div>
    </div>
  );
};

export default NavbarAndSidebar;

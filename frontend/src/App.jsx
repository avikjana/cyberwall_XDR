import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';

import AuthPage from './pages/Auth/AuthPage';
import Dashboard from './pages/Dashboard/Dashboard';
import Threats from './pages/Threats/Threats';
import Traffic from './pages/Traffic/Traffic';
import Analytics from './pages/Analytics/Analytics';
import IncidentResponse from './pages/IncidentResponse/IncidentResponse';
import Settings from './pages/Settings/Settings';
import NavbarAndSidebar from './components/layout/NavbarAndSidebar';

// Route protection component
const ProtectedRoute = ({ children }) => {
  const { token, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center font-mono text-slate-500 text-xs">
        🛡️ INITIALIZING CYBERWALL SECURE GATEWAY...
      </div>
    );
  }
  
  return token ? <NavbarAndSidebar>{children}</NavbarAndSidebar> : <Navigate to="/login" replace />;
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Guest Gateway */}
          <Route path="/login" element={<AuthPage />} />

          {/* Secure XDR Operations */}
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/threats" element={<ProtectedRoute><Threats /></ProtectedRoute>} />
          <Route path="/traffic" element={<ProtectedRoute><Traffic /></ProtectedRoute>} />
          <Route path="/analytics" element={<ProtectedRoute><Analytics /></ProtectedRoute>} />
          <Route path="/incident-response" element={<ProtectedRoute><IncidentResponse /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />

          {/* Catch-all fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;

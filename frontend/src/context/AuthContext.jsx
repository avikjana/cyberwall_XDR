import React, { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchUserProfile();
    } else {
      delete axios.defaults.headers.common['Authorization'];
      setLoading(false);
    }
  }, [token]);

  // ─── Axios interceptor for automatic token refresh on 401 ──────────
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        // If we get a 401 and haven't already retried, attempt token refresh
        if (error.response?.status === 401 && !originalRequest._retry && originalRequest.url !== '/api/auth/refresh') {
          originalRequest._retry = true;
          const refreshToken = localStorage.getItem('refreshToken');

          if (refreshToken) {
            try {
              const res = await axios.post('/api/auth/refresh', { refreshToken });
              if (res.data.success) {
                const newToken = res.data.token;
                localStorage.setItem('token', newToken);
                setToken(newToken);
                axios.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
                originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                return axios(originalRequest);
              }
            } catch (refreshError) {
              // Refresh failed — force logout
              logout();
              return Promise.reject(refreshError);
            }
          }
        }

        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, []);

  const fetchUserProfile = async () => {
    try {
      // Pointing directly to our express API (or Nginx proxy)
      const res = await axios.get('/api/auth/me');
      setUser(res.data.user);
    } catch (err) {
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = useCallback(async (email, password) => {
    const res = await axios.post('/api/auth/login', { email, password });
    if (res.data.success) {
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('refreshToken', res.data.refreshToken);
      setToken(res.data.token);
      setUser(res.data.user);
    }
    return res.data;
  }, []);

  const register = useCallback(async (username, email, password, role) => {
    const res = await axios.post('/api/auth/register', { username, email, password, role });
    if (res.data.success) {
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('refreshToken', res.data.refreshToken);
      setToken(res.data.token);
      setUser(res.data.user);
    }
    return res.data;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    setToken(null);
    setUser(null);
  }, []);

  // ─── Memoize context value to prevent unnecessary consumer re-renders ──
  const contextValue = useMemo(() => ({
    user, token, loading, login, register, logout
  }), [user, token, loading, login, register, logout]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

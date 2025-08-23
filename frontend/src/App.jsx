import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';

import Layout from './components/layout/Layout';
import Registration from './pages/Registration';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import SendMoney from './pages/SendMoney';
import SecurityDetails from './pages/SecurityDetails';
import Transactions from './pages/Transactions';
import Cards from './pages/Cards';
import NotFound from './pages/NotFound';
import ServerError from './pages/ServerError';
import SecureCipherLanding from './pages/LandingPage';
import ErrorBoundary from './components/common/ErrorBoundary';
import './App.css';

function AppRoutes() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  const checkAuth = () => {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    setIsAuthenticated(isLoggedIn);
    setAuthChecked(true);
  };

  useEffect(() => {
    checkAuth();

    // Listen for auth changes from other tabs or components
    const handleStorageChange = (event) => {
      if (event.key === 'isLoggedIn') {
        checkAuth();
      }
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const ProtectedRoute = ({ children }) => {
    if (!authChecked) return null;
    return isAuthenticated ? <Layout>{children}</Layout> : <Navigate to="/login" />;
  };

  return (
    <Routes>
        <Route
          path=""
          element={
            authChecked
              ? isAuthenticated
                ? <Navigate to="/index" />
                : <Navigate to="/index" />
              : null
          }
        />
      {/* Public */}
      <Route path="/register" element={<Registration />} />
      <Route path="/login" element={<Login />} />

      {/* Protected */}
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/index" element={<SecureCipherLanding />} />
      <Route path="/send-money" element={<ProtectedRoute><SendMoney /></ProtectedRoute>} />
      <Route path="/security-details" element={<ProtectedRoute><SecurityDetails /></ProtectedRoute>} />
      <Route path="/transactions" element={<ProtectedRoute><Transactions /></ProtectedRoute>} />
      <Route path="/cards" element={<ProtectedRoute><Cards /></ProtectedRoute>} />

      {/* Errors */}
      <Route path="/server-error" element={<ServerError />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Router>
        <AppRoutes />
      </Router>
    </ErrorBoundary>
  );
}

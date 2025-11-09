import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect, Suspense, lazy } from 'react';

import Layout from './components/layout/Layout';
import ErrorBoundary from './components/common/ErrorBoundary';
import './App.css';

// Lazy load components for code splitting
const Registration = lazy(() => import('./pages/Registration'));
const Login = lazy(() => import('./pages/Login'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const SendMoney = lazy(() => import('./pages/SendMoney'));
const SecurityDetails = lazy(() => import('./pages/SecurityDetails'));
const Transactions = lazy(() => import('./pages/Transactions'));
const Cards = lazy(() => import('./pages/Cards'));
const NotFound = lazy(() => import('./pages/NotFound'));
const ServerError = lazy(() => import('./pages/ServerError'));
const SecureCipherLanding = lazy(() => import('./pages/LandingPage'));

// Loading component for Suspense fallback
const LoadingSpinner = () => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
      <p className="mt-4 text-gray-600">Loading SecureCipher...</p>
    </div>
  </div>
);

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
        <Suspense fallback={<LoadingSpinner />}>
          <AppRoutes />
        </Suspense>
      </Router>
    </ErrorBoundary>
  );
}

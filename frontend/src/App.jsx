import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';

// Layouts
import Layout from './components/layout/Layout';

// Pages
import Registration from './pages/Registration';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import SendMoney from './pages/SendMoney';
import SecurityDetails from './pages/SecurityDetails';
import Transactions from './pages/Transactions';
import NotFound from './pages/NotFound';
import ServerError from './pages/ServerError';
import Cards from './pages/Cards';

// Error Handling
import ErrorBoundary from './components/common/ErrorBoundary';

// Styles
import './App.css';

function AppRoutes() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const checkAuth = () => {
    const userProfile = localStorage.getItem('userProfile');
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const authenticated = Boolean(userProfile && isLoggedIn);
    setIsAuthenticated(authenticated);
    return authenticated;
  };

  useEffect(() => {
    checkAuth(); // Initial check
    
    // Listen for storage events (from other tabs)
    const handleStorageChange = () => {
      checkAuth();
    };
    
    window.addEventListener('storage', handleStorageChange);
    
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  // Helper function for protected routes
  const ProtectedRoute = ({ children }) => {
    return isAuthenticated ? (
      <Layout>
        {children}
      </Layout>
    ) : <Navigate to="/register" />;
  };

  return (
    <Routes>
      {/* Root redirect */}
      <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Navigate to="/register" />} />

      {/* Public routes */}
      <Route path="/register" element={<Registration />} />
      <Route 
        path="/login" 
        element={
          <Login 
            isAuthenticated={isAuthenticated} 
            userProfile={JSON.parse(localStorage.getItem('userProfile') || 'null')}
            onAuthChange={checkAuth} // Pass callback to update auth state
          />
        } 
      />

      {/* Protected routes - now all using the same authentication logic */}
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/send-money" element={<ProtectedRoute><SendMoney /></ProtectedRoute>} />
      <Route path="/security-details" element={<ProtectedRoute><SecurityDetails /></ProtectedRoute>} />
      <Route path="/transactions" element={<ProtectedRoute><Transactions /></ProtectedRoute>} />
      <Route path="/cards" element={<ProtectedRoute><Cards /></ProtectedRoute>} />

      {/* Error routes */}
      <Route path="/server-error" element={<ServerError />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <Router>
        <AppRoutes />
      </Router>
    </ErrorBoundary>
  );
}

export default App;
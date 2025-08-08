import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Layouts
import Layout from './components/layout/Layout';

// Common Components

// Pages
import Registration from './pages/Registration';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import SendMoney from './pages/SendMoney';
import SecurityDetails from './pages/SecurityDetails';
import Settings from './pages/Settings';
import NotFound from './pages/NotFound';
import ServerError from './pages/ServerError';

// Error Handling
import ErrorBoundary from './components/common/ErrorBoundary';

// Styles
import './App.css';

import RecentTransactions from './components/dashboard/RecentTransactions';

function AppRoutes() {
  // Use localStorage for authentication check
  const isAuthenticated = !!localStorage.getItem('userProfile');
  return (
    <Routes>
      {/* Root redirect: send new users to register, authenticated users to dashboard */}
      <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Navigate to="/register" />} />
      
      {/* Public routes */}
      <Route path="/register" element={<Registration />} /> 
      <Route path="/login" element={<Login />} />
      

      
      {/* Protected routes with Layout */}
      <Route path="/dashboard" element={
        <Layout>
          <Dashboard />
        </Layout>
      } />
      <Route path="/send-money" element={
        <Layout>
          <SendMoney />
        </Layout>
      } />
      <Route path="/security" element={
        <Layout>
          <SecurityDetails />
        </Layout>
      } />
      <Route path="/settings" element={
        <Layout>
          <Settings />
        </Layout>
      } />
      
      {/* Placeholder routes for future features */}
      <Route path="/cards" element={
        <Layout>
          <div className="p-6 text-center">
            <h1 className="text-2xl font-semibold text-gray-800 mb-4">My Cards</h1>
            <p className="text-gray-600">This feature is coming soon.</p>
          </div>
        </Layout>
      } />
      <Route path="/transactions" element={
        <Layout>
          <div className="p-6 text-center">
            <RecentTransactions />
          </div>
        </Layout>
      } />
      
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

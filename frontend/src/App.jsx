import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState } from 'react';

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
  const isAuthenticated = !!(localStorage.getItem('userProfile') && localStorage.getItem('userTransactions'));

  return (
    <Routes>
      {/* Root redirect */}
      <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Navigate to="/register" />} />
      
      {/* Public routes */}
      <Route path="/register" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Registration />} />
      <Route path="/login" element={isAuthenticated ? <Navigate to="/dashboard" /> : <Login />} />

      {/* Protected routes */}
      <Route path="/dashboard" element={isAuthenticated ? (
        <Layout>
          <Dashboard />
        </Layout>
      ) : <Navigate to="/register" />} />
      <Route path="/send-money" element={isAuthenticated ? (
        <Layout>
          <SendMoney />
        </Layout>
      ) : <Navigate to="/register" />} />
      <Route path="/security-details" element={isAuthenticated ? (
        <Layout>
          <SecurityDetails />
        </Layout>
      ) : <Navigate to="/register" />} />
      <Route path="/transactions" element={isAuthenticated ? (
        <Layout>
          <Transactions />
        </Layout>
      ) : <Navigate to="/register" />} />
      <Route path="/cards" element={isAuthenticated ? (
        <Layout>
          <Cards />
        </Layout>
      ) : <Navigate to="/register" />} />

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

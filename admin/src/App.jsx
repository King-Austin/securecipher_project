import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';

import Layout from './components/Layout';

import Dashboard from './pages/Dashboard';


import './App.css';

function AppRoutes() {

  return (
    <Routes>

      <Route path="/login" element={<Login />} />

      {/* Protected */}
      <Route path="/dashboard" element={<Layout><Dashboard /></Layout>} />


      {/* Errors */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default function App() {
  return (
      <Router>
        <AppRoutes />
      </Router>
  );
}

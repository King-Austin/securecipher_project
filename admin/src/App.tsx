import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "sonner";
import Index from "./pages/Index";
import CryptoAdmin from "./pages/CryptoAdmin";
import Dashboard from "./components/Dashboard";
import KeyManagement from "./components/KeyManagement";
import Transactions from "./components/Transactions";
import Security from "./components/Security";
import Logs from "./components/Logs";
import { AuthProvider } from "./context/AuthContext";

const App = () => (
  <AuthProvider>
    <Toaster richColors position="top-right" />
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Index />} />
        <Route path="/crypto-admin" element={<CryptoAdmin />}>
          <Route index element={<Dashboard />} /> 
          <Route path="keys" element={<KeyManagement />} />
          <Route path="transactions" element={<Transactions />} />
          <Route path="logs" element={<Logs />} />
          <Route path="security" element={<Security />} />
        </Route>
        <Route path="*" element={<div className="flex items-center justify-center min-h-screen text-xl">Page Not Found</div>} />
      </Routes>
    </BrowserRouter>
  </AuthProvider>
);

export default App;
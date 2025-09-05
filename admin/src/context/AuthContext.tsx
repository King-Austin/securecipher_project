import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from "react";

interface User {
  id: string;
  username: string;
  email: string;
}


// // Uncomment this for local development
// const MIDDLEWARE_URL = 'http://localhost:8000'; 
// const SERVER_URL = "http://localhost:8001"; 


const MIDDLEWARE_URL = "https://middleware.securecipher.app";
const SERVER_URL = "https://bankingapi.securecipher.app";

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  rotateKey: (reason: string) => Promise<any | null>;
  dashboardData: any | null;
  bankingDashboardData: any | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [dashboardData, setDashboardData] = useState<any | null>(null);
  const [bankingDashboardData, setBankingDashboardData] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(
    localStorage.getItem("isAuthenticated") === "true"
  );

  const apiCall = useCallback(async (url: string, options?: RequestInit) => {
    try {
      const response = await fetch(url, {
        headers: {
          "Content-Type": "application/json",
          ...options?.headers,
        },
        ...options,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (err) {
      console.error(`API call failed to ${url}:`, err);
      throw err;
    }
  }, []);

  useEffect(() => {
    const loadStoredData = () => {
      try {
        const storedDashboard = localStorage.getItem("dashboardData");
        const storedBanking = localStorage.getItem("bankingDashboard");
        const savedUser = localStorage.getItem("user");
        
        if (storedDashboard) setDashboardData(JSON.parse(storedDashboard));
        if (storedBanking) setBankingDashboardData(JSON.parse(storedBanking));
        if (savedUser) setUser(JSON.parse(savedUser));
      } catch (err) {
        console.error("Failed to parse stored data:", err);
      }
    };

    loadStoredData();
  }, []);

  const fetchDashboard = useCallback(async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall(`${MIDDLEWARE_URL}/api/admin/`);
      localStorage.setItem("dashboardData", JSON.stringify(data));
      setDashboardData(data);
      return data;
    } catch (err) {
      console.error("Fetch middleware dashboard error:", err);
      return null;
    }
  }, [isAuthenticated, apiCall]);

  const fetchBankingDashboard = useCallback(async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall(`${SERVER_URL}/admin-dashboard`);
      localStorage.setItem("bankingDashboard", JSON.stringify(data));
      setBankingDashboardData(data);
      return data;
    } catch (err) {
      console.error("Fetch banking dashboard error:", err);
      return null;
    }
  }, [isAuthenticated, apiCall]);

  useEffect(() => {
    const fetchAllData = async () => {
      if (!isAuthenticated) return;
      
      try {
        await fetchDashboard();
        await fetchBankingDashboard();
      } catch (err) {
        console.error("Auto-fetch failed:", err);
      }
    };

    fetchAllData();

    // Set up polling for real-time updates
    const interval = setInterval(fetchAllData, 5000);
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    setLoading(true);
    setError(null);

    try {
      const data = await apiCall(`${MIDDLEWARE_URL}/api/login/`, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });

      if (data.authenticated) {
        setUser(data.user);
        setIsAuthenticated(true);
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("user", JSON.stringify(data.user));
        return true;
      }
      return false;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      return false;
    } finally {
      setLoading(false);
    }
  }, [apiCall]);

  const logout = useCallback(() => {
    setUser(null);
    setIsAuthenticated(false);
    setDashboardData(null);
    setBankingDashboardData(null);
    setError(null);
    localStorage.clear();
  }, []);

  const rotateKey = useCallback(async (reason: string): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall(`${MIDDLEWARE_URL}/api/rotate-key/`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      
      localStorage.setItem("dashboardData", JSON.stringify(data));
      setDashboardData(data);
      return data;
    } catch (err) {
      console.error("Rotate key error:", err);
      return null;
    }
  }, [isAuthenticated, apiCall]);

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        rotateKey,
        dashboardData,
        bankingDashboardData,
        isAuthenticated,
        loading,
        error,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
};
import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from "react";

interface User {
  id: string;
  username: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  rotateKey: (reason: string) => Promise<any | null>;
  fetchDashboard: () => Promise<any | null>;
  fetchBankingDashboard: () => Promise<any | null>;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(
    localStorage.getItem("isAuthenticated") === "true"
  );

  // Memoized API call function
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
    if (isAuthenticated && !user) {
      const savedUser = localStorage.getItem("user");
      if (savedUser) {
        try {
          setUser(JSON.parse(savedUser));
        } catch (err) {
          console.error("Failed to parse saved user:", err);
          logout();
        }
      }
    }
  }, [isAuthenticated, user]);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    setLoading(true);
    setError(null);

    try {
      const data = await apiCall("https://securecipher-middleware.onrender.com/api/login/", {
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
    setError(null);
    localStorage.clear();
  }, []);

  const rotateKey = useCallback(async (reason: string): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall("https://securecipher-middleware.onrender.com/api/rotate-key/", {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      
      localStorage.setItem("dashboardData", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Rotate key error:", err);
      return null;
    }
  }, [isAuthenticated, apiCall]);

  const fetchDashboard = useCallback(async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall("https://securecipher-middleware.onrender.com/api/admin/");
      localStorage.setItem("dashboardData", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Fetch middleware dashboard error:", err);
      return null;
    }
  }, [isAuthenticated, apiCall]);

  const fetchBankingDashboard = useCallback(async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    
    try {
      const data = await apiCall("https://securecipher-server.onrender.com/admin-dashboard");
      localStorage.setItem("bankingDashboard", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Fetch banking dashboard error:", err);
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
        fetchDashboard,
        fetchBankingDashboard,
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
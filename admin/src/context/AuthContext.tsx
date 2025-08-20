// context/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

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
  fetchDashboard: () => Promise<any | null>;        // middleware dashboard
  fetchBankingDashboard: () => Promise<any | null>; // banking dashboard
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(
    localStorage.getItem("isAuthenticated") === "true"
  );

  useEffect(() => {
    if (isAuthenticated && !user) {
      const savedUser = localStorage.getItem("user");
      if (savedUser) setUser(JSON.parse(savedUser));
    }
  }, [isAuthenticated, user]);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      const res = await fetch("https://securecipher-middleware.onrender.com/api/login/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) return false;
      const data = await res.json();

      if (data.authenticated) {
        setUser(data.user);
        setIsAuthenticated(true);
        localStorage.setItem("isAuthenticated", "true");
        localStorage.setItem("user", JSON.stringify(data.user));
        return true;
      }
      return false;
    } catch (err) {
      console.error("Login error:", err);
      return false;
    }
  };

  const logout = () => {
    setUser(null);
    setIsAuthenticated(false);
    localStorage.clear();
  };

  const rotateKey = async (reason: string): Promise<any | null> => {
    if (!isAuthenticated) return null;
    try {
      const res = await fetch("https://securecipher-middleware.onrender.com/api/rotate-key/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      if (!res.ok) return null;
      const data = await res.json();
      localStorage.setItem("dashboardData", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Rotate key error:", err);
      return null;
    }
  };

  const fetchDashboard = async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    try {
      const res = await fetch("https://securecipher-middleware.onrender.com/api/admin/");
      if (!res.ok) return null;
      const data = await res.json();
      localStorage.setItem("dashboardData", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Fetch middleware dashboard error:", err);
      return null;
    }
  };

  const fetchBankingDashboard = async (): Promise<any | null> => {
    if (!isAuthenticated) return null;
    try {
      const res = await fetch("https://securecipher-server.onrender.com/admin-dashboard");
      if (!res.ok) return null;
      const data = await res.json();
      localStorage.setItem("bankingDashboard", JSON.stringify(data));
      return data;
    } catch (err) {
      console.error("Fetch banking dashboard error:", err);
      return null;
    }
  };

  return (
    <AuthContext.Provider
      value={{ user, login, logout, rotateKey, fetchDashboard, fetchBankingDashboard, isAuthenticated }}
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

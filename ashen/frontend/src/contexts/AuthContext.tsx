import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from "react";
import { auth as authApi, ApiError } from "@/lib/api";

export type UserRole = "analyst" | "admin";

interface User {
  email: string;
  name: string;
  role: UserRole;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Error message from the last login attempt */
  loginError: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/** Decode a JWT payload without verifying signature (browser-side) */
function decodePayload(token: string): Record<string, unknown> | null {
  try {
    const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(base64));
  } catch {
    return null;
  }
}

/** Build a User object from a JWT token */
function userFromToken(token: string): User | null {
  const payload = decodePayload(token);
  if (!payload || !payload.sub || !payload.role) return null;

  // Check expiry
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) return null;

  return {
    email: payload.sub as string,
    name: (payload.sub as string).split("@")[0], // derive name from email
    role: (payload.role as string).toLowerCase() as UserRole,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true); // true until rehydration check
  const [loginError, setLoginError] = useState<string | null>(null);

  // Rehydrate session from localStorage on mount
  useEffect(() => {
    const token = localStorage.getItem("ashen_token");
    if (token) {
      const restored = userFromToken(token);
      if (restored) {
        setUser(restored);
      } else {
        // Token expired or invalid — clean up
        localStorage.removeItem("ashen_token");
      }
    }
    setIsLoading(false);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setLoginError(null);
    try {
      const res = await authApi.login(email, password);
      localStorage.setItem("ashen_token", res.access_token);
      const u = userFromToken(res.access_token);
      if (!u) throw new Error("Invalid token received");
      setUser(u);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Login failed. Check your credentials.";
      setLoginError(msg);
      throw e;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      if (user?.role === "admin") {
        await authApi.adminLogout();
      } else {
        await authApi.userLogout();
      }
    } catch {
      // Even if backend call fails, clear local session
    }
    localStorage.removeItem("ashen_token");
    setUser(null);
  }, [user?.role]);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: !!user, isLoading, login, logout, loginError }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

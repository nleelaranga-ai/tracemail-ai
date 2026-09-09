import { create } from "zustand";
import type { User } from "@/types";

interface AuthState {
  token: string | null;
  user: User | null;
  hydrate: () => void;
  setSession: (token: string, user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  user: null,
  hydrate: () => {
    if (typeof window === "undefined") return;
    const token = window.localStorage.getItem("tm_token");
    const userRaw = window.localStorage.getItem("tm_user");
    if (token && userRaw) {
      set({ token, user: JSON.parse(userRaw) as User });
    }
  },
  setSession: (token, user) => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem("tm_token", token);
      window.localStorage.setItem("tm_user", JSON.stringify(user));
    }
    set({ token, user });
  },
  logout: () => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem("tm_token");
      window.localStorage.removeItem("tm_user");
    }
    set({ token: null, user: null });
  }
}));

"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/store/authStore";
import { api } from "@/services/api";

export function useAuth() {
  const { token, user, hydrate, setSession, logout } = useAuthStore();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    hydrate();
    setReady(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const router = useRouter();

  async function login(email: string, password: string) {
    const res = await api.login(email, password);
    setSession(res.token, res.user);
    router.push("/dashboard");
  }

  async function register(email: string, password: string) {
    const res = await api.register(email, password);
    setSession(res.token, res.user);
    router.push("/dashboard");
  }

  function signOut() {
    logout();
    router.push("/login");
  }

  return { token, user, ready, isAuthenticated: !!token, login, register, signOut };
}

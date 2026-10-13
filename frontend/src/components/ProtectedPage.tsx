"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import BrandNav from "@/components/BrandNav";
import { apiFetch, readError, type User } from "@/lib/api";

export default function ProtectedPage({
  children,
  adminOnly = false,
}: {
  children: (user: User) => ReactNode;
  adminOnly?: boolean;
}) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const response = await apiFetch("/auth/me");
        if (response.status === 401) {
          window.localStorage.removeItem("coreworks_access_token");
          router.replace("/login");
          return;
        }
        if (!response.ok) throw new Error(await readError(response));
        const current = (await response.json()) as User;
        if (!active) return;
        if (adminOnly && current.role !== "admin") {
          router.replace("/dashboard");
          return;
        }
        setUser(current);
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : "Greška pri povezivanju.");
      }
    }
    load();
    return () => { active = false; };
  }, [adminOnly, router]);

  if (error) {
    return <main className="container"><section className="card"><h1>Greška</h1><p>{error}</p><p>Proveri da li je FastAPI backend pokrenut.</p><button className="button" onClick={() => window.location.reload()}>Pokušaj ponovo</button></section></main>;
  }
  if (!user) return <main className="container"><p className="muted">Provera prijave…</p></main>;

  return <>
    <BrandNav user={user} />
    <main className="container">{children(user)}</main>
  </>;
}

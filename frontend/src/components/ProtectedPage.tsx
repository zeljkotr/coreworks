"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import BrandNav from "@/components/BrandNav";
import LocalInfrastructureCard from "@/components/LocalInfrastructureCard";
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
        if (active) setError(e instanceof Error ? e.message : "Connection error.");
      }
    }
    load();
    return () => { active = false; };
  }, [adminOnly, router]);

  useEffect(() => {
    if (!user) return;

    const layout = document.querySelector<HTMLElement>(".app-layout");
    const main = layout?.querySelector<HTMLElement>(".app-main");
    const sidebar = layout?.querySelector<HTMLElement>(".infra-sidebar");
    const target = main?.querySelector<HTMLElement>(
      ".grid, .page-heading + .card, .page-heading + section.card"
    );

    if (!layout || !main || !sidebar || !target) return;

    const alignSidebar = () => {
      if (window.innerWidth <= 700) {
        sidebar.style.marginTop = "0px";
        return;
      }
      const offset = target.getBoundingClientRect().top - layout.getBoundingClientRect().top;
      sidebar.style.marginTop = `${Math.max(0, offset)}px`;
    };

    alignSidebar();
    const observer = new ResizeObserver(alignSidebar);
    observer.observe(main);
    observer.observe(target);
    window.addEventListener("resize", alignSidebar);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", alignSidebar);
      sidebar.style.marginTop = "";
    };
  }, [user]);

  if (error) {
    return <main className="container"><section className="card"><h1>Error</h1><p>{error}</p><p>Check whether the FastAPI backend is running.</p><button className="button" onClick={() => window.location.reload()}>Try again</button></section></main>;
  }
  if (!user) return <main className="container"><p className="muted">Checking authentication…</p></main>;

  return <>
    <BrandNav user={user} />
    <div className="app-layout">
      <main className="container app-main">{children(user)}</main>
      <aside className="infra-sidebar" aria-label="Local server infrastructure">
        <LocalInfrastructureCard />
      </aside>
    </div>
  </>;
}

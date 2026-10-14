"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { TOKEN_KEY, type User } from "@/lib/api";

export default function BrandNav({ user }: { user: User }) {
  const router = useRouter();

  function logout() {
    window.localStorage.removeItem(TOKEN_KEY);
    router.replace("/login");
  }

  return (
    <header className="topbar">
      <Link className="brand" href="/dashboard">CoreWorks</Link>
      <nav className="nav">
        <Link href="/dashboard">Dashboard</Link>
        <Link href="/monitor/status">Monitor</Link>
        <Link href="/guardian">Guardian</Link>
        {user.role === "admin" && <Link href="/admin">Admin</Link>}
        <span className="user-label">{user.username}</span>
        <button className="button button-secondary button-small" onClick={logout}>Log out</button>
      </nav>
    </header>
  );
}

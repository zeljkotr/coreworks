"use client";

import Link from "next/link";
import ProtectedPage from "@/components/ProtectedPage";
import type { User } from "@/lib/api";

export default function DashboardPage() {
  return <ProtectedPage>{(user: User) => <>
    <div className="page-heading dashboard-page-heading">
      <div className="eyebrow">WORKSPACE</div>
      <h1>CoreWorks Hub</h1>
      <p className="muted">Welcome, {user.username}. Central hub for IT tools and integrations.</p>
    </div>
    <div className="grid">
      <section className="card">
        <div className="card-icon">M</div>
        <h2>CoreWorks Monitor</h2>
        <p>Server and service monitoring.</p>
        <p className="muted">Core module. Monitoring checks are not yet implemented.</p>
        <Link className="text-link" href="/monitor/status">Open module →</Link>
      </section>
      <section className="card">
        <div className="card-icon">I</div>
        <h2>Integrations</h2>
        <p className="muted">Space for future independent modules.</p>
        <span className="status-pill">Planned</span>
      </section>
    </div>
  </>}</ProtectedPage>;
}

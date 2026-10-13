"use client";

import Link from "next/link";
import ProtectedPage from "@/components/ProtectedPage";
import type { User } from "@/lib/api";

export default function DashboardPage() {
  return <ProtectedPage>{(user: User) => <>
    <div className="page-heading">
      <div className="eyebrow">RADNI PROSTOR</div>
      <h1>CoreWorks Hub</h1>
      <p className="muted">Dobrodošli, {user.username}. Centralni portal za IT alate i integracije.</p>
    </div>
    <div className="grid">
      <section className="card">
        <div className="card-icon">M</div>
        <h2>CoreWorks Monitor</h2>
        <p>Nadzor servera i servisa.</p>
        <p className="muted">Osnovni modul. Monitoring provere još nisu implementirane.</p>
        <Link className="text-link" href="/monitor/status">Otvori modul →</Link>
      </section>
      <section className="card">
        <div className="card-icon">I</div>
        <h2>Integracije</h2>
        <p className="muted">Prostor za buduće nezavisne module.</p>
        <span className="status-pill">U planu</span>
      </section>
    </div>
  </>}</ProtectedPage>;
}

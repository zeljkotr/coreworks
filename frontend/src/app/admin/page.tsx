"use client";

import { useEffect, useState } from "react";
import ProtectedPage from "@/components/ProtectedPage";
import { apiFetch, readError, type User } from "@/lib/api";

type AdminUser = User & { created_at: string };

function AdminContent() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    apiFetch("/admin/users")
      .then(async response => {
        if (!response.ok) throw new Error(await readError(response));
        return response.json() as Promise<AdminUser[]>;
      })
      .then(data => { if (active) setUsers(data); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : "Greška pri učitavanju."); });
    return () => { active = false; };
  }, []);

  return <>
    <div className="page-heading">
      <div className="eyebrow">COREWORKS HUB / ADMIN</div>
      <h1>Korisnici</h1>
      <p className="muted">Pregled registrovanih naloga i njihovih uloga.</p>
    </div>
    <section className="card table-card">
      {error ? <p className="error-message">{error}</p> : users.length === 0 ? <p className="muted">Učitavanje korisnika…</p> : <div className="table-scroll">
        <table>
          <thead><tr><th>ID</th><th>Korisnik</th><th>Uloga</th><th>Kreiran</th></tr></thead>
          <tbody>{users.map(user => <tr key={user.id}>
            <td>{user.id}</td><td>{user.username}</td><td><span className="status-pill">{user.role}</span></td>
            <td>{new Date(user.created_at).toLocaleString("sr-RS")}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>
  </>;
}

export default function AdminPage() {
  return <ProtectedPage adminOnly>{() => <AdminContent />}</ProtectedPage>;
}

"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { TOKEN_KEY, readError, type User } from "@/lib/api";

export default function LoginForm() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      if (!response.ok) {
        setError(response.status === 401 ? "Neispravno korisničko ime ili lozinka." : await readError(response));
        return;
      }
      const result = await response.json() as { access_token: string; user: User };
      window.localStorage.setItem(TOKEN_KEY, result.access_token);
      router.replace("/dashboard");
    } catch {
      setError("Backend nije dostupan. Proveri da li FastAPI radi na portu 8000.");
    } finally {
      setBusy(false);
    }
  }

  return <section className="card login-card">
    <div className="eyebrow">COREWORKS HUB</div>
    <h1>Dobrodošli u CoreWorks</h1>
    <p className="muted">Prijavite se da biste pristupili IT platformi.</p>
    <form onSubmit={submit}>
      <label htmlFor="username">Korisničko ime</label>
      <input id="username" name="username" value={username} onChange={e => setUsername(e.target.value)} required maxLength={255} autoComplete="username" autoFocus />
      <label htmlFor="password">Lozinka</label>
      <input id="password" name="password" type="password" value={password} onChange={e => setPassword(e.target.value)} required maxLength={1024} autoComplete="current-password" />
      {error && <p className="error-message" role="alert">{error}</p>}
      <button className="button login-button" type="submit" disabled={busy}>{busy ? "Prijavljivanje…" : "Prijavi se"}</button>
    </form>
  </section>;
}

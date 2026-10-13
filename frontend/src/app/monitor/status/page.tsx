"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import ProtectedPage from "@/components/ProtectedPage";
import { apiFetch, TOKEN_KEY } from "@/lib/api";

type Check = {
  name: string;
  status: "ok" | "error";
  message: string;
};

type MonitorResult = {
  checked_at: string;
  status: "ok" | "error";
  checks: Check[];
};

function MonitorContent() {
  const router = useRouter();
  const [result, setResult] = useState<MonitorResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const runChecks = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const response = await apiFetch("/monitor/status");

      if (response.status === 401) {
        window.localStorage.removeItem(TOKEN_KEY);
        router.replace("/login");
        return;
      }

      if (!response.ok) {
        throw new Error("Provera trenutno nije dostupna. Pokušajte ponovo.");
      }

      setResult((await response.json()) as MonitorResult);
    } catch {
      setError("Nije moguće preuzeti rezultate. Proverite dostupnost API-ja.");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    void runChecks();
  }, [runChecks]);

  const checkedAt = result?.checked_at
    ? new Date(result.checked_at).toLocaleString("sr-RS")
    : null;

  return (
    <>
      <div className="page-heading">
        <div className="eyebrow">COREWORKS HUB / MONITOR</div>
        <h1>CoreWorks Monitor</h1>
        <p className="muted">
          Pregled dostupnosti aplikacije i veze sa bazom podataka.
        </p>
      </div>

      <section className="card">
        <div className="monitor-toolbar">
          <div>
            <span className={`status-pill ${result?.status === "ok" ? "monitor-ok" : result?.status === "error" ? "monitor-error" : ""}`}>
              {loading && !result
                ? "Provera u toku"
                : result?.status === "ok"
                  ? "Svi sistemi rade"
                  : result?.status === "error"
                    ? "Potrebna provera"
                    : "Čeka proveru"}
            </span>
            <h2>Status sistema</h2>
            <p className="muted">
              Poslednja provera: {checkedAt ?? "Još nije izvršena"}
            </p>
          </div>
          <button className="button" onClick={() => void runChecks()} disabled={loading}>
            {loading ? "Provera…" : "Proveri ponovo"}
          </button>
        </div>

        {error && <p className="error-message" role="alert">{error}</p>}

        {result && (
          <div className="monitor-checks">
            {result.checks.map((check) => (
              <article className="monitor-check" key={check.name}>
                <div>
                  <h3>{check.name}</h3>
                  <p className="muted">{check.message}</p>
                </div>
                <span className={`status-pill ${check.status === "ok" ? "monitor-ok" : "monitor-error"}`}>
                  {check.status === "ok" ? "Dostupno" : "Greška"}
                </span>
              </article>
            ))}
          </div>
        )}

        {!result && !error && (
          <p className="muted">Preuzimanje rezultata provera…</p>
        )}
      </section>
    </>
  );
}

export default function MonitorPage() {
  return <ProtectedPage>{() => <MonitorContent />}</ProtectedPage>;
}

"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import ProtectedPage from "@/components/ProtectedPage";
import { apiFetch, TOKEN_KEY } from "@/lib/api";

type Host = {
  id: number;
  name: string;
  host: string;
  port: number;
  status: "ok" | "error";
  message: string;
  checked_at: string;
  created_at?: string;
};

type HostResponse = {
  checked_at: string;
  total: number;
  hosts: Host[];
};

function MonitorContent() {
  const router = useRouter();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [checkedAt, setCheckedAt] = useState("");

  const handleUnauthorized = useCallback(() => {
    window.localStorage.removeItem(TOKEN_KEY);
    router.replace("/login");
  }, [router]);

  const loadHosts = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await apiFetch("/monitor/hosts");
      if (response.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!response.ok) {
        throw new Error(
          response.status === 503
            ? "Monitor cannot access the database at the moment."
            : "Nije moguće učitati registrovane hostove.",
        );
      }
      const data = (await response.json()) as HostResponse;
      setHosts(data.hosts);
      setCheckedAt(data.checked_at);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Error checking remote hosts.",
      );
    } finally {
      setLoading(false);
    }
  }, [handleUnauthorized]);

  useEffect(() => {
    void loadHosts();
  }, [loadHosts]);

  async function submitHost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");

    const parsedPort = Number(port);
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setError("Port mora biti broj između 1 i 65535.");
      setSaving(false);
      return;
    }

    try {
      const response = await apiFetch("/monitor/hosts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, host, port: parsedPort }),
      });

      if (response.status === 401) {
        handleUnauthorized();
        return;
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "Nije moguće registrovati host.",
        );
      }

      const created = (await response.json()) as Host;
      setName("");
      setHost("");
      setNotice(
        created.status === "ok"
          ? "The host is registered and the service is available."
          : "The host is registered, but the service is currently unavailable.",
      );
      await loadHosts();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Error registering host.",
      );
    } finally {
      setSaving(false);
    }
  }

  async function removeHost(id: number) {
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`/monitor/hosts/${id}`, {
        method: "DELETE",
      });
      if (response.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!response.ok) {
        throw new Error("Nije moguće ukloniti host.");
      }
      setNotice("Host je uklonjen.");
      await loadHosts();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error removing host.");
    }
  }

  const onlineCount = hosts.filter((item) => item.status === "ok").length;

  return (
    <>
      <div className="page-heading">
        <div className="eyebrow">COREWORKS HUB / MONITOR</div>
        <h1>CoreWorks Monitor</h1>
        <p className="muted">
          Register remote servers and check the availability of their TCP services.
        </p>
      </div>

      <section className="card">
        <h2>Add remote host</h2>
        <p className="muted">
          Enter the IP address or DNS name and the port of the service you want to monitor.
          Primer: SSH 22, HTTP 80, HTTPS 443.
        </p>

        <form
          onSubmit={submitHost}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
            gap: 12,
            alignItems: "end",
          }}
        >
          <label>
            Name
            <input
              required
              maxLength={120}
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Production web"
              style={{ display: "block", width: "100%", marginTop: 6 }}
            />
          </label>
          <label>
            IP address / DNS
            <input
              required
              maxLength={253}
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="192.168.1.20 ili server.example.com"
              style={{ display: "block", width: "100%", marginTop: 6 }}
            />
          </label>
          <label>
            TCP port
            <input
              required
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(event) => setPort(event.target.value)}
              style={{ display: "block", width: "100%", marginTop: 6 }}
            />
          </label>
          <button className="button" type="submit" disabled={saving}>
            {saving ? "Registering…" : "Add host"}
          </button>
        </form>

        {error && <p className="error-message" role="alert">{error}</p>}
        {notice && <p role="status">{notice}</p>}
      </section>

      <section className="card" style={{ marginTop: 20 }}>
        <div className="monitor-toolbar">
          <div>
            <h2>Registered hosts</h2>
            <p className="muted">
              Total: {hosts.length} · Available: {onlineCount} · Unavailable:{" "}
              {hosts.length - onlineCount}
            </p>
            <p className="muted">
              Last checked:{" "}
              {checkedAt ? new Date(checkedAt).toLocaleString("sr-RS") : "—"}
            </p>
          </div>
          <button
            className="button"
            type="button"
            onClick={() => void loadHosts()}
            disabled={loading}
          >
            {loading ? "Checking…" : "Check again"}
          </button>
        </div>

        {hosts.length === 0 && !loading && (
          <p className="muted">
            No hosts have been registered yet. Add a server above to get started
            monitoring.
          </p>
        )}

        <div style={{ display: "grid", gap: 12 }}>
          {hosts.map((item) => (
            <article
              className="monitor-check"
              key={item.id}
              style={{ display: "flex", gap: 16, justifyContent: "space-between" }}
            >
              <div>
                <h3><Link href={`/monitor/hosts/${item.id}`}>{item.name}</Link></h3>
                <p className="muted">
                  {item.host}:{item.port}
                </p>
                <p className="muted">{item.message}</p>
                <p className="muted">
                  Checked: {new Date(item.checked_at).toLocaleString("sr-RS")}
                </p>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "end" }}>
                <span
                  className={`status-pill ${
                    item.status === "ok" ? "monitor-ok" : "monitor-error"
                  }`}
                >
                  {item.status === "ok" ? "Available" : "Unavailable"}
                </span>
                <button
                  className="button"
                  type="button"
                  onClick={() => void removeHost(item.id)}
                >
                  Remove
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

export default function MonitorPage() {
  return <ProtectedPage>{() => <MonitorContent />}</ProtectedPage>;
}

"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
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
};

type Disk = {
  mountpoint: string;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
};

type Metrics = {
  recorded_at: string;
  cpu_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  disk: Disk[];
  uptime_seconds: number;
  os_name: string;
  hostname: string;
  agent_version: string;
};

type AgentStatus = {
  host: {
    agent_connected: boolean;
    agent_last_seen_at: string | null;
    agent_version: string | null;
    agent_os: string | null;
  };
  latest: Metrics | null;
};

function bytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "N/A";
  if (value < 1024) return `${value} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }

  return `${size.toFixed(1)} ${units[unit]}`;
}

function uptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days} days, ${hours} hours, ${minutes} minutes`;
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "No data";
  return new Date(value).toLocaleString("en-GB");
}

function Gauge({ label, value, detail }: { label: string; value: number | null; detail: string }) {
  const valid = value !== null && Number.isFinite(value);
  const percent = valid ? Math.max(0, Math.min(100, value)) : 0;
  const color = percent >= 90 ? "#ef4444" : percent >= 75 ? "#f59e0b" : "#22c55e";
  const circumference = 2 * Math.PI * 43;

  return (
    <div style={{ border: "1px solid var(--border, rgba(127,127,127,.22))", borderRadius: 14, padding: 18, minWidth: 0 }}>
      <div style={{ textAlign: "center", fontSize: 13, fontWeight: 650, textTransform: "uppercase", color: "var(--muted)" }}>{label}</div>
      <div style={{ width: 156, maxWidth: "100%", margin: "8px auto 4px" }}>
        <svg viewBox="0 0 100 100" role="img" aria-label={`${label}: ${valid ? `${percent.toFixed(1)} percent` : "no data"}`} style={{ display: "block", width: "100%" }}>
          <circle cx="50" cy="50" r="43" fill="none" stroke="currentColor" strokeOpacity=".12" strokeWidth="9" />
          {valid && <circle cx="50" cy="50" r="43" fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={circumference * (1 - percent / 100)} transform="rotate(-90 50 50)" style={{ transition: "stroke-dashoffset .5s ease" }} />}
          <text x="50" y="48" textAnchor="middle" dominantBaseline="middle" fontSize="21" fontWeight="700" fill="currentColor">{valid ? `${percent.toFixed(1)}%` : "—"}</text>
          <text x="50" y="64" textAnchor="middle" fontSize="8" fill="currentColor">{valid ? (percent >= 90 ? "CRITICAL" : percent >= 75 ? "WARNING" : "NORMAL") : "NO DATA"}</text>
        </svg>
      </div>
      <div style={{ textAlign: "center", fontSize: 13, color: "var(--muted)", overflowWrap: "anywhere" }}>{detail}</div>
    </div>
  );
}

async function copyText(value: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Clipboard API may be blocked by browser permissions.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.readOnly = true;
  textarea.style.position = "fixed";
  textarea.style.left = "0";
  textarea.style.top = "0";
  textarea.style.width = "1px";
  textarea.style.height = "1px";
  textarea.style.opacity = "0.01";
  document.body.appendChild(textarea);

  try {
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, value.length);

    if (!document.execCommand("copy")) {
      throw new Error(
        "Automatic copying failed. Select the text in the command box and copy it manually."
      );
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

function HostDetails() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();

  const [host, setHost] = useState<Host | null>(null);
  const [metrics, setMetrics] = useState<AgentStatus | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);
  const [issuing, setIssuing] = useState(false);
  const [token, setToken] = useState("");
  const [copied, setCopied] = useState(false);

  const loadHost = useCallback(async () => {
    const response = await apiFetch("/monitor/hosts");

    if (response.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      router.replace("/login");
      return;
    }

    if (!response.ok) throw new Error("Unable to load hosts.");

    const data = await response.json();
    const found = (data.hosts as Host[]).find(
      (item) => item.id === Number(id),
    );

    if (!found) throw new Error("Host not found or access denied.");
    setHost(found);
  }, [id, router]);

  const loadMetrics = useCallback(async () => {
    const response = await apiFetch(`/monitor/hosts/${id}/metrics`);

    if (response.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      router.replace("/login");
      return;
    }

    if (!response.ok) {
      throw new Error("Unable to load agent metrics.");
    }

    setMetrics(await response.json());
  }, [id, router]);

  const refresh = useCallback(async () => {
    setError("");

    try {
      await Promise.all([loadHost(), loadMetrics()]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "An error occurred while loading data.");
    } finally {
      setLoading(false);
    }
  }, [loadHost, loadMetrics]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function issueToken() {
    setIssuing(true);
    setError("");
    setNotice("");
    setToken("");
    setCopied(false);

    try {
      const response = await apiFetch(
        `/monitor/hosts/${id}/agent-token`,
        { method: "POST" },
      );

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to generate an agent token.");
      }

      const result = await response.json();
      setToken(result.token);
      setNotice("Token generated. Save it now; it will not be shown again.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate the token.");
    } finally {
      setIssuing(false);
    }
  }

  const apiBase =
    typeof window !== "undefined" && window.location.protocol === "https:"
      ? `${window.location.origin}/api`
      : "";

  const installCommand = token && apiBase
    ? `set -eu
sudo apt-get update
sudo apt-get install -y python3 python3-venv curl
sudo install -d -m 755 /opt/coreworks-monitor
sudo python3 -m venv /opt/coreworks-monitor/venv
sudo /opt/coreworks-monitor/venv/bin/pip install psutil
sudo curl -fsSL '${apiBase}/monitor/agent.py' -o /opt/coreworks-monitor/agent.py
sudo chmod 755 /opt/coreworks-monitor/agent.py
sudo tee /etc/coreworks-monitor.env >/dev/null <<'CWENV'
COREWORKS_MONITOR_URL=${apiBase}
COREWORKS_MONITOR_TOKEN=${token}
COREWORKS_MONITOR_INTERVAL=30
CWENV
sudo chmod 600 /etc/coreworks-monitor.env
sudo tee /etc/systemd/system/coreworks-monitor-agent.service >/dev/null <<'CWSERVICE'
[Unit]
Description=CoreWorks Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/coreworks-monitor.env
ExecStart=/opt/coreworks-monitor/venv/bin/python /opt/coreworks-monitor/agent.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
CWSERVICE
sudo systemctl daemon-reload
sudo systemctl enable --now coreworks-monitor-agent.service
sudo systemctl --no-pager --full status coreworks-monitor-agent.service`
    : "";

  async function copyInstallCommand() {
    if (!installCommand) {
      setError("A public HTTPS CoreWorks URL is required to generate the installation script.");
      return;
    }
    try {
      await copyText(installCommand);
      setCopied(true);
      setError("");
      setNotice("Installation command copied to clipboard.");
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Copy failed. Select the command and copy it manually.",
      );
    }
  }

  async function copyToken() {
    try {
      await copyText(token);
      setNotice("Agent token copied to clipboard.");
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to copy the token.");
    }
  }

  const latest = metrics?.latest ?? null;
  const agentConnected = metrics?.host.agent_connected ?? false;

  return (
    <>
      <div className="page-heading">
        <div className="eyebrow">COREWORKS HUB / MONITOR / SERVER</div>
        <h1>{host?.name ?? "Server details"}</h1>
        <p className="muted">Remote infrastructure overview.</p>
        <Link href="/monitor/status">← Back to Monitor</Link>
      </div>

      {loading && <section className="card">Loading...</section>}

      {error && (
        <section className="card">
          <p className="error-message">{error}</p>
        </section>
      )}

      {notice && (
        <section className="card">
          <p role="status">{notice}</p>
        </section>
      )}

      {host && !loading && (
        <>
          <section className="card">
            <h2>Status and availability</h2>
            <p>Address: {host.host}</p>
            <p>TCP port: {host.port}</p>
            <p>
              TCP status:{" "}
              <strong>{host.status === "ok" ? "Available" : "Unavailable"}</strong>
            </p>
            <p>Last TCP check: {formatDate(host.checked_at)}</p>
            <p>
              Agent:{" "}
              <strong>{agentConnected ? "Connected" : "Not connected"}</strong>
            </p>
            <button className="button" onClick={() => void refresh()}>
              Refresh
            </button>
          </section>

          <section className="card" style={{ marginTop: 20 }}>
            <h2>Install Monitor Agent</h2>
            <p>
              A token is issued for this host and displayed only once.
              Generating a new token invalidates the previous token.
            </p>

            <button
              className="button"
              disabled={issuing}
              onClick={() => void issueToken()}
            >
              {issuing ? "Generating token..." : "Generate token and installation command"}
            </button>

            {token && (
              <div style={{ marginTop: 16 }}>
                <p><strong>Agent token — save it now:</strong></p>
                <textarea
                  readOnly
                  aria-label="Agent token"
                  value={token}
                  rows={2}
                  style={{ width: "100%", boxSizing: "border-box" }}
                  onFocus={(event) => event.currentTarget.select()}
                />
                <button
                  className="button"
                  style={{ marginTop: 8 }}
                  onClick={() => void copyToken()}
                >
                  Copy token
                </button>

                <p className="muted" style={{ marginTop: 16 }}>
                  Run the following command on the remote Linux server.
                  Sudo access and network access to the CoreWorks API are required.
                </p>

                <textarea
                  readOnly
                  aria-label="Agent installation command"
                  value={installCommand}
                  rows={16}
                  style={{
                    width: "100%",
                    boxSizing: "border-box",
                    fontFamily: "monospace",
                  }}
                  onFocus={(event) => event.currentTarget.select()}
                />

                <button
                  className="button"
                  style={{ marginTop: 8 }}
                  onClick={() => void copyInstallCommand()}
                >
                  {copied ? "Command copied" : "Copy installation command"}
                </button>

                <p className="muted">
                  The token is a secret. Do not share it or publish it in logs.
                  Generate a new token if it is lost or exposed.
                </p>
              </div>
            )}
          </section>

          <section className="card" style={{ marginTop: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
              <div>
                <h2 style={{ marginBottom: 4 }}>Infrastructure metrics</h2>
                <p className="muted" style={{ marginTop: 0 }}>Live resource utilization and system health</p>
              </div>
              <div style={{ fontSize: 12, color: "var(--muted)" }}>
                <div>Last contact</div>
                <strong>{formatDate(metrics?.host.agent_last_seen_at)}</strong>
              </div>
            </div>

            {!latest && (
              <p className="muted">No metrics received yet. Install the agent on the remote server. Metrics will appear after its first successful report.</p>
            )}

            {latest && (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 16, marginTop: 18 }}>
                  <Gauge label="CPU usage" value={latest.cpu_percent} detail="Processor utilization" />
                  <Gauge
                    label="Memory usage"
                    value={latest.memory_total_bytes > 0 ? latest.memory_used_bytes / latest.memory_total_bytes * 100 : null}
                    detail={`${bytes(latest.memory_used_bytes)} used of ${bytes(latest.memory_total_bytes)}`}
                  />
                </div>

                <div style={{ marginTop: 24 }}>
                  <h3 style={{ marginBottom: 12 }}>Disk utilization</h3>
                  {latest.disk.length === 0 && <p className="muted">No disk metrics reported.</p>}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12 }}>
                    {latest.disk.map((disk) => {
                      const valid = disk.total_bytes > 0;
                      const percent = valid ? Math.max(0, Math.min(100, disk.used_bytes / disk.total_bytes * 100)) : 0;
                      const color = percent >= 90 ? "#ef4444" : percent >= 75 ? "#f59e0b" : "#22c55e";
                      return (
                        <div key={disk.mountpoint} style={{ border: "1px solid var(--border, rgba(127,127,127,.22))", borderRadius: 12, padding: 15, minWidth: 0 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
                            <strong style={{ overflowWrap: "anywhere" }}>{disk.mountpoint}</strong>
                            <strong style={{ color: valid ? color : "var(--muted)", whiteSpace: "nowrap" }}>{valid ? `${percent.toFixed(1)}%` : "N/A"}</strong>
                          </div>
                          <div role="img" aria-label={`${disk.mountpoint} disk utilization`} style={{ height: 9, borderRadius: 99, background: "rgba(127,127,127,.18)", overflow: "hidden" }}>
                            <div style={{ width: `${percent}%`, height: "100%", borderRadius: 99, background: color, transition: "width .5s ease" }} />
                          </div>
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginTop: 9, fontSize: 12, color: "var(--muted)" }}>
                            <span>{bytes(disk.used_bytes)} used</span>
                            <span>{bytes(disk.total_bytes)} total</span>
                          </div>
                          {valid && percent >= 90 && <p style={{ color, fontSize: 12 }}>Critical: disk space is running low.</p>}
                          {valid && percent >= 75 && percent < 90 && <p style={{ color, fontSize: 12 }}>Warning: disk usage is high.</p>}
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div style={{ marginTop: 24 }}>
                  <h3 style={{ marginBottom: 12 }}>System information</h3>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 12 }}>
                    {[
                      ["Hostname", latest.hostname],
                      ["Operating system", latest.os_name],
                      ["System uptime", uptime(latest.uptime_seconds)],
                      ["Agent version", latest.agent_version],
                      ["Sample time", formatDate(latest.recorded_at)],
                    ].map(([label, value]) => (
                      <div key={label} style={{ border: "1px solid var(--border, rgba(127,127,127,.22))", borderRadius: 10, padding: 13, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 6 }}>{label}</div>
                        <div style={{ fontWeight: 600, overflowWrap: "anywhere" }}>{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
            <p className="muted" style={{ marginTop: 18 }}>Auto-refresh: every 15 seconds. Thresholds: warning at 75%, critical at 90%.</p>
          </section>
        </>
      )}
    </>
  );
}

export default function MonitorHostPage() {
  return <ProtectedPage>{() => <HostDetails />}</ProtectedPage>;
}

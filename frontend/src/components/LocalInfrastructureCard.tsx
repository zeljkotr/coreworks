"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Disk = {
  mountpoint: string;
  used_percent: number;
  used_bytes: number;
  total_bytes: number;
};

type Metrics = {
  hostname: string;
  operating_system: string;
  cpu_percent: number;
  ram_percent: number;
  ram_used_bytes: number;
  ram_total_bytes: number;
  disks: Disk[];
  uptime_seconds: number;
  updated_at: string;
};

function bytes(value: number) {
  return value >= 1024 ** 3
    ? `${(value / 1024 ** 3).toFixed(1)} GB`
    : `${(value / 1024 ** 2).toFixed(0)} MB`;
}

function uptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return `${days}d ${hours}h`;
}

function colorFor(value: number) {
  return value >= 90 ? "#fb7185" : value >= 75 ? "#fbbf24" : "#34d399";
}

function Meter({ label, value }: { label: string; value: number }) {
  const safe = Math.min(100, Math.max(0, value));
  return (
    <div className="infra-meter">
      <div className="infra-meter-label">
        <span>{label}</span><strong>{value.toFixed(1)}%</strong>
      </div>
      <div className="infra-track">
        <div className="infra-fill" style={{ width: `${safe}%`, background: colorFor(value) }} />
      </div>
    </div>
  );
}

export default function LocalInfrastructureCard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const response = await apiFetch("/local-infrastructure");
        if (!response.ok) throw new Error(`Request failed (${response.status})`);
        const result = (await response.json()) as Metrics;
        if (active) {
          setMetrics(result);
          setError("");
        }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Unable to load metrics");
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <section className="infra-panel">
      <div className="infra-heading">
        <span className="infra-pulse" />
        <div><h2>Infrastructure</h2><p>LOCAL SERVER</p></div>
      </div>

      {error && <p className="infra-error" role="alert">Metrics unavailable: {error}</p>}
      {!metrics && !error && <p className="muted">Connecting to server…</p>}

      {metrics && <>
        <div className="infra-host">
          <span className="infra-host-icon">⌘</span>
          <div><strong>{metrics.hostname}</strong><span>CoreWorks host</span></div>
        </div>

        <div className="infra-meters">
          <Meter label="CPU" value={metrics.cpu_percent} />
          <Meter label="Memory" value={metrics.ram_percent} />
          <div className="infra-memory">
            {bytes(metrics.ram_used_bytes)} <span>/ {bytes(metrics.ram_total_bytes)}</span>
          </div>
        </div>

        <div className="infra-section-label">STORAGE</div>
        {metrics.disks.map((disk) => (
          <div className="infra-disk" key={disk.mountpoint}>
            <div className="infra-meter-label">
              <span>{disk.mountpoint}</span><strong>{disk.used_percent.toFixed(1)}%</strong>
            </div>
            <div className="infra-track">
              <div className="infra-fill" style={{
                width: `${Math.min(100, Math.max(0, disk.used_percent))}%`,
                background: colorFor(disk.used_percent),
              }} />
            </div>
            <div className="infra-detail">{bytes(disk.used_bytes)} used · {bytes(disk.total_bytes)} total</div>
          </div>
        ))}

        <div className="infra-section-label">SYSTEM</div>
        <div className="infra-fact"><span>Operating system</span><strong>{metrics.operating_system}</strong></div>
        <div className="infra-fact"><span>Uptime</span><strong>{uptime(metrics.uptime_seconds)}</strong></div>
        <div className="infra-footer">
          <span>Live · 15 sec refresh</span>
          <span>{new Date(metrics.updated_at).toLocaleTimeString()}</span>
        </div>
      </>}
    </section>
  );
}

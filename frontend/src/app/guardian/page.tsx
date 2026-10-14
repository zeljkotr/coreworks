"use client";

import { useCallback, useEffect, useState } from "react";
import ProtectedPage from "@/components/ProtectedPage";
import { apiFetch, readError } from "@/lib/api";

type Finding = {
  host: string;
  port: number;
  service: string;
  product: string;
  version: string;
  evidence: string;
  confidence: string;
  severity: string;
  title: string;
  recommendation: string;
};

type Scan = {
  id: number;
  target: string;
  scanned_at: string;
  hosts_checked: number;
  ports_per_host: number;
  checks_completed: number;
  open_ports: number;
  findings: Finding[];
  notice?: string;
};

type HistoryItem = Omit<Scan, "findings">;

type ComparisonFinding = Finding & {
  status: "new" | "resolved" | "unchanged";
};

type Comparison = {
  target: string;
  previous_scan: {
    id: number;
    scanned_at: string;
    open_ports: number;
  };
  current_scan: {
    id: number;
    scanned_at: string;
    open_ports: number;
  };
  summary: {
    new: number;
    resolved: number;
    unchanged: number;
  };
  findings: ComparisonFinding[];
  resolved_findings: ComparisonFinding[];
};

function GuardianContent() {
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [comparingId, setComparingId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Scan | null>(null);
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const loadHistory = useCallback(async () => {
    try {
      const response = await apiFetch("/guardian/history");
      if (!response.ok) throw new Error(await readError(response));
      setHistory(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  async function startScan() {
    setScanning(true);
    setError("");
    setComparison(null);
    setResult(null);

    try {
      const response = await apiFetch("/guardian/scan", {
        method: "POST",
        body: JSON.stringify({ target: target.trim() }),
      });
      if (!response.ok) throw new Error(await readError(response));
      setResult(await response.json());
      await loadHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Guardian scan failed.");
    } finally {
      setScanning(false);
    }
  }

  async function viewDetails(id: number) {
    setError("");
    setComparison(null);

    try {
      const response = await apiFetch(`/guardian/history/${id}`);
      if (!response.ok) throw new Error(await readError(response));
      setResult(await response.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load scan details.");
    }
  }

  async function compareScans(id: number) {
    setError("");
    setComparingId(id);
    setComparison(null);

    try {
      const response = await apiFetch(
        `/guardian/history/${id}/comparison`
      );
      if (!response.ok) throw new Error(await readError(response));
      setComparison(await response.json());
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not compare scans."
      );
    } finally {
      setComparingId(null);
    }
  }

  const comparisonFindings = comparison
    ? [...comparison.findings, ...comparison.resolved_findings].sort(
        (a, b) =>
          a.host.localeCompare(b.host) ||
          a.port - b.port ||
          a.status.localeCompare(b.status)
      )
    : [];

  function statusStyle(status: ComparisonFinding["status"]) {
    if (status === "new") {
      return { color: "#b91c1c", fontWeight: 700 as const };
    }
    if (status === "resolved") {
      return { color: "#15803d", fontWeight: 700 as const };
    }
    return { color: "inherit", fontWeight: 500 as const };
  }

  return (
    <main className="page">
      <div className="page-heading">
        <div className="eyebrow">COREWORKS HUB / SECURITY</div>
        <h1>Guardian</h1>
        <p className="muted">
          Network discovery and security exposure assessment.
        </p>
      </div>

      <section className="card">
        <h2>Network scan</h2>
        <p>
          Scan an authorized private IP address or CIDR network.
          DNS names and public IP addresses are not accepted.
        </p>

        <label htmlFor="guardian-target">Target IP or CIDR</label>
        <input
          id="guardian-target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="192.168.1.10 or 192.168.1.0/24"
          maxLength={100}
          autoComplete="off"
          spellCheck={false}
          style={{
            width: "100%",
            maxWidth: 520,
            marginTop: 8,
            marginBottom: 16,
          }}
        />

        <p className="muted">
          Maximum 256 IP addresses and 4096 host-port checks per scan.
        </p>

        <button
          className="button"
          disabled={scanning || !target.trim()}
          onClick={() => void startScan()}
        >
          {scanning ? "Scanning network..." : "Start scan"}
        </button>
      </section>

      {error && (
        <section className="card" style={{ marginTop: 20 }}>
          <p className="error-message" role="alert">{error}</p>
        </section>
      )}

      <section className="card" style={{ marginTop: 20 }}>
        <h2>Scan History</h2>
        <p className="muted">
          Inspect previous scans or compare a scan with the previous scan
          of the same target.
        </p>

        {loading ? (
          <p>Loading history...</p>
        ) : history.length === 0 ? (
          <p>No saved scans yet.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: 10 }}>Date</th>
                  <th style={{ textAlign: "left", padding: 10 }}>Target</th>
                  <th style={{ textAlign: "left", padding: 10 }}>Hosts</th>
                  <th style={{ textAlign: "left", padding: 10 }}>Open ports</th>
                  <th style={{ textAlign: "left", padding: 10 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{ padding: 10 }}>
                      {new Date(scan.scanned_at).toLocaleString("en-GB")}
                    </td>
                    <td style={{ padding: 10 }}>{scan.target}</td>
                    <td style={{ padding: 10 }}>{scan.hosts_checked}</td>
                    <td style={{ padding: 10 }}>{scan.open_ports}</td>
                    <td style={{ padding: 10 }}>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 8,
                        }}
                      >
                        <button
                          className="button"
                          onClick={() => void viewDetails(scan.id)}
                        >
                          View details
                        </button>
                        <button
                          className="button"
                          disabled={comparingId !== null}
                          onClick={() => void compareScans(scan.id)}
                        >
                          {comparingId === scan.id
                            ? "Comparing..."
                            : "Compare"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {comparison && (
        <section className="card" style={{ marginTop: 20 }}>
          <h2>Scan Comparison</h2>
          <p><strong>Target:</strong> {comparison.target}</p>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 16,
              marginTop: 16,
              marginBottom: 20,
            }}
          >
            <div>
              <p className="muted">Previous scan</p>
              <p>
                {new Date(
                  comparison.previous_scan.scanned_at
                ).toLocaleString("en-GB")}
              </p>
              <p>
                Open ports: {comparison.previous_scan.open_ports}
              </p>
            </div>
            <div>
              <p className="muted">Current scan</p>
              <p>
                {new Date(
                  comparison.current_scan.scanned_at
                ).toLocaleString("en-GB")}
              </p>
              <p>
                Open ports: {comparison.current_scan.open_ports}
              </p>
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
              gap: 12,
              marginBottom: 20,
            }}
          >
            {(
              [
                ["New", comparison.summary.new, "#b91c1c"],
                ["Resolved", comparison.summary.resolved, "#15803d"],
                ["Unchanged", comparison.summary.unchanged, "inherit"],
              ] as const
            ).map(([label, count, color]) => (
              <div
                key={label}
                style={{
                  padding: 16,
                  border: "1px solid var(--border, #d1d5db)",
                  borderRadius: 8,
                }}
              >
                <p className="muted" style={{ margin: 0 }}>{label}</p>
                <p
                  style={{
                    fontSize: 28,
                    fontWeight: 700,
                    color,
                    margin: "8px 0 0",
                  }}
                >
                  {count}
                </p>
              </div>
            ))}
          </div>

          <h3>Port Changes</h3>
          {comparisonFindings.length === 0 ? (
            <p>No port findings are available in these scans.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {[
                      "Status",
                      "Host",
                      "Port",
                      "Service",
                      "Product / version",
                      "Exposure",
                    ].map((heading) => (
                      <th
                        key={heading}
                        style={{ textAlign: "left", padding: 10 }}
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {comparisonFindings.map((finding) => (
                    <tr
                      key={`${finding.status}:${finding.host}:${finding.port}`}
                    >
                      <td
                        style={{
                          padding: 10,
                          ...statusStyle(finding.status),
                        }}
                      >
                        {finding.status.toUpperCase()}
                      </td>
                      <td style={{ padding: 10 }}>{finding.host}</td>
                      <td style={{ padding: 10 }}>{finding.port}</td>
                      <td style={{ padding: 10 }}>{finding.service}</td>
                      <td style={{ padding: 10 }}>
                        {[finding.product, finding.version]
                          .filter(Boolean)
                          .join(" ") || "Unknown"}
                      </td>
                      <td style={{ padding: 10 }}>
                        {finding.severity.toUpperCase()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {result && (
        <section className="card" style={{ marginTop: 20 }}>
          <h2>Scan Results</h2>
          <p><strong>Target:</strong> {result.target}</p>
          <p><strong>Hosts checked:</strong> {result.hosts_checked}</p>
          <p><strong>Ports per host:</strong> {result.ports_per_host}</p>
          <p><strong>Checks completed:</strong> {result.checks_completed}</p>
          <p><strong>Open ports:</strong> {result.open_ports}</p>
          <p>
            <strong>Completed:</strong>{" "}
            {new Date(result.scanned_at).toLocaleString("en-GB")}
          </p>

          {result.findings.length === 0 ? (
            <p>No open ports were detected among the selected ports.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {[
                      "Host",
                      "Port",
                      "Service",
                      "Product / version",
                      "Confidence",
                      "Evidence",
                      "Exposure",
                      "Recommendation",
                    ].map((heading) => (
                      <th
                        key={heading}
                        style={{ textAlign: "left", padding: 10 }}
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.findings.map((finding) => (
                    <tr key={`${finding.host}:${finding.port}`}>
                      <td style={{ padding: 10 }}>{finding.host}</td>
                      <td style={{ padding: 10 }}>{finding.port}</td>
                      <td style={{ padding: 10 }}>{finding.service}</td>
                      <td style={{ padding: 10 }}>
                        {finding.product} {finding.version}
                      </td>
                      <td style={{ padding: 10 }}>{finding.confidence}</td>
                      <td
                        style={{
                          padding: 10,
                          maxWidth: 360,
                          overflowWrap: "anywhere",
                        }}
                      >
                        {finding.evidence || "No banner returned."}
                      </td>
                      <td style={{ padding: 10 }}>
                        {finding.severity.toUpperCase()}
                      </td>
                      <td style={{ padding: 10 }}>
                        {finding.recommendation}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.notice && (
            <p className="muted" style={{ marginTop: 16 }}>
              {result.notice}
            </p>
          )}
        </section>
      )}
    </main>
  );
}

export default function GuardianPage() {
  return <ProtectedPage>{() => <GuardianContent />}</ProtectedPage>;
}

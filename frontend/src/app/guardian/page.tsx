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

type VulnerabilityMatch = {
  cve_id: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  url: string;
  matched_product: string;
  detected_version: string;
  status: string;
  published?: string | null;
};

type VulnerabilityReport = {
  scan_id: number;
  target: string;
  source: string;
  checked_services: number;
  results: VulnerabilityMatch[];
  errors: string[];
  notice: string;
};

type RiskTrend = {
  id: number;
  scanned_at: string;
  risk_score: number;
  findings_count: number;
  open_ports: number;
};

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
  const [trends, setTrends] = useState<RiskTrend[]>([]);
  const [trendsLoading, setTrendsLoading] = useState(false);
  const [trendsError, setTrendsError] = useState("");
  const [vulnerabilityReport, setVulnerabilityReport] =
    useState<VulnerabilityReport | null>(null);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(false);
  const [vulnerabilitiesError, setVulnerabilitiesError] = useState("");

  async function checkVulnerabilities(scanId: number) {
    setVulnerabilitiesLoading(true);
    setVulnerabilitiesError("");
    setVulnerabilityReport(null);
    try {
      const response = await apiFetch(
        `/guardian/history/${scanId}/vulnerabilities`
      );
      if (!response.ok) throw new Error(await readError(response));
      setVulnerabilityReport(await response.json());
    } catch (e) {
      setVulnerabilitiesError(
        e instanceof Error ? e.message : "Could not check known vulnerabilities."
      );
    } finally {
      setVulnerabilitiesLoading(false);
    }
  }

  async function loadTrends() {
    const selectedTarget = target.trim();
    if (!selectedTarget) {
      setTrendsError("Enter a target IP or CIDR first.");
      return;
    }
    setTrendsLoading(true);
    setTrendsError("");
    try {
      const response = await apiFetch(
        `/guardian/trends?target=${encodeURIComponent(selectedTarget)}`
      );
      if (!response.ok) throw new Error(await readError(response));
      const data = await response.json();
      setTrends(data.scans);
    } catch (e) {
      setTrendsError(e instanceof Error ? e.message : "Could not load risk trends.");
    } finally {
      setTrendsLoading(false);
    }
  }

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
    setVulnerabilityReport(null);
    setVulnerabilitiesError("");

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
        <h2>Risk Trends</h2>
        <p className="muted">
          Track security exposure over time for a specific target.
          Risk score is capped at 100.
        </p>
        <button
          className="button"
          disabled={trendsLoading || !target.trim()}
          onClick={() => void loadTrends()}
        >
          {trendsLoading ? "Loading trends..." : "Load risk trends"}
        </button>

        {trendsError && (
          <p className="error-message" role="alert" style={{ marginTop: 12 }}>
            {trendsError}
          </p>
        )}

        {trends.length > 0 && (
          <div style={{ marginTop: 20 }}>
            <div
              style={{
                display: "flex",
                alignItems: "end",
                gap: 8,
                minHeight: 180,
                overflowX: "auto",
                padding: "12px 4px 0",
                borderBottom: "1px solid var(--border, #888)",
              }}
              aria-label="Risk score by scan"
            >
              {trends.map((scan) => (
                <div
                  key={scan.id}
                  title={`${new Date(scan.scanned_at).toLocaleString("en-GB")} — Risk score ${scan.risk_score}/100`}
                  style={{
                    minWidth: 42,
                    flex: "1 0 42px",
                    maxWidth: 76,
                    textAlign: "center",
                  }}
                >
                  <div style={{ fontSize: 12, marginBottom: 5 }}>
                    {scan.risk_score}
                  </div>
                  <div
                    style={{
                      height: `${Math.max(scan.risk_score, 2)}px`,
                      minHeight: 3,
                      maxHeight: 100,
                      background:
                        scan.risk_score >= 70
                          ? "#b91c1c"
                          : scan.risk_score >= 35
                            ? "#d97706"
                            : "#15803d",
                      borderRadius: "4px 4px 0 0",
                      margin: "0 auto",
                      width: "70%",
                    }}
                  />
                  <div style={{ fontSize: 11, marginTop: 6 }}>
                    #{scan.id}
                  </div>
                </div>
              ))}
            </div>
            <p className="muted" style={{ marginTop: 12 }}>
              Green: 0–34 · Amber: 35–69 · Red: 70–100.
              Scores are severity-weighted exposure indicators, not proof of exploitability.
            </p>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Date", "Scan", "Risk score", "Findings", "Open ports"].map((heading) => (
                      <th key={heading} style={{ textAlign: "left", padding: 8 }}>
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {trends.map((scan) => (
                    <tr key={scan.id}>
                      <td style={{ padding: 8 }}>
                        {new Date(scan.scanned_at).toLocaleString("en-GB")}
                      </td>
                      <td style={{ padding: 8 }}>#{scan.id}</td>
                      <td style={{ padding: 8 }}>{scan.risk_score}/100</td>
                      <td style={{ padding: 8 }}>{scan.findings_count}</td>
                      <td style={{ padding: 8 }}>{scan.open_ports}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {!trendsLoading && !trendsError && trends.length === 0 && (
          <p className="muted" style={{ marginTop: 12 }}>
            Enter a target and load its saved scan history.
          </p>
        )}
      </section>

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

          <button
            className="button"
            disabled={vulnerabilitiesLoading}
            onClick={() => void checkVulnerabilities(result.id)}
          >
            {vulnerabilitiesLoading
              ? "Checking NVD..."
              : "Check for known vulnerabilities"}
          </button>

          {vulnerabilitiesError && (
            <p className="error-message" role="alert" style={{ marginTop: 12 }}>
              {vulnerabilitiesError}
            </p>
          )}

          {vulnerabilityReport?.scan_id === result.id && (
            <div style={{ marginTop: 18 }}>
              <h3>Known Vulnerability Lookup</h3>
              <p className="muted">
                Source: {vulnerabilityReport.source}. Checked services:{" "}
                {vulnerabilityReport.checked_services}.
              </p>
              <p>{vulnerabilityReport.notice}</p>

              {vulnerabilityReport.errors.map((item, index) => (
                <p className="error-message" role="alert" key={`${index}:${item}`}>
                  {item}
                </p>
              ))}

              {vulnerabilityReport.results.length === 0 ? (
                <p>
                  {vulnerabilityReport.errors.length > 0
                    ? "The lookup was incomplete. No conclusion can be drawn from failed lookups."
                    : "No potential matches were returned by NVD for the checked product/version keywords. This does not prove the software is free of vulnerabilities."}
                </p>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["CVE", "Severity", "CVSS", "Detected product / version", "Description", "Source"].map((heading) => (
                          <th key={heading} style={{ textAlign: "left", padding: 10 }}>
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {vulnerabilityReport.results.map((item) => (
                        <tr key={`${item.cve_id}:${item.matched_product}:${item.detected_version}`}>
                          <td style={{ padding: 10, verticalAlign: "top" }}>
                            <a href={item.url} target="_blank" rel="noopener noreferrer">
                              {item.cve_id}
                            </a>
                            <div className="muted">Potential match</div>
                          </td>
                          <td style={{ padding: 10, verticalAlign: "top" }}>
                            {item.severity}
                          </td>
                          <td style={{ padding: 10, verticalAlign: "top" }}>
                            {item.cvss_score ?? "N/A"}
                          </td>
                          <td style={{ padding: 10, verticalAlign: "top" }}>
                            {item.matched_product} {item.detected_version}
                          </td>
                          <td style={{ padding: 10, verticalAlign: "top", minWidth: 240 }}>
                            {item.description}
                          </td>
                          <td style={{ padding: 10, verticalAlign: "top" }}>
                            <a href={item.url} target="_blank" rel="noopener noreferrer">
                              NVD
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

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

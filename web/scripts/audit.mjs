import { spawnSync } from "node:child_process";

// Cortex is a client-only Vite SPA. It does not use React Router's RSC mode,
// server actions, or createCallServer, so GHSA-qwww-vcr4-c8h2 is not reachable.
// Keep this exception exact and fail closed for every other production finding.
const ALLOWED = new Map([
  [
    "react-router",
    new Set(["https://github.com/advisories/GHSA-qwww-vcr4-c8h2"]),
  ],
  ["react-router-dom", new Set(["react-router"])],
]);

const audit = spawnSync(
  process.platform === "win32" ? "npm.cmd" : "npm",
  ["audit", "--omit=dev", "--json"],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);

let report;
try {
  report = JSON.parse(audit.stdout || "{}");
} catch (error) {
  console.error("npm audit did not return valid JSON");
  console.error(audit.stderr || error);
  process.exit(1);
}

const unexpected = [];
for (const [name, finding] of Object.entries(report.vulnerabilities || {})) {
  const allowedVia = ALLOWED.get(name);
  const via = Array.isArray(finding.via) ? finding.via : [];
  const identifiers = via.map((item) =>
    typeof item === "string" ? item : item?.url,
  );
  if (
    !allowedVia ||
    identifiers.length === 0 ||
    identifiers.some((identifier) => !allowedVia.has(identifier))
  ) {
    unexpected.push({ name, severity: finding.severity, via: identifiers });
  }
}

if (unexpected.length > 0 || report.error) {
  console.error("Unexpected production dependency vulnerabilities:");
  console.error(JSON.stringify(unexpected.length ? unexpected : report.error, null, 2));
  process.exit(1);
}

if ((report.metadata?.vulnerabilities?.total || 0) > 0) {
  console.warn(
    "Acknowledged GHSA-qwww-vcr4-c8h2 for unused React Router RSC mode; no other production vulnerabilities found.",
  );
} else {
  console.log("No production dependency vulnerabilities found.");
}

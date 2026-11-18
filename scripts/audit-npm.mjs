import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ghsa = 'GHSA-fc5q-39xc-vjpf';
const cve = 'CVE-2026-112366';
const npmAdvisory = 'https://github.com/advisories/' + ghsa;
const githubRecord = 'https://api.github.com/advisories/' + ghsa;
const severities = ['info', 'low', 'moderate', 'high', 'critical'];
const expectedDevPackages = new Set(['picomatch', 'fdir', 'tinyglobby', 'vite', 'vitest']);

const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isKnownRange = (range) => typeof range === 'string' && range.replace(/\s/g, '') === '<=4.0.7';

function isExactNpmAdvisory(cause) {
  return (
    isRecord(cause) &&
    cause.source === 1247710 &&
    cause.url === npmAdvisory &&
    cause.name === 'picomatch' &&
    cause.dependency === 'picomatch' &&
    cause.severity === 'high' &&
    isKnownRange(cause.range)
  );
}

function isWithdrawnGithubRecord(record) {
  if (!record || record.ghsa_id !== ghsa || record.cve_id !== cve) return false;
  if (!Array.isArray(record.vulnerabilities) || record.vulnerabilities.length !== 1) return false;
  const [finding] = record.vulnerabilities;
  const withdrawn = record.withdrawn_at;
  return (
    finding?.package?.ecosystem === 'npm' &&
    finding.package.name === 'picomatch' &&
    isKnownRange(finding.vulnerable_version_range) &&
    typeof withdrawn === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(withdrawn) &&
    Date.parse(withdrawn) <= Date.now()
  );
}

function isKnownDevFinding(name, findings, packages, visited = new Set()) {
  if (!expectedDevPackages.has(name) || visited.has(name)) return false;
  const entry = findings.get(name);
  if (
    entry?.severity !== 'high' ||
    !Array.isArray(entry.nodes) ||
    !entry.nodes.length ||
    !Array.isArray(entry.via) ||
    !entry.via.length
  )
    return false;
  const devOnly = entry.nodes.every((node) => {
    if (
      typeof node !== 'string' ||
      (node !== `node_modules/${name}` && !node.endsWith(`/node_modules/${name}`))
    )
      return false;
    const pkg = Object.hasOwn(packages, node) ? packages[node] : null;
    return pkg?.dev === true && (name !== 'picomatch' || pkg.version === '4.0.7');
  });
  if (!devOnly) return false;
  if (name === 'picomatch') return entry.via.length === 1 && isExactNpmAdvisory(entry.via[0]);
  const path = new Set(visited).add(name);
  return entry.via.every(
    (cause) => typeof cause === 'string' && isKnownDevFinding(cause, findings, packages, path),
  );
}

export async function verifyNpmAudit(report, exitStatus, packages, getAdvisory) {
  if (report?.error || report?.auditReportVersion !== 2 || !isRecord(report.vulnerabilities)) {
    throw new Error('npm did not return a complete audit report.');
  }
  const counts = report.metadata?.vulnerabilities;
  const findings = new Map(Object.entries(report.vulnerabilities));
  if (
    !isRecord(counts) ||
    counts.total !== findings.size ||
    severities.some(
      (severity) =>
        counts[severity] !==
        [...findings.values()].filter((entry) => entry?.severity === severity).length,
    ) ||
    [...findings].some(
      ([name, entry]) => entry?.name !== name || !severities.includes(entry.severity),
    )
  ) {
    throw new Error('npm audit report counts or findings are inconsistent.');
  }
  const { high, critical } = counts;
  if (exitStatus === 0 && high === 0 && critical === 0) return { withdrawn: null, high, critical };
  if (
    exitStatus !== 1 ||
    !high ||
    critical ||
    !isRecord(packages) ||
    packages['']?.name !== 'snurpo-desktop' ||
    ![...findings]
      .filter(([, entry]) => entry.severity === 'high')
      .every(([name]) => isKnownDevFinding(name, findings, packages))
  ) {
    throw new Error('npm audit did not pass the high/critical dependency gate.');
  }
  if (!isWithdrawnGithubRecord(await getAdvisory())) {
    throw new Error(`GitHub has not confirmed the withdrawal of ${ghsa}.`);
  }
  return { withdrawn: ghsa, high, critical };
}

async function fetchGithubAdvisory() {
  const response = await fetch(githubRecord, {
    headers: { Accept: 'application/vnd.github+json', 'Cache-Control': 'no-cache' },
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`GitHub advisory API returned HTTP ${response.status}.`);
  return response.json();
}

async function main() {
  const npm = process.env.npm_execpath;
  if (!npm) throw new Error('Run this check with npm run audit:ci.');
  const root = new URL('../', import.meta.url);
  const audit = spawnSync(
    process.execPath,
    [
      npm,
      'audit',
      '--json',
      '--audit-level=high',
      '--include=dev',
      '--prefer-online',
      '--registry=https://registry.npmjs.org',
    ],
    {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000,
    },
  );
  if (audit.error) throw audit.error;
  const report = JSON.parse(audit.stdout);
  const { packages } = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8'));
  try {
    const result = await verifyNpmAudit(report, audit.status, packages, fetchGithubAdvisory);
    if (result.withdrawn) {
      console.log(
        `npm reported ${result.high} high dev findings attributed only to ${result.withdrawn}.`,
      );
      console.log(
        `GitHub confirms withdrawal. Residual dev-tool risk tracked separately as ${cve}.`,
      );
    } else {
      console.log('npm audit passed the high/critical dependency gate.');
    }
  } catch (error) {
    console.error(audit.stdout.trim());
    throw error;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

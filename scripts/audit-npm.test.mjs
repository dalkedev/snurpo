import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyNpmAudit } from './audit-npm.mjs';

const advisoryId = 'GHSA-fc5q-39xc-vjpf';
const advisoryUrl = `https://github.com/advisories/${advisoryId}`;
const npmFinding = {
  source: 1247710,
  name: 'picomatch',
  dependency: 'picomatch',
  url: advisoryUrl,
  range: '<=4.0.7',
  severity: 'high',
};
const githubAdvisory = {
  ghsa_id: advisoryId,
  cve_id: 'CVE-2026-112366',
  html_url: advisoryUrl,
  type: 'reviewed',
  published_at: '2026-10-19T18:32:12Z',
  withdrawn_at: '2026-11-18T15:38:56Z',
  updated_at: '2026-11-18T15:38:58Z',
  vulnerabilities: [
    {
      package: { ecosystem: 'npm', name: 'picomatch' },
      vulnerable_version_range: '<= 4.0.7',
    },
  ],
};

const packages = {
  '': { name: 'snurpo-desktop', version: '1.5.1' },
  'node_modules/fdir': { version: '6.5.0', dev: true },
  'node_modules/picomatch': { version: '4.0.7', dev: true },
  'node_modules/tinyglobby': { version: '0.2.17', dev: true },
  'node_modules/vite': { version: '6.4.5', dev: true },
  'node_modules/vitest': { version: '5.1.0', dev: true },
};

function vulnerabilitiesFixture() {
  const graph = {
    fdir: ['picomatch'],
    picomatch: [{ ...npmFinding }],
    tinyglobby: ['fdir', 'picomatch'],
    vite: ['fdir', 'picomatch', 'tinyglobby'],
    vitest: ['picomatch', 'tinyglobby', 'vite'],
  };
  return Object.fromEntries(
    Object.entries(graph).map(([name, via]) => [
      name,
      {
        name,
        via,
        severity: 'high',
        isDirect: name === 'vite' || name === 'vitest',
        effects: Object.keys(graph).filter((other) => graph[other].includes(name)),
        range: '*',
        nodes: [`node_modules/${name}`],
        fixAvailable: { name: 'vitest', version: '3.1.4', isSemVerMajor: true },
      },
    ]),
  );
}

function reportFixture(vulnerabilities = vulnerabilitiesFixture()) {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  for (const { severity } of Object.values(vulnerabilities)) {
    counts[severity] += 1;
    counts.total += 1;
  }
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: counts },
  };
}

const getAdvisory = async () => githubAdvisory;

test('uses the normal npm pass result without contacting GitHub', async () => {
  let calls = 0;
  const result = await verifyNpmAudit(reportFixture({}), 0, packages, async () => {
    calls += 1;
    return githubAdvisory;
  });
  assert.deepEqual(result, { withdrawn: null, high: 0, critical: 0 });
  assert.equal(calls, 0);
});

test('preserves the high severity threshold for lower findings accepted by npm', async () => {
  const vulnerabilities = vulnerabilitiesFixture();
  vulnerabilities.picomatch.severity = 'moderate';
  vulnerabilities.picomatch.via[0].severity = 'moderate';
  const report = reportFixture({ picomatch: vulnerabilities.picomatch });
  const result = await verifyNpmAudit(report, 0, packages, async () => {
    assert.fail('npm did not require an advisory exception');
  });
  assert.deepEqual(result, { withdrawn: null, high: 0, critical: 0 });
});

test('accepts the exact withdrawn advisory and all of its transitive findings', async () => {
  let calls = 0;
  const result = await verifyNpmAudit(reportFixture(), 1, packages, async () => {
    calls += 1;
    return githubAdvisory;
  });
  assert.equal(calls, 1);
  assert.equal(result.high, 5);
  assert.equal(result.critical, 0);
  assert.equal(result.withdrawn, advisoryId);
});

test('requires a matching official advisory and a valid past withdrawal date', async () => {
  const invalidAdvisories = [
    { ...githubAdvisory, withdrawn_at: null },
    { ...githubAdvisory, withdrawn_at: 'recently' },
    { ...githubAdvisory, withdrawn_at: '2999-01-01T00:00:00Z' },
    { ...githubAdvisory, ghsa_id: 'GHSA-2222-3333-4444' },
    { ...githubAdvisory, cve_id: 'CVE-2026-99999' },
    {
      ...githubAdvisory,
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: 'different-package' },
          vulnerable_version_range: '<= 4.0.7',
        },
      ],
    },
    {
      ...githubAdvisory,
      vulnerabilities: [
        { package: { ecosystem: 'pip', name: 'picomatch' }, vulnerable_version_range: '<= 4.0.7' },
      ],
    },
    {
      ...githubAdvisory,
      vulnerabilities: [
        { package: { ecosystem: 'npm', name: 'picomatch' }, vulnerable_version_range: '< 4.0.8' },
      ],
    },
  ];
  for (const advisory of invalidAdvisories) {
    await assert.rejects(verifyNpmAudit(reportFixture(), 1, packages, async () => advisory));
  }
});

test('fails instead of suppressing findings when advisory verification throws', async () => {
  await assert.rejects(
    verifyNpmAudit(reportFixture(), 1, packages, async () => {
      throw new Error('GitHub advisory verification timed out');
    }),
  );
});

test('keeps the gate on npm advisories outside the single exact match', async () => {
  const unrecognizedFinding = {
    ...npmFinding,
    source: 1247711,
    url: 'https://github.com/advisories/GHSA-2222-3333-4444',
  };
  const wrongSource = vulnerabilitiesFixture();
  wrongSource.picomatch.via[0].source = 1247711;
  const mixed = vulnerabilitiesFixture();
  mixed.picomatch.via.push(unrecognizedFinding);
  const separate = vulnerabilitiesFixture();
  separate.vite.via.push({ ...unrecognizedFinding, name: 'vite', dependency: 'vite' });
  for (const vulnerabilities of [wrongSource, mixed, separate]) {
    await assert.rejects(verifyNpmAudit(reportFixture(vulnerabilities), 1, packages, getAdvisory));
  }
});

test('keeps the gate on a critical finding alongside the withdrawn advisory', async () => {
  const vulnerabilities = vulnerabilitiesFixture();
  vulnerabilities.vite.severity = 'critical';
  await assert.rejects(verifyNpmAudit(reportFixture(vulnerabilities), 1, packages, getAdvisory));
});

test('rejects missing, empty, and cyclic transitive causes', async () => {
  for (const via of [['not-in-report'], [], ['tinyglobby']]) {
    const vulnerabilities = vulnerabilitiesFixture();
    vulnerabilities.fdir.via = via;
    await assert.rejects(verifyNpmAudit(reportFixture(vulnerabilities), 1, packages, getAdvisory));
  }
});

test('requires affected lockfile nodes to be development packages and picomatch to be 4.0.7', async () => {
  await assert.rejects(
    verifyNpmAudit(
      reportFixture(),
      1,
      {
        ...packages,
        'node_modules/picomatch': { version: '4.0.6', dev: true },
      },
      getAdvisory,
    ),
  );
  await assert.rejects(
    verifyNpmAudit(
      reportFixture(),
      1,
      {
        ...packages,
        'node_modules/vite': { version: '6.4.5', dev: false },
      },
      getAdvisory,
    ),
  );
});

test('does not apply the exception to a different npm project', async () => {
  const otherPackages = { ...packages, '': { name: 'another-project', version: '1.5.1' } };
  await assert.rejects(verifyNpmAudit(reportFixture(), 1, otherPackages, getAdvisory));
});

test('fails on an unsupported report, inconsistent metrics, or a failed npm process', async () => {
  const inconsistent = reportFixture();
  inconsistent.metadata.vulnerabilities.high = 4;
  const failures = [
    [null, 1],
    [{ ...reportFixture(), auditReportVersion: 99 }, 1],
    [{ ...reportFixture(), error: { code: 'EAUDIT' } }, 1],
    [inconsistent, 1],
    [reportFixture(), 0],
    [reportFixture(), 2],
    [reportFixture({}), 1],
  ];
  for (const [report, exitStatus] of failures) {
    await assert.rejects(verifyNpmAudit(report, exitStatus, packages, getAdvisory));
  }
});

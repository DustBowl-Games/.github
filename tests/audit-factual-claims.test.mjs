import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  auditText,
  evaluateFindings,
  resolveRepoRoot,
  validateAllowlist,
} from '../.github/scripts/audit-factual-claims.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPT_PATH = path.resolve(__dirname, '../.github/scripts/audit-factual-claims.mjs');

test('detects all 6 unapproved claim rule categories on realistic public copy', () => {
  const sample = [
    '<p>General &amp; Sales: Within 24 Hours</p>',
    '<p>Hardware &amp; PC Builds: Same Business Day</p>',
    '<p>Active Server Outages: Priority Ticket Dispatch</p>',
    '<span>&lt; 2 Hour Technical Response</span>',
    '<p>We run a 95% SLA by design and 98.0% Honest SLA.</p>',
    '<p>13-17ms Hickory Fiber with Sub-20ms East Coast routing.</p>',
    '<p>24/7 uptime and 48-hour risk-free deployment guarantees.</p>',
    '<p>Certified SOC 2 and NIST 800-88 compliance.</p>',
  ].join('\n');

  const findings = auditText(sample, 'Components/Pages/Contact.razor');
  const ruleIds = new Set(findings.map(f => f.ruleId));

  assert.ok(ruleIds.has('UNAPPROVED_RESPONSE_SLA'));
  assert.ok(ruleIds.has('UNAPPROVED_SLA_PERCENT'));
  assert.ok(ruleIds.has('UNAPPROVED_FIBER_OR_LATENCY_CLAIM'));
  assert.ok(ruleIds.has('UNAPPROVED_24_7_CLAIM'));
  assert.ok(ruleIds.has('UNAPPROVED_GUARANTEE_OR_REFUND_CLAIM'));
  assert.ok(ruleIds.has('UNAPPROVED_CERTIFICATION_CLAIM'));
});

test('ignores Razor comments, HTML comments, CSS utility classes, and clean copy', () => {
  const sample = `
@* 98% SLA and Same Business Day in comment *@
<!-- 24/7 uptime and SOC 2 in HTML comment -->
<div class="min-h-11 duration-200 px-4 py-2" data-sla="99">
  <p>We host game servers on owned bare-metal hardware in Hickory, NC.</p>
  <p>Open a support ticket and our engineering team will review it.</p>
</div>
@code {
  private readonly string _slaRoute = "/sla";
  // 13-17ms Hickory Fiber in C# comment
}
`;
  const findings = auditText(sample, 'Components/Pages/Home.razor');
  assert.equal(findings.length, 0);
});

test('validateAllowlist enforces required metadata fields', () => {
  const valid = {
    schemaVersion: 1,
    verifiedFacts: [
      {
        id: 'no-fake-24-7',
        file: 'Components/Shared/HostComparisonTable.razor',
        ruleId: 'UNAPPROVED_24_7_CLAIM',
        match: 'no fake "24/7" promise',
        verifiedBy: 'policy/honest-marketing',
        reason: 'Explicitly disclaims fake 24/7 claims.',
      },
    ],
    legacyAuditBaseline: [],
  };
  assert.deepEqual(validateAllowlist(valid), []);

  const invalid = {
    schemaVersion: 1,
    verifiedFacts: [{ id: 'x', file: 'a.razor', ruleId: 'UNAPPROVED_24_7_CLAIM', match: '24/7', verifiedBy: '', reason: '' }],
    legacyAuditBaseline: [{ file: 'b.razor', ruleId: 'UNAPPROVED_SLA_PERCENT', fingerprint: '', status: 'needs-owner-review' }],
  };
  const errors = validateAllowlist(invalid);
  assert.ok(errors.length >= 3);
});

test('verifiedFacts allowlist only matches exact file + ruleId + match, and legacy baseline blocks copy-paste growth', () => {
  const copy = [
    '<p>"24/7 monitoring with honest, best-effort human support - no fake \\"24/7\\" promise"</p>',
    '<p>Same Business Day</p>',
  ].join('\n');

  const findings = auditText(copy, 'Components/Shared/HostComparisonTable.razor');
  const allowlist = {
    schemaVersion: 1,
    verifiedFacts: [
      {
        id: 'no-fake-24-7',
        file: 'Components/Shared/HostComparisonTable.razor',
        ruleId: 'UNAPPROVED_24_7_CLAIM',
        match: 'no fake \\"24/7\\" promise',
        verifiedBy: 'policy/honest-marketing',
        reason: 'Disclaims fake 24/7.',
      },
    ],
    legacyAuditBaseline: [
      {
        file: 'Components/Shared/HostComparisonTable.razor',
        ruleId: 'UNAPPROVED_RESPONSE_SLA',
        fingerprint: '<p>Same Business Day</p>',
        status: 'needs-owner-review',
      },
    ],
  };

  // Exact match passes
  const res1 = evaluateFindings(findings, allowlist, { strict: false });
  assert.equal(res1.verifiedMatches.length, 1);
  assert.equal(res1.legacyMatches.length, 1);
  assert.equal(res1.unapproved.length, 0);

  // Strict mode rejects legacy baseline entries
  const resStrict = evaluateFindings(findings, allowlist, { strict: true });
  assert.equal(resStrict.unapproved.length, 1);

  // Copy-pasting the legacy claim a second time exceeds baseline count (1) and fails
  const duplicated = auditText('<p>Same Business Day</p>\n<p>Same Business Day</p>', 'Components/Shared/HostComparisonTable.razor');
  const resDup = evaluateFindings(duplicated, allowlist, { strict: false });
  assert.equal(resDup.legacyMatches.length, 1);
  assert.equal(resDup.unapproved.length, 1);

  // Removing the legacy claim shrinks cleanly and still passes
  const cleaned = auditText('<p>We reply during EST hours.</p>', 'Components/Shared/HostComparisonTable.razor');
  const resClean = evaluateFindings(cleaned, allowlist, { strict: false });
  assert.equal(resClean.unapproved.length, 0);
});

test('resolveRepoRoot prefers --repo-root, then GITHUB_WORKSPACE, then cwd', () => {
  const cwd = path.resolve('a', 'b');
  assert.equal(
    resolveRepoRoot(['--repo-root', '/tmp/caller'], cwd, { GITHUB_WORKSPACE: '/tmp/ws' }),
    path.resolve(cwd, '/tmp/caller')
  );
  assert.equal(
    resolveRepoRoot(['--repo-root=/tmp/eq-caller'], cwd, { GITHUB_WORKSPACE: '/tmp/ws' }),
    path.resolve(cwd, '/tmp/eq-caller')
  );
  assert.equal(
    resolveRepoRoot([], cwd, { GITHUB_WORKSPACE: '/tmp/ws' }),
    path.resolve(cwd, '/tmp/ws')
  );
  assert.equal(resolveRepoRoot([], cwd, {}), cwd);
});

test('CLI scans caller workspace via --repo-root and GITHUB_WORKSPACE even when invoked from simulated .org-ci directory', () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'claims-gate-test-'));
  try {
    const callerWs = path.join(tmpBase, 'caller-workspace');
    const orgCiDir = path.join(callerWs, '.org-ci', '.github', 'scripts');
    fs.mkdirSync(orgCiDir, { recursive: true });
    fs.copyFileSync(SCRIPT_PATH, path.join(orgCiDir, 'audit-factual-claims.mjs'));

    const pagesDir = path.join(callerWs, 'Components', 'Pages');
    const cfgDir = path.join(callerWs, 'config');
    fs.mkdirSync(pagesDir, { recursive: true });
    fs.mkdirSync(cfgDir, { recursive: true });
    fs.writeFileSync(
      path.join(cfgDir, 'verified-claims-allowlist.json'),
      JSON.stringify({ schemaVersion: 1, verifiedFacts: [], legacyAuditBaseline: [] }, null, 2)
    );

    const razorPath = path.join(pagesDir, 'Pricing.razor');
    fs.writeFileSync(razorPath, '<p>We offer a 99.9% uptime guarantee and 24/7 support.</p>\n');

    const copiedScript = path.join(orgCiDir, 'audit-factual-claims.mjs');

    // Negative: explicit --repo-root catches violation inside caller workspace
    const negExplicit = spawnSync(
      process.execPath,
      [copiedScript, '--repo-root', callerWs, '--allowlist', path.join(cfgDir, 'verified-claims-allowlist.json'), '--all'],
      { cwd: orgCiDir, env: { ...process.env, GITHUB_WORKSPACE: '' }, encoding: 'utf8' }
    );
    assert.notEqual(negExplicit.status, 0);
    assert.match(negExplicit.stderr, /UNAPPROVED_SLA_PERCENT/);
    assert.match(negExplicit.stderr, /UNAPPROVED_24_7_CLAIM/);

    // Negative: GITHUB_WORKSPACE fallback catches violation without --repo-root
    const negEnv = spawnSync(
      process.execPath,
      [copiedScript, '--all'],
      { cwd: orgCiDir, env: { ...process.env, GITHUB_WORKSPACE: callerWs }, encoding: 'utf8' }
    );
    assert.notEqual(negEnv.status, 0);
    assert.match(negEnv.stderr, /UNAPPROVED_SLA_PERCENT/);

    // Negative: non-existent --repo-root fails loudly
    const missingDir = spawnSync(
      process.execPath,
      [copiedScript, '--repo-root', path.join(tmpBase, 'does-not-exist'), '--all'],
      { cwd: orgCiDir, encoding: 'utf8' }
    );
    assert.notEqual(missingDir.status, 0);
    assert.match(missingDir.stderr, /does not exist/);

    // Positive: clean copy passes with exit 0
    fs.writeFileSync(razorPath, '<p>Game server hosting on bare-metal hardware in Hickory, NC.</p>\n');
    const posRes = spawnSync(
      process.execPath,
      [copiedScript, `--repo-root=${callerWs}`, '--all'],
      { cwd: orgCiDir, env: { ...process.env, GITHUB_WORKSPACE: '' }, encoding: 'utf8' }
    );
    assert.equal(posRes.status, 0, posRes.stderr);
    assert.match(posRes.stdout, /Auditing 1 public-facing file\(s\)/);
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test('legacyAuditBaseline respects count: 0 and rejects non-integer/negative counts', () => {
  const findings = auditText('<p>Same Business Day</p>', 'Components/Shared/Host.razor');
  const allowZero = {
    schemaVersion: 1,
    verifiedFacts: [],
    legacyAuditBaseline: [
      {
        file: 'Components/Shared/Host.razor',
        ruleId: 'UNAPPROVED_RESPONSE_SLA',
        fingerprint: '<p>Same Business Day</p>',
        status: 'needs-owner-review',
        count: 0,
      },
    ],
  };
  assert.deepEqual(validateAllowlist(allowZero), []);
  const resZero = evaluateFindings(findings, allowZero, { strict: false });
  assert.equal(resZero.legacyMatches.length, 0);
  assert.equal(resZero.unapproved.length, 1);

  for (const badCount of ['999', -1, 1.5]) {
    assert.throws(() =>
      evaluateFindings(findings, {
        schemaVersion: 1,
        verifiedFacts: [],
        legacyAuditBaseline: [{ ...allowZero.legacyAuditBaseline[0], count: badCount }],
      })
    );
    assert.ok(
      validateAllowlist({
        schemaVersion: 1,
        verifiedFacts: [],
        legacyAuditBaseline: [{ ...allowZero.legacyAuditBaseline[0], count: badCount }],
      }).length > 0
    );
  }
});

test('audits multi-line and single-line C# raw string literals while ignoring clean copy and comments', () => {
  const csBad = [
    'public static class SeedArticles {',
    '  // 24/7 support in comment outside literal is ignored',
    '  public const string Body = """',
    '      We guarantee 24/7 support and 99.9% uptime guarantee.',
    '      """;',
    '  public const string FourQuotes = $""""',
    '      Same Business Day dispatch for "{tier}".',
    '      """";',
    '  public const string Inline = """SOC 2 certified""";',
    '}',
  ].join('\n');

  const findings = auditText(csBad, 'Services/SeedArticles.cs');
  const rules = new Set(findings.map(f => f.ruleId));
  assert.ok(rules.has('UNAPPROVED_24_7_CLAIM'));
  assert.ok(rules.has('UNAPPROVED_SLA_PERCENT'));
  assert.ok(rules.has('UNAPPROVED_RESPONSE_SLA'));
  assert.ok(rules.has('UNAPPROVED_CERTIFICATION_CLAIM'));
  assert.equal(findings.some(f => f.line === 2), false);

  const csClean = [
    'public static class CleanArticles {',
    '  public const string Body = """',
    '      Owned bare-metal game server hosting in Hickory, NC.',
    '      """;',
    '}',
  ].join('\n');
  assert.equal(auditText(csClean, 'Services/SeedArticles.cs').length, 0);
});

test('CLI diff mode fails closed when GITHUB_BASE_SHA / GITHUB_HEAD_SHA fail git diff', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'claims-badsha-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);
    fs.mkdirSync(path.join(tmpRepo, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'config', 'verified-claims-allowlist.json'),
      JSON.stringify({ schemaVersion: 1, verifiedFacts: [], legacyAuditBaseline: [] })
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: init']);

    const res = spawnSync(process.execPath, [SCRIPT_PATH, '--repo-root', tmpRepo], {
      encoding: 'utf8',
      env: { ...process.env, GITHUB_BASE_SHA: 'deadbeef'.repeat(5), GITHUB_HEAD_SHA: 'cafebabe'.repeat(5) },
    });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /\[FAIL\]/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

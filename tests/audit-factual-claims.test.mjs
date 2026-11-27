import assert from 'node:assert/strict';
import test from 'node:test';
import {
  auditText,
  evaluateFindings,
  validateAllowlist,
} from '../.github/scripts/audit-factual-claims.mjs';

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
    '<p>"24/7 monitoring with honest, best-effort human support â€” no fake \\"24/7\\" promise"</p>',
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

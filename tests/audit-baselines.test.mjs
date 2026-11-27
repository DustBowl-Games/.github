import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  compareIgnoreFiles,
  compareJsonBaselines,
  discoverBaseBaselineFiles,
  hasBaselineInitApproval,
  hasBaselineRemovalApproval,
} from '../.github/scripts/audit-baselines.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPT_PATH = path.resolve(__dirname, '../.github/scripts/audit-baselines.mjs');

test('JSON baseline ratchet allows shrinking/unchanged and blocks growth or key swapping', () => {
  const base = JSON.stringify({
    schemaVersion: 1,
    ai_smells_baseline: [
      { file: 'src/A.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'catch {}', count: 2 },
    ],
  });

  // Positive: shrunk count
  const shrunk = JSON.stringify({
    schemaVersion: 1,
    ai_smells_baseline: [
      { file: 'src/A.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'catch {}', count: 1 },
    ],
  });
  assert.deepEqual(compareJsonBaselines(base, shrunk, 'config/ai-smells-baseline.json'), []);

  // Negative: grew count
  const grew = JSON.stringify({
    schemaVersion: 1,
    ai_smells_baseline: [
      { file: 'src/A.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'catch {}', count: 3 },
    ],
  });
  assert.equal(compareJsonBaselines(base, grew, 'config/ai-smells-baseline.json').length > 0, true);

  // Negative: same total (2) but swapped in a new entry
  const swapped = JSON.stringify({
    schemaVersion: 1,
    ai_smells_baseline: [
      { file: 'src/A.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'catch {}', count: 1 },
      { file: 'src/B.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'catch {}', count: 1 },
    ],
  });
  const swapErrs = compareJsonBaselines(base, swapped, 'config/ai-smells-baseline.json');
  assert.equal(swapErrs.length > 0, true);
});

test('ignore-file ratchet allows shrinking and new comments, blocks adding or swapping CVEs', () => {
  const base = '# existing\nCVE-2024-0001\nCVE-2024-0002\n';

  // Positive: removed one CVE and added comment lines
  const shrunk = '# reviewed\n# still tracked\nCVE-2024-0001\n';
  assert.deepEqual(compareIgnoreFiles(base, shrunk, '.trivyignore'), []);

  // Negative: added a CVE
  const added = '# existing\nCVE-2024-0001\nCVE-2024-0002\nCVE-2025-9999\n';
  assert.equal(compareIgnoreFiles(base, added, '.trivyignore').length > 0, true);

  // Negative: swapped CVE
  const swapped = 'CVE-2024-0001\nCVE-2025-9999\n';
  assert.equal(compareIgnoreFiles(base, swapped, '.trivyignore').length > 0, true);
});

test('hasBaselineInitApproval requires issue number or URL', () => {
  assert.equal(hasBaselineInitApproval('chore: init\n\nAllow-Baseline-Init: #2451', ''), true);
  assert.equal(hasBaselineInitApproval('', 'Allow-Baseline-Init: https://github.com/org/repo/issues/12'), true);
  assert.equal(hasBaselineInitApproval('chore: init\n\nAllow-Baseline-Init: trust-me', ''), false);
  assert.equal(hasBaselineInitApproval('', 'Allow-Baseline-Init:\n\n#123'), false);
  assert.equal(hasBaselineInitApproval('chore: init', ''), false);
});

test('hasBaselineRemovalApproval requires a non-empty reason', () => {
  assert.equal(
    hasBaselineRemovalApproval('chore: cleanup\n\nAllow-Baseline-Removal: all violations fixed (#123)', ''),
    true
  );
  assert.equal(hasBaselineRemovalApproval('', 'Allow-Baseline-Removal: resolved'), true);
  assert.equal(hasBaselineRemovalApproval('chore: cleanup\n\nAllow-Baseline-Removal:   ', ''), false);
  assert.equal(hasBaselineRemovalApproval('', 'Allow-Baseline-Removal:\n\n## Summary\nRoutine refactor'), false);
  assert.equal(
    hasBaselineRemovalApproval('chore: drop\n\nAllow-Baseline-Removal:\nSigned-off-by: Bot', ''),
    false
  );
  assert.equal(hasBaselineRemovalApproval('chore: cleanup', ''), false);
});

test('CLI blocks unauthorized new .trivyignore in git repo and allows with Allow-Baseline-Init', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-git-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.mkdirSync(path.join(tmpRepo, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'config', 'ai-smells-baseline.json'),
      JSON.stringify({ ai_smells_baseline: [{ file: 'a.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'x', count: 1 }] })
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: initial baseline']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    // Commit 2: add unapproved .trivyignore
    fs.writeFileSync(path.join(tmpRepo, '.trivyignore'), 'CVE-2024-1234\n');
    git(['add', '.']);
    git(['commit', '-m', 'chore: add trivyignore']);
    const headSha = git(['rev-parse', 'HEAD']).trim();

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha],
      { encoding: 'utf8' }
    );
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /BASELINE_RATCHET/);

    // With Allow-Baseline-Init in PR_BODY it succeeds
    const passRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha],
      { encoding: 'utf8', env: { ...process.env, PR_BODY: 'Allow-Baseline-Init: #2451' } }
    );
    assert.equal(passRes.status, 0, passRes.stderr);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('CLI unions auto-discovered baseline/ignore files with --paths', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-union-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.writeFileSync(path.join(tmpRepo, '.trivyignore'), 'CVE-2024-0001\n');
    fs.mkdirSync(path.join(tmpRepo, 'waivers'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'waivers', 'custom.json'),
      JSON.stringify({ baseline: [{ file: 'a.cs', ruleId: 'R1', count: 1 }] })
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: initial baselines']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    // Grow .trivyignore while passing --paths waivers/custom.json (which is unchanged)
    fs.writeFileSync(path.join(tmpRepo, '.trivyignore'), 'CVE-2024-0001\nCVE-2025-9999\n');
    git(['add', '.']);
    git(['commit', '-m', 'chore: sneak trivyignore entry']);
    const headSha = git(['rev-parse', 'HEAD']).trim();

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha, '--paths', 'waivers/custom.json'],
      { encoding: 'utf8' }
    );
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /\.trivyignore/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('CLI blocks silent deletion of tracked baseline files and allows approved or non-existent paths', () => {
  // Case 1: Deleting one baseline while another remains
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-delete-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.mkdirSync(path.join(tmpRepo, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'config', 'ai-smells-baseline.json'),
      JSON.stringify({ ai_smells_baseline: [{ file: 'a.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'x', count: 1 }] })
    );
    fs.writeFileSync(path.join(tmpRepo, '.semgrepignore'), 'legacy/\n');
    git(['add', '.']);
    git(['commit', '-m', 'chore: initial baselines']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    assert.deepEqual(discoverBaseBaselineFiles(tmpRepo, baseSha), [
      '.semgrepignore',
      'config/ai-smells-baseline.json',
    ]);

    // Non-existent optional --paths file (neither in base nor head) succeeds cleanly
    const passMissingOptionalRes = spawnSync(
      process.execPath,
      [
        SCRIPT_PATH,
        '--repo-root',
        tmpRepo,
        '--base',
        baseSha,
        '--head',
        baseSha,
        '--paths',
        'config/optional-missing.json',
      ],
      { encoding: 'utf8' }
    );
    assert.equal(passMissingOptionalRes.status, 0, passMissingOptionalRes.stderr);
    assert.doesNotMatch(passMissingOptionalRes.stderr, /ENOENT/);

    // Delete tracked JSON baseline silently
    git(['rm', 'config/ai-smells-baseline.json']);
    git(['commit', '-m', 'chore: remove baseline silently']);
    const headSha = git(['rev-parse', 'HEAD']).trim();

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha],
      { encoding: 'utf8' }
    );
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /BASELINE_RATCHET/);
    assert.doesNotMatch(failRes.stderr, /ENOENT/);

    // Approved via PR_BODY succeeds cleanly
    const passPrRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha],
      { encoding: 'utf8', env: { ...process.env, PR_BODY: 'Allow-Baseline-Removal: all violations fixed (#123)' } }
    );
    assert.equal(passPrRes.status, 0, passPrRes.stderr);
    assert.doesNotMatch(passPrRes.stderr, /ENOENT/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }

  // Case 2: Deleting the sole tracked baseline file in the repository
  const soleRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-delete-sole-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: soleRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.mkdirSync(path.join(soleRepo, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(soleRepo, 'config', 'ai-smells-baseline.json'),
      JSON.stringify({ ai_smells_baseline: [{ file: 'a.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'x', count: 1 }] })
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: initial sole baseline']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    git(['rm', 'config/ai-smells-baseline.json']);
    git(['commit', '-m', 'chore: remove sole baseline silently']);
    const silentHeadSha = git(['rev-parse', 'HEAD']).trim();

    const failSoleRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', soleRepo, '--base', baseSha, '--head', silentHeadSha],
      { encoding: 'utf8' }
    );
    assert.notEqual(failSoleRes.status, 0);
    assert.match(failSoleRes.stderr, /BASELINE_RATCHET/);
    assert.doesNotMatch(failSoleRes.stderr, /ENOENT/);

    // Commit message approval also succeeds cleanly
    git(['commit', '--amend', '-m', 'chore: remove sole baseline\n\nAllow-Baseline-Removal: all violations fixed (#123)']);
    const approvedHeadSha = git(['rev-parse', 'HEAD']).trim();

    const passCommitRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', soleRepo, '--base', baseSha, '--head', approvedHeadSha],
      { encoding: 'utf8' }
    );
    assert.equal(passCommitRes.status, 0, passCommitRes.stderr);
    assert.doesNotMatch(passCommitRes.stderr, /ENOENT/);
  } finally {
    fs.rmSync(soleRepo, { recursive: true, force: true });
  }
});

test('CLI rejects baseline deletion when Allow-Baseline-Removal lacks a same-line reason', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-newline-bypass-test-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.mkdirSync(path.join(tmpRepo, 'config'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'config', 'ai-smells-baseline.json'),
      JSON.stringify({ ai_smells_baseline: [{ file: 'a.cs', ruleId: 'EMPTY_CATCH', fingerprint: 'x', count: 1 }] })
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: initial baseline']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    git(['rm', 'config/ai-smells-baseline.json']);
    git(['commit', '-m', 'chore: drop\n\nAllow-Baseline-Removal:\nSigned-off-by: Bot']);
    const commitBypassSha = git(['rev-parse', 'HEAD']).trim();

    // Case 1: Empty Allow-Baseline-Removal in multiline commit message must exit 1 with [BASELINE_RATCHET]
    const commitFailRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', commitBypassSha],
      { encoding: 'utf8' }
    );
    assert.equal(commitFailRes.status, 1);
    assert.match(commitFailRes.stderr, /\[BASELINE_RATCHET\]/);

    // Case 2: Empty Allow-Baseline-Removal in multiline PR_BODY must exit 1 with [BASELINE_RATCHET]
    git(['commit', '--amend', '-m', 'chore: drop baseline']);
    const prBypassSha = git(['rev-parse', 'HEAD']).trim();

    const prFailRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', prBypassSha],
      { encoding: 'utf8', env: { ...process.env, PR_BODY: 'Allow-Baseline-Removal:\n\n## Summary\nRoutine refactor' } }
    );
    assert.equal(prFailRes.status, 1);
    assert.match(prFailRes.stderr, /\[BASELINE_RATCHET\]/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

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
  hasBaselineInitApproval,
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
  assert.equal(hasBaselineInitApproval('chore: init', ''), false);
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

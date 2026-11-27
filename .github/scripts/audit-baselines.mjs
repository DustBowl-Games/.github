#!/usr/bin/env node
/**
 * DustBowl Games - Baseline & Ignore-File Ratchet Gate
 *
 * Prevents silent growth or entry-swapping in baseline/ignore files:
 * - JSON baselines (legacyAuditBaseline, workflow_hygiene_baseline, ai_smells_baseline,
 *   infra_safety_baseline, ci_integrity_baseline, entries, baseline)
 * - Line-based ignore files (.trivyignore, .gitleaksignore, .semgrepignore)
 * - Brand-new baseline/ignore files require Allow-Baseline-Init: #<issue> or URL
 *   in commit log or PR_BODY.
 * - Deleting tracked baseline/ignore files requires Allow-Baseline-Removal: <reason>
 *   in commit log or PR_BODY.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

const IGNORED_DIRS = new Set([
  '.git',
  '.org-ci',
  'node_modules',
  'bin',
  'obj',
  'artifacts',
  '.venv',
  'vendor',
  '__pycache__',
  '.agents',
]);

const BASELINE_JSON_KEYS = [
  'legacyAuditBaseline',
  'workflow_hygiene_baseline',
  'ai_smells_baseline',
  'infra_safety_baseline',
  'ci_integrity_baseline',
  'entries',
  'baseline',
];

const ALLOW_BASELINE_INIT_RE = /Allow-Baseline-Init:\s*(?:#\d+|https?:\/\/\S+)/i;
const ALLOW_BASELINE_REMOVAL_RE = /Allow-Baseline-Removal:\s*\S+/i;

export function normalizePath(p) {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function normalizeFingerprint(text) {
  return String(text || '').replace(/\s+/g, ' ').trim();
}

export function resolveRepoRoot(args = process.argv.slice(2), cwd = process.cwd(), env = process.env) {
  let explicitRoot = null;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--repo-root') {
      if (!args[i + 1] || args[i + 1].startsWith('--')) {
        throw new Error('--repo-root requires a directory path.');
      }
      explicitRoot = args[i + 1];
      break;
    }
    if (arg.startsWith('--repo-root=')) {
      explicitRoot = arg.slice('--repo-root='.length);
      if (!explicitRoot) {
        throw new Error('--repo-root= requires a non-empty directory path.');
      }
      break;
    }
  }
  return path.resolve(cwd, explicitRoot || env.GITHUB_WORKSPACE || cwd);
}

export function hasBaselineInitApproval(commitText = '', prBody = process.env.PR_BODY || '') {
  return ALLOW_BASELINE_INIT_RE.test(`${commitText}\n${prBody}`);
}

export function hasBaselineRemovalApproval(commitText = '', prBody = process.env.PR_BODY || '') {
  return ALLOW_BASELINE_REMOVAL_RE.test(`${commitText}\n${prBody}`);
}

function isBaselineCandidate(relPath) {
  const norm = normalizePath(relPath);
  const base = path.posix.basename(norm);
  if (base === '.trivyignore' || base === '.gitleaksignore' || base === '.semgrepignore') {
    return true;
  }
  if (/^config\/.*(?:allowlist|baseline).*\.json$/i.test(norm)) {
    return true;
  }
  if (/^\.github\/.*baseline.*\.json$/i.test(norm)) {
    return true;
  }
  return false;
}

export function discoverBaselineFiles(repoRoot) {
  const out = [];
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        walk(full);
      } else if (entry.isFile()) {
        const rel = normalizePath(path.relative(repoRoot, full));
        if (isBaselineCandidate(rel)) out.push(rel);
      }
    }
  }
  walk(repoRoot);
  return out.sort();
}

export function discoverBaseBaselineFiles(repoRoot, baseRev) {
  if (!baseRev || !String(baseRev).trim()) return [];
  let raw = '';
  try {
    raw = execFileSync('git', ['ls-tree', '-r', '--name-only', '-z', String(baseRev).trim()], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return [];
  }
  const out = [];
  for (const entry of raw.split('\0')) {
    if (!entry) continue;
    const norm = normalizePath(entry);
    const parts = norm.split('/');
    if (parts.slice(0, -1).some(part => IGNORED_DIRS.has(part))) continue;
    if (isBaselineCandidate(norm)) out.push(norm);
  }
  return out.sort();
}

function buildJsonCountMap(arr) {
  const map = new Map();
  let total = 0;
  for (const item of arr) {
    if (!item || typeof item !== 'object') {
      const k = JSON.stringify(item);
      map.set(k, (map.get(k) || 0) + 1);
      total += 1;
      continue;
    }
    const count = Number.isInteger(item.count) && item.count > 0 ? item.count : 1;
    const hasKeyFields = item.file !== undefined || item.ruleId !== undefined || item.fingerprint !== undefined;
    const key = hasKeyFields
      ? `${normalizePath(String(item.file || ''))}|${String(item.ruleId || '')}|${normalizeFingerprint(item.fingerprint || '')}`
      : JSON.stringify(item);
    map.set(key, (map.get(key) || 0) + count);
    total += count;
  }
  return { map, total };
}

export function compareJsonBaselines(baseRaw, headRaw, relFile) {
  const baseDoc = JSON.parse(baseRaw.replace(/^\uFEFF/, '') || '{}');
  const headDoc = JSON.parse(headRaw.replace(/^\uFEFF/, '') || '{}');
  const errors = [];

  if (Array.isArray(headDoc)) {
    const baseArr = Array.isArray(baseDoc) ? baseDoc : [];
    const { map: bMap, total: bTotal } = buildJsonCountMap(baseArr);
    const { map: hMap, total: hTotal } = buildJsonCountMap(headDoc);
    if (hTotal > bTotal) {
      errors.push(`${relFile}: baseline total grew from ${bTotal} to ${hTotal}`);
    }
    for (const [k, hCnt] of hMap.entries()) {
      const bCnt = bMap.get(k) || 0;
      if (hCnt > bCnt) {
        errors.push(`${relFile}: baseline entry grew or was swapped in (${k}: ${bCnt} -> ${hCnt})`);
      }
    }
    return errors;
  }

  for (const key of BASELINE_JSON_KEYS) {
    const headArr = Array.isArray(headDoc?.[key]) ? headDoc[key] : null;
    if (!headArr) continue;
    const baseArr = Array.isArray(baseDoc?.[key]) ? baseDoc[key] : [];
    const { map: bMap, total: bTotal } = buildJsonCountMap(baseArr);
    const { map: hMap, total: hTotal } = buildJsonCountMap(headArr);

    if (hTotal > bTotal) {
      errors.push(`${relFile} (${key}): baseline total grew from ${bTotal} to ${hTotal}`);
    }
    for (const [k, hCnt] of hMap.entries()) {
      const bCnt = bMap.get(k) || 0;
      if (hCnt > bCnt) {
        errors.push(`${relFile} (${key}): baseline entry grew or was swapped in (${k}: ${bCnt} -> ${hCnt})`);
      }
    }
  }

  return errors;
}

function parseIgnoreEntries(raw) {
  const counts = new Map();
  let total = 0;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    counts.set(trimmed, (counts.get(trimmed) || 0) + 1);
    total += 1;
  }
  return { counts, total };
}

export function compareIgnoreFiles(baseRaw, headRaw, relFile) {
  const { counts: bMap, total: bTotal } = parseIgnoreEntries(baseRaw);
  const { counts: hMap, total: hTotal } = parseIgnoreEntries(headRaw);
  const errors = [];

  if (hTotal > bTotal) {
    errors.push(`${relFile}: ignore entries grew from ${bTotal} to ${hTotal}`);
  }
  for (const [entry, hCnt] of hMap.entries()) {
    const bCnt = bMap.get(entry) || 0;
    if (hCnt > bCnt) {
      errors.push(`${relFile}: new or duplicated ignore entry "${entry}" (${bCnt} -> ${hCnt})`);
    }
  }
  return errors;
}

function resolveBaseHead(repoRoot, baseArg, headArg) {
  const baseSha = baseArg || process.env.GITHUB_BASE_SHA || '';
  const headSha = headArg || process.env.GITHUB_HEAD_SHA || '';
  if (baseSha && headSha) return { base: baseSha, head: headSha };

  const baseRef = process.env.GITHUB_BASE_REF || 'main';
  for (const candidate of [`origin/${baseRef}`, baseRef]) {
    try {
      const mergeBase = execFileSync('git', ['merge-base', candidate, 'HEAD'], {
        cwd: repoRoot,
        encoding: 'utf8',
      }).trim();
      if (mergeBase) return { base: mergeBase, head: 'HEAD' };
    } catch {
      // Try next candidate
    }
  }
  try {
    execFileSync('git', ['rev-parse', '--verify', 'HEAD~1'], { cwd: repoRoot, stdio: 'ignore' });
    return { base: 'HEAD~1', head: 'HEAD' };
  } catch {
    return null;
  }
}

function gitShowOrNull(repoRoot, rev, relFile) {
  try {
    return execFileSync('git', ['show', `${rev}:${relFile}`], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

function parseFlag(args, name) {
  const idx = args.indexOf(name);
  if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('--')) return args[idx + 1];
  const eq = args.find(a => a.startsWith(`${name}=`));
  return eq ? eq.slice(name.length + 1) : '';
}

function main() {
  const args = process.argv.slice(2);
  let repoRoot;
  try {
    repoRoot = resolveRepoRoot(args, process.cwd(), process.env);
  } catch (err) {
    console.error(`[FAIL] ${err.message}`);
    process.exit(1);
  }
  if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
    console.error(`[FAIL] Repository root does not exist: ${repoRoot}`);
    process.exit(1);
  }

  const baseArg = parseFlag(args, '--base');
  const headArg = parseFlag(args, '--head');
  const pathsArg = parseFlag(args, '--paths');

  const revs = resolveBaseHead(repoRoot, baseArg, headArg);
  if (!revs) {
    console.log('[INFO] No base revision available for baseline ratchet; skipping.');
    process.exit(0);
  }

  const discovered = discoverBaselineFiles(repoRoot);
  const baseDiscovered = discoverBaseBaselineFiles(repoRoot, revs.base);
  const explicit = pathsArg
    ? pathsArg.split(',').map(s => normalizePath(s.trim())).filter(Boolean)
    : [];
  const targets = [...new Set([...discovered, ...baseDiscovered, ...explicit])].sort();

  if (targets.length === 0) {
    console.log('[PASS] No baseline or ignore files to ratchet.');
    process.exit(0);
  }

  let commitText = '';
  try {
    commitText = execFileSync('git', ['log', `${revs.base}..${revs.head}`, '--pretty=format:%B'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
  } catch {
    commitText = '';
  }

  const approvedInit = hasBaselineInitApproval(commitText);
  const approvedRemoval = hasBaselineRemovalApproval(commitText);
  const violations = [];

  for (const rel of targets) {
    const absPath = path.join(repoRoot, rel);
    const baseRaw = gitShowOrNull(repoRoot, revs.base, rel);
    if (!fs.existsSync(absPath)) {
      if (baseRaw !== null && !approvedRemoval) {
        violations.push(
          `${rel}: baseline/ignore file deleted without "Allow-Baseline-Removal: <reason>" in commit log or PR body.`
        );
      }
      continue;
    }

    const headRaw = fs.readFileSync(absPath, 'utf8');

    if (baseRaw === null) {
      if (!approvedInit) {
        violations.push(
          `${rel}: brand-new baseline/ignore file introduced without "Allow-Baseline-Init: #<issue>" in commit log or PR body.`
        );
      }
      continue;
    }

    if (rel.toLowerCase().endsWith('.json')) {
      violations.push(...compareJsonBaselines(baseRaw, headRaw, rel));
    } else {
      violations.push(...compareIgnoreFiles(baseRaw, headRaw, rel));
    }
  }

  console.log(`[SUMMARY] Baseline ratchet checked ${targets.length} file(s): violations=${violations.length}`);

  if (violations.length > 0) {
    for (const err of violations) {
      console.error(`::error::[BASELINE_RATCHET] ${err}`);
    }
    process.exit(1);
  }

  console.log('[PASS] All baseline and ignore files obeyed the ratchet.');
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}

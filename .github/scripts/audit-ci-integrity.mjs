#!/usr/bin/env node
/**
 * DustBowl Games - CI Integrity & Anti-Bypass Gate
 *
 * Blocks attempts to weaken or bypass CI quality and security checks:
 * - Newly added [Fact(Skip=...)] / [Theory(Skip=...)] (single or multi-line)
 * - Newly added continue-on-error: true in .github/workflows/*.yml
 * - Exit-code masking (|| true, || :, || exit 0, || echo ...::warning::) in workflows & .sh
 * - Newly added suppression directives (#pragma warning disable, [SuppressMessage],
 *   nosemgrep, eslint-disable, @ts-ignore/@ts-nocheck, # noqa, # nosec) unless baselined
 * - Weakening or removing <TreatWarningsAsErrors>true</TreatWarningsAsErrors> in .csproj / Directory.Build.*
 * - Deleting test files without Allow-Test-Removal: <reason>
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

const WORKFLOW_RE = /^\.github\/workflows\/.+\.ya?ml$/i;
const SHELL_RE = /\.sh$/i;
const CS_RE = /\.cs$/i;
const CSPROJ_OR_BUILD_RE = /(?:^|\/)(?:[^/]+\.csproj|Directory\.Build\.(?:props|targets))$/i;
const TEST_FILE_RE = /(?:Tests?\.cs|\.test\.(?:mjs|js|ts)|(?:^|\/)test_[^/]+\.py)$/i;
const TEST_FIXTURE_EXEMPT_RE = /^(?:.*\/)?(?:tests\/(?:ci\/)?.*\.(?:test\.(?:mjs|js|ts)|py)|scripts\/test_[^/]+\.py)$/i;
const SELF_SCRIPT_EXEMPT_RE = /(?:^|\/)\.github\/scripts\/audit-ci-integrity\.mjs$/i;

const SINGLE_LINE_SKIP_RE = /\[(?:Skippable)?(?:Fact|Theory)\s*\([^)]*\bSkip\s*=/i;
const MULTILINE_ATTR_START_RE = /\[(?:Skippable)?(?:Fact|Theory)\s*\(/i;
const SKIP_ARG_RE = /\bSkip\s*=/i;
const CONTINUE_ON_ERROR_RE = /^\s*(?:-\s*)?continue-on-error\s*:\s*true(?:\s|$|#)/i;
const EXIT_MASK_RE = /\|\|\s*(?:(?:true|exit\s+0)\b|:(?:\s|$|;|&&))|\|\|\s*echo\b[^\n]*::warning::/i;

const TREAT_WARN_TRUE_RE = /<TreatWarningsAsErrors>\s*true\s*<\/TreatWarningsAsErrors>/i;
const TREAT_WARN_FALSE_RE = /<TreatWarningsAsErrors>\s*false\s*<\/TreatWarningsAsErrors>/i;
const ALLOW_TEST_REMOVAL_RE = /Allow-Test-Removal:\s*\S+/i;

const SUPPRESSION_RULES = [
  {
    exts: /\.(?:cs|razor)$/i,
    patterns: [
      /#pragma\s+warning\s+disable\b/i,
      /\[\s*(?:System\.Diagnostics\.CodeAnalysis\.)?SuppressMessage\b/i,
    ],
  },
  {
    exts: /\.(?:cs|razor|js|mjs|ts|tsx|jsx|py|sh|ya?ml)$/i,
    patterns: [/(?:\/\/|#)\s*nosemgrep\b/i],
  },
  {
    exts: /\.(?:js|mjs|ts|tsx|jsx)$/i,
    patterns: [
      /(?:\/\/|\/\*)\s*eslint-disable(?:-next-line|-line)?\b/i,
      /\/\/\s*@ts-(?:ignore|nocheck)\b/,
    ],
  },
  {
    exts: /\.py$/i,
    patterns: [/#\s*noqa\b/i, /#\s*nosec\b/i],
  },
];

export function normalizePath(p) {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function normalizeFingerprint(text) {
  return text.replace(/\s+/g, ' ').trim();
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

function isIgnoredRel(relPath) {
  const parts = normalizePath(relPath).split('/');
  return parts.slice(0, -1).some(part => IGNORED_DIRS.has(part));
}

function checkAddedLineRules(relFile, lineNum, text, state, findings) {
  const trimmed = text.trim();

  if (CS_RE.test(relFile)) {
    if (SINGLE_LINE_SKIP_RE.test(text)) {
      findings.push({
        file: relFile,
        line: lineNum,
        ruleId: 'SKIPPED_TEST',
        fingerprint: normalizeFingerprint(text),
        message: 'Skipped unit test attribute ([Fact(Skip=...)] / [Theory(Skip=...)]) is forbidden.',
      });
      state.inTestAttr = false;
    } else if (MULTILINE_ATTR_START_RE.test(text) && !text.includes(')]')) {
      state.inTestAttr = true;
      if (SKIP_ARG_RE.test(text)) {
        findings.push({
          file: relFile,
          line: lineNum,
          ruleId: 'SKIPPED_TEST',
          fingerprint: normalizeFingerprint(text),
          message: 'Skipped unit test attribute (Skip=) is forbidden.',
        });
        state.inTestAttr = false;
      }
    } else if (state.inTestAttr) {
      if (SKIP_ARG_RE.test(text)) {
        findings.push({
          file: relFile,
          line: lineNum,
          ruleId: 'SKIPPED_TEST',
          fingerprint: normalizeFingerprint(text),
          message: 'Skipped unit test attribute (Skip=) is forbidden.',
        });
        state.inTestAttr = false;
      } else if (text.includes(')') || text.includes(']')) {
        state.inTestAttr = false;
      }
    }
  }

  if (WORKFLOW_RE.test(relFile) && !trimmed.startsWith('#')) {
    if (CONTINUE_ON_ERROR_RE.test(text)) {
      findings.push({
        file: relFile,
        line: lineNum,
        ruleId: 'CONTINUE_ON_ERROR',
        fingerprint: normalizeFingerprint(text),
        message: 'continue-on-error: true is forbidden in GitHub Actions workflows.',
      });
    }
  }

  if ((WORKFLOW_RE.test(relFile) || SHELL_RE.test(relFile)) && !trimmed.startsWith('#')) {
    const codePart = text.replace(/\s+#.*$/, '');
    if (EXIT_MASK_RE.test(codePart)) {
      findings.push({
        file: relFile,
        line: lineNum,
        ruleId: 'EXIT_CODE_MASKING',
        fingerprint: normalizeFingerprint(text),
        message: 'Exit-code masking (|| true, || :, || exit 0, || echo ::warning::) is forbidden.',
      });
    }
  }

  if (!TEST_FIXTURE_EXEMPT_RE.test(relFile) && !SELF_SCRIPT_EXEMPT_RE.test(relFile)) {
    for (const rule of SUPPRESSION_RULES) {
      if (!rule.exts.test(relFile)) continue;
      if (rule.patterns.some(pat => pat.test(text))) {
        findings.push({
          file: relFile,
          line: lineNum,
          ruleId: 'NEW_SUPPRESSION_DIRECTIVE',
          fingerprint: normalizeFingerprint(text),
          message: 'New analyzer/linter suppression directive added without baseline approval.',
        });
        break;
      }
    }
  }
}

export function loadBaselineEntries(baselinePath) {
  if (!baselinePath) return [];
  if (!fs.existsSync(baselinePath)) {
    throw new Error(`Baseline file not found: ${baselinePath}`);
  }
  const raw = fs.readFileSync(baselinePath, 'utf8').replace(/^\uFEFF/, '').trim();
  if (!raw) return [];
  const data = JSON.parse(raw);
  if (Array.isArray(data)) return data;
  for (const key of ['ci_integrity_baseline', 'entries', 'legacyAuditBaseline', 'baseline']) {
    if (Array.isArray(data[key])) return data[key];
  }
  throw new Error(`Unsupported baseline schema in ${baselinePath}`);
}

export function applyBaseline(findings, baselineEntries = [], { strict = false } = {}) {
  if (strict || !baselineEntries.length) {
    return { baselined: [], unapproved: [...findings] };
  }
  const exactCounts = new Map();
  const ruleCounts = new Map();

  for (const entry of baselineEntries) {
    const file = normalizePath(String(entry.file || ''));
    const ruleId = String(entry.ruleId || '');
    const count = Number.isInteger(entry.count) && entry.count > 0 ? entry.count : 1;
    if (entry.fingerprint) {
      const k = `${file}|${ruleId}|${normalizeFingerprint(String(entry.fingerprint))}`;
      exactCounts.set(k, (exactCounts.get(k) || 0) + count);
    } else {
      const k = `${file}|${ruleId}`;
      ruleCounts.set(k, (ruleCounts.get(k) || 0) + count);
    }
  }

  const baselined = [];
  const unapproved = [];
  for (const f of findings) {
    const ek = `${f.file}|${f.ruleId}|${f.fingerprint}`;
    const rk = `${f.file}|${f.ruleId}`;
    if ((exactCounts.get(ek) || 0) > 0) {
      exactCounts.set(ek, exactCounts.get(ek) - 1);
      baselined.push(f);
    } else if ((ruleCounts.get(rk) || 0) > 0) {
      ruleCounts.set(rk, ruleCounts.get(rk) - 1);
      baselined.push(f);
    } else {
      unapproved.push(f);
    }
  }
  return { baselined, unapproved };
}

export function auditDiffLines(diffText, deletedFiles = [], commitText = '', options = {}) {
  const prBody = options.prBody ?? process.env.PR_BODY ?? '';
  const findings = [];
  const treatWarningsTracker = new Map();
  let currentFile = null;
  let currentLine = 0;
  const lineState = { inTestAttr: false };

  for (const raw of diffText.split(/\r?\n/)) {
    if (raw.startsWith('+++ ')) {
      const target = raw.slice(4).trim();
      currentFile = target === '/dev/null' ? null : normalizePath(target.replace(/^b\//, ''));
      lineState.inTestAttr = false;
      continue;
    }
    if (raw.startsWith('--- ')) {
      lineState.inTestAttr = false;
      continue;
    }
    if (raw.startsWith('@@ ')) {
      const m = raw.match(/\+(\d+)/);
      currentLine = m ? Number.parseInt(m[1], 10) : 1;
      lineState.inTestAttr = false;
      continue;
    }
    if (!currentFile || isIgnoredRel(currentFile)) continue;

    if (raw.startsWith('-') && !raw.startsWith('---')) {
      const text = raw.slice(1);
      if (CSPROJ_OR_BUILD_RE.test(currentFile) && TREAT_WARN_TRUE_RE.test(text)) {
        const rec = treatWarningsTracker.get(currentFile) || { removedTrue: 0, addedTrue: 0, line: currentLine || 1 };
        rec.removedTrue += 1;
        treatWarningsTracker.set(currentFile, rec);
      }
      continue;
    }

    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      const text = raw.slice(1);
      checkAddedLineRules(currentFile, currentLine, text, lineState, findings);

      if (CSPROJ_OR_BUILD_RE.test(currentFile)) {
        if (TREAT_WARN_FALSE_RE.test(text)) {
          findings.push({
            file: currentFile,
            line: currentLine,
            ruleId: 'TREAT_WARNINGS_AS_ERRORS_WEAKENED',
            fingerprint: normalizeFingerprint(text),
            message: 'Setting <TreatWarningsAsErrors>false</TreatWarningsAsErrors> is forbidden.',
          });
        }
        if (TREAT_WARN_TRUE_RE.test(text)) {
          const rec = treatWarningsTracker.get(currentFile) || { removedTrue: 0, addedTrue: 0, line: currentLine };
          rec.addedTrue += 1;
          treatWarningsTracker.set(currentFile, rec);
        }
      }

      currentLine += 1;
    } else if (raw.startsWith(' ')) {
      currentLine += 1;
      lineState.inTestAttr = false;
    }
  }

  for (const [file, rec] of treatWarningsTracker.entries()) {
    if (rec.removedTrue > rec.addedTrue) {
      findings.push({
        file,
        line: rec.line,
        ruleId: 'TREAT_WARNINGS_AS_ERRORS_WEAKENED',
        fingerprint: '<TreatWarningsAsErrors>true</TreatWarningsAsErrors> removed',
        message: 'Removing <TreatWarningsAsErrors>true</TreatWarningsAsErrors> is forbidden.',
      });
    }
  }

  const approvalText = `${commitText}\n${prBody}`;
  const hasApproval = ALLOW_TEST_REMOVAL_RE.test(approvalText);
  for (const del of deletedFiles) {
    const normDel = normalizePath(del);
    if (!normDel || isIgnoredRel(normDel)) continue;
    if (TEST_FILE_RE.test(normDel) && !hasApproval) {
      findings.push({
        file: normDel,
        line: 1,
        ruleId: 'UNAPPROVED_TEST_DELETION',
        fingerprint: `deleted:${normDel}`,
        message: 'Test file deleted without "Allow-Test-Removal: <reason>" in commit message or PR body.',
      });
    }
  }

  return findings;
}

function walkFiles(dir, repoRoot, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      walkFiles(full, repoRoot, out);
    } else if (entry.isFile()) {
      const rel = normalizePath(path.relative(repoRoot, full));
      if (!isIgnoredRel(rel)) out.push({ full, rel });
    }
  }
  return out;
}

export function auditRepoFiles(repoRoot) {
  const findings = [];
  for (const { full, rel } of walkFiles(repoRoot, repoRoot)) {
    const content = fs.readFileSync(full, 'utf8');
    const lines = content.split(/\r?\n/);
    const state = { inTestAttr: false };
    for (let i = 0; i < lines.length; i++) {
      checkAddedLineRules(rel, i + 1, lines[i], state, findings);
    }
  }
  return findings;
}

function resolveGitRange(repoRoot, baseArg, headArg) {
  const baseSha = baseArg || process.env.GITHUB_BASE_SHA || '';
  const headSha = headArg || process.env.GITHUB_HEAD_SHA || '';
  if (baseSha && headSha) return `${baseSha}..${headSha}`;

  const baseRef = process.env.GITHUB_BASE_REF || 'main';
  for (const candidate of [`origin/${baseRef}`, baseRef]) {
    try {
      execFileSync('git', ['rev-parse', '--verify', candidate], { cwd: repoRoot, stdio: 'ignore' });
      return `${candidate}...HEAD`;
    } catch {
      // Try next ref
    }
  }
  try {
    execFileSync('git', ['rev-parse', '--verify', 'HEAD~1'], { cwd: repoRoot, stdio: 'ignore' });
    return 'HEAD~1..HEAD';
  } catch {
    return null;
  }
}

function getGitDiffAndMeta(repoRoot, baseArg, headArg) {
  const range = resolveGitRange(repoRoot, baseArg, headArg);
  if (!range) {
    return { diffText: '', deletedFiles: [], commitText: '' };
  }
  const diffRange = range.includes('...') ? range : range.replace('..', '...');
  const diffText = execFileSync('git', ['diff', '-U0', diffRange], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 25 * 1024 * 1024,
  });
  const delOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=D', diffRange], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  const logRange = range.replace('...', '..');
  let commitText = '';
  try {
    commitText = execFileSync('git', ['log', logRange, '--pretty=format:%B'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });
  } catch {
    commitText = '';
  }
  return {
    diffText,
    deletedFiles: delOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean),
    commitText,
  };
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

  const scanAll = args.includes('--all');
  const strict = args.includes('--strict');
  const baseArg = parseFlag(args, '--base');
  const headArg = parseFlag(args, '--head');
  const baselineArg = parseFlag(args, '--baseline');

  let baselineEntries = [];
  if (baselineArg) {
    const resolvedBaseline = path.isAbsolute(baselineArg) ? baselineArg : path.resolve(repoRoot, baselineArg);
    try {
      baselineEntries = loadBaselineEntries(resolvedBaseline);
    } catch (err) {
      console.error(`[FAIL] ${err.message}`);
      process.exit(1);
    }
  }

  let findings;
  if (scanAll) {
    findings = auditRepoFiles(repoRoot);
  } else {
    const { diffText, deletedFiles, commitText } = getGitDiffAndMeta(repoRoot, baseArg, headArg);
    findings = auditDiffLines(diffText, deletedFiles, commitText);
  }

  const { baselined, unapproved } = applyBaseline(findings, baselineEntries, { strict });
  console.log(
    `[SUMMARY] CI Integrity scan (${scanAll ? 'full' : 'diff'}): ` +
    `baselined=${baselined.length} | unapproved=${unapproved.length}`
  );

  if (unapproved.length > 0) {
    for (const v of unapproved) {
      console.error(`::error file=${v.file},line=${v.line}::[${v.ruleId}] ${v.message}`);
    }
    process.exit(1);
  }

  console.log('[PASS] No CI integrity bypasses or unapproved suppressions detected.');
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}

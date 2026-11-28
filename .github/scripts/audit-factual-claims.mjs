#!/usr/bin/env node
/**
 * DustBowl Games - Factual Claims & No-Fake-Promises CI Gate
 *
 * Scans public-facing Razor pages, shared components, email templates, and KB
 * seeders to block unapproved SLA percentages, response-time promises, 24/7
 * claims, hardcoded fiber/ms latency numbers, refund/uptime guarantees, and
 * compliance/certification badges unless explicitly backed by an allowlist.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
  const candidate = explicitRoot || env.GITHUB_WORKSPACE || cwd;
  return path.resolve(cwd, candidate);
}

export const REPO_ROOT = resolveRepoRoot([], process.cwd(), process.env);
export const DEFAULT_ALLOWLIST_PATH = path.join(REPO_ROOT, 'config', 'verified-claims-allowlist.json');

export const RULES = [
  {
    ruleId: 'UNAPPROVED_SLA_PERCENT',
    remediation: 'Remove unverified SLA/uptime percentage claims or document and allowlist a verified policy fact.',
    patterns: [
      /\b9\d(?:\.\d+)?%\s*(?:monthly\s+)?(?:honest\s+)?(?:uptime|availability|SLA)\b/i,
      /\bSLA\b[^\n]{0,40}\b9\d(?:\.\d+)?%/i,
      /\buptime\s+guarantee\b/i,
      /\b(?:95|98|99(?:\.9+)?)\s*%\s*(?:by\s+design|commitment|guarantee)\b/i,
    ],
  },
  {
    ruleId: 'UNAPPROVED_RESPONSE_SLA',
    remediation: 'Do not promise unbacked response times (same-day, within X hours, <2h, 24h/48h SLA, priority dispatch).',
    patterns: [
      /\bsame[- ]business[- ]day\b/i,
      /\bsame[- ]day\s+(?:response|reply|dispatch|support|turnaround)\b/i,
      /\bwithin\s+\d+\s*(?:minutes?|mins?|hours?|hrs?|business\s+(?:hours?|days?))\b/i,
      /(?:<|&lt;|under|sub-?)\s*\d+\s*(?:min|minute|hour|hr)s?\s*(?:technical\s+)?(?:response|reply|SLA)\b/i,
      /\b(?:\d+[hH]|48-hour|24-hour)\s*(?:response|review|appeal|intake)?\s*SLA\b/i,
      /\b(?:response|review|appeal)\s+SLA\b/i,
      /\bpriority\s+ticket\s+dispatch\b/i,
    ],
  },
  {
    ruleId: 'UNAPPROVED_24_7_CLAIM',
    remediation: 'Remove unverified 24/7 support or uptime claims; only explicit anti-fake disclaimers may be allowlisted.',
    patterns: [
      /\b24\s*[/x\u00d7]\s*7\b/i,
    ],
  },
  {
    ruleId: 'UNAPPROVED_FIBER_OR_LATENCY_CLAIM',
    remediation: 'Remove hardcoded fiber transit or millisecond latency claims unless backed by live telemetry or allowlisted.',
    patterns: [
      /\b\d+\s*(?:-|\u2013|\u2014|&ndash;|&mdash;)\s*\d+\s*ms\b/i,
      /\bsub-\d+\s*ms\b/i,
      /(?:<|&lt;|under)\s*\d+\s*ms\b/i,
      /\b(?:direct|carrier|local|regional|dedicated|hickory)\s+(?:carrier\s+|regional\s+)?fiber\b/i,
      /\b\d+\s*(?:Gbps|Tbps)\b/i,
    ],
  },
  {
    ruleId: 'UNAPPROVED_GUARANTEE_OR_REFUND_CLAIM',
    remediation: 'Remove unverified refund/money-back/zero-downtime guarantees or align with verified policy.',
    patterns: [
      /\b(?:48-hour|72-hour|7-day|30-day)\s+(?:full\s+|risk-free\s+)?(?:refunds?|money-back|trials?|guarantees?|deployment\s+guarantees?)\b/i,
      /\bmoney-back\s+guarantees?\b/i,
      /\bzero\s+downtime\b/i,
      /\b48h\s+(?:100%|full)\b/i,
    ],
  },
  {
    ruleId: 'UNAPPROVED_CERTIFICATION_CLAIM',
    remediation: 'Do not claim formal compliance or certification standards (SOC 2, ISO 27001, HIPAA, PCI-DSS, Tier 3/4, NIST 800-88, Fortune 500) without verification.',
    patterns: [
      /\bSOC\s*2\b/i,
      /\bISO\s*27001\b/i,
      /\bHIPAA\b/i,
      /\bPCI[- ]DSS\b/i,
      /\bTier\s*(?:[34]|III|IV)\b/i,
      /\bNIST\s*800-88\b/i,
      /\bFortune\s*500\b/i,
    ],
  },
];

export function normalizePath(p) {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

export function isTargetFile(relPath) {
  const norm = normalizePath(relPath);
  if (norm.startsWith('Components/Pages/Admin/') || norm.startsWith('Components/Pages/Management/')) {
    return false;
  }
  if (norm.startsWith('Components/Pages/') && norm.endsWith('.razor')) return true;
  if (norm.startsWith('Components/Shared/') && norm.endsWith('.razor')) return true;
  if (/^Services\/EmailTemplateService.*\.cs$/.test(norm)) return true;
  if (/^Services\/SeedArticles.*\.cs$/.test(norm)) return true;
  if (/^docs\/emails\/.+\.(?:md|html)$/.test(norm)) return true;
  return false;
}

function stripHtmlAttributes(line) {
  return line
    .replace(/\b(?:class|href|src|d|viewBox|fill|stroke|stroke-width|aria-hidden|data-[a-zA-Z0-9_-]+)=["'][^"']*["']/gi, ' ')
    .replace(/\b(?:class|href|src|d|viewBox)=@\w+/gi, ' ');
}

function extractCSharpLineLiterals(rawLine, rawState) {
  const literals = [];
  if (rawState.inRaw) {
    const closeRe = new RegExp(`"{${rawState.quoteLen},}`);
    const m = rawLine.match(closeRe);
    if (!m) {
      const t = rawLine.trim();
      if (t) literals.push(t);
      return literals;
    }
    const beforeClose = rawLine.slice(0, m.index).trim();
    if (beforeClose) literals.push(beforeClose);
    rawState.inRaw = false;
    rawState.quoteLen = 0;
    const rest = rawLine.slice(m.index + m[0].length);
    if (rest) {
      literals.push(...extractCSharpLineLiterals(rest, rawState));
    }
    return literals;
  }

  let i = 0;
  const n = rawLine.length;
  while (i < n) {
    const ch = rawLine[i];
    if (ch === '/' && rawLine[i + 1] === '/') {
      break;
    }
    if (ch === '"') {
      let qCount = 0;
      while (i + qCount < n && rawLine[i + qCount] === '"') {
        qCount++;
      }
      if (qCount >= 3) {
        const afterOpen = rawLine.slice(i + qCount);
        const closeRe = new RegExp(`"{${qCount},}`);
        const closeMatch = afterOpen.match(closeRe);
        if (closeMatch) {
          const inner = afterOpen.slice(0, closeMatch.index).trim();
          if (inner) literals.push(inner);
          i = i + qCount + closeMatch.index + closeMatch[0].length;
          continue;
        }
        const tail = afterOpen.trim();
        if (tail) literals.push(tail);
        rawState.inRaw = true;
        rawState.quoteLen = qCount;
        break;
      }
      if (qCount === 2) {
        i += 2;
        continue;
      }
      let j = i + 1;
      while (j < n) {
        if (rawLine[j] === '\\') {
          j += 2;
          continue;
        }
        if (rawLine[j] === '"') {
          literals.push(rawLine.slice(i + 1, j));
          j++;
          break;
        }
        j++;
      }
      i = j;
      continue;
    }
    i++;
  }
  return literals;
}

function extractAuditableSegments(content, relPath) {
  const isRazor = relPath.endsWith('.razor');
  const isCsharp = relPath.endsWith('.cs');

  // Remove Razor comments (@* ... *@) and HTML comments (<!-- ... -->) preserving line count
  let cleaned = content.replace(/@\*[\s\S]*?\*@/g, m => m.replace(/[^\n]/g, ' '));
  cleaned = cleaned.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '));

  const lines = cleaned.split(/\r?\n/);
  const segments = [];
  let inCodeBlock = false;
  let codeBraceDepth = 0;
  const rawState = { inRaw: false, quoteLen: 0 };

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    const lineNum = i + 1;

    if (!trimmed) continue;
    if (!rawState.inRaw && trimmed.startsWith('//')) continue;

    if (isRazor) {
      if (!inCodeBlock && /@code\s*\{/.test(trimmed)) {
        inCodeBlock = true;
        codeBraceDepth = 0;
        for (const ch of rawLine) {
          if (ch === '{') codeBraceDepth++;
          else if (ch === '}') codeBraceDepth--;
        }
        if (codeBraceDepth <= 0) inCodeBlock = false;
        continue;
      }

      if (inCodeBlock) {
        if (!rawState.inRaw) {
          for (const ch of rawLine) {
            if (ch === '{') codeBraceDepth++;
            else if (ch === '}') codeBraceDepth--;
          }
        }
        const literals = extractCSharpLineLiterals(rawLine, rawState);
        if (literals.length > 0) {
          segments.push({ line: lineNum, text: literals.join(' '), rawLine: trimmed });
        }
        if (!rawState.inRaw && codeBraceDepth <= 0) inCodeBlock = false;
        continue;
      }

      const stripped = stripHtmlAttributes(rawLine).trim();
      if (stripped) {
        segments.push({ line: lineNum, text: stripped, rawLine: trimmed });
      }
      continue;
    }

    if (isCsharp) {
      const literals = extractCSharpLineLiterals(rawLine, rawState);
      if (literals.length > 0) {
        segments.push({ line: lineNum, text: literals.join(' '), rawLine: trimmed });
      }
      continue;
    }

    segments.push({ line: lineNum, text: stripHtmlAttributes(rawLine).trim(), rawLine: trimmed });
  }

  return segments;
}

export function normalizeFingerprint(text) {
  return text.replace(/\s+/g, ' ').trim();
}

export function auditText(content, filePath) {
  const normFile = normalizePath(filePath);
  const segments = extractAuditableSegments(content, normFile);
  const findings = [];

  for (const seg of segments) {
    for (const rule of RULES) {
      let matchedText = null;
      for (const pat of rule.patterns) {
        const m = seg.text.match(pat);
        if (m) {
          matchedText = m[0];
          break;
        }
      }
      if (matchedText) {
        findings.push({
          file: normFile,
          line: seg.line,
          ruleId: rule.ruleId,
          match: matchedText,
          fingerprint: normalizeFingerprint(seg.text).slice(0, 180).trim(),
          contextLine: normalizeFingerprint(seg.rawLine),
          remediation: rule.remediation,
        });
      }
    }
  }

  return findings;
}

export function validateAllowlist(allowlist) {
  const errors = [];
  if (!allowlist || typeof allowlist !== 'object') {
    return ['Allowlist JSON must be an object.'];
  }
  if (allowlist.schemaVersion !== 1) {
    errors.push(`Unsupported schemaVersion '${allowlist.schemaVersion}'; expected 1.`);
  }
  if (!Array.isArray(allowlist.verifiedFacts)) {
    errors.push('Allowlist must contain a "verifiedFacts" array.');
  } else {
    allowlist.verifiedFacts.forEach((entry, idx) => {
      for (const field of ['id', 'file', 'ruleId', 'match', 'verifiedBy', 'reason']) {
        if (typeof entry?.[field] !== 'string' || !entry[field].trim()) {
          errors.push(`verifiedFacts[${idx}] is missing required non-empty string field "${field}".`);
        }
      }
    });
  }
  if (!Array.isArray(allowlist.legacyAuditBaseline)) {
    errors.push('Allowlist must contain a "legacyAuditBaseline" array.');
  } else {
    allowlist.legacyAuditBaseline.forEach((entry, idx) => {
      for (const field of ['file', 'ruleId', 'fingerprint', 'status']) {
        if (typeof entry?.[field] !== 'string' || !entry[field].trim()) {
          errors.push(`legacyAuditBaseline[${idx}] is missing required non-empty string field "${field}".`);
        }
      }
      if (entry.count !== undefined && (!Number.isInteger(entry.count) || entry.count < 0)) {
        errors.push(`legacyAuditBaseline[${idx}].count must be a non-negative integer.`);
      }
    });
  }
  return errors;
}

export function evaluateFindings(findings, allowlist, { strict = false } = {}) {
  const verifiedMatches = [];
  const legacyMatches = [];
  const unapproved = [];

  const legacyRemaining = new Map();
  for (const entry of allowlist.legacyAuditBaseline || []) {
    let count;
    if (entry.count === undefined) {
      count = 1;
    } else if (Number.isInteger(entry.count) && entry.count >= 0) {
      count = entry.count;
    } else {
      throw new Error(`Invalid legacyAuditBaseline entry count: ${JSON.stringify(entry.count)} (must be a non-negative integer)`);
    }
    const key = `${normalizePath(entry.file)}|${entry.ruleId}|${normalizeFingerprint(entry.fingerprint)}`;
    legacyRemaining.set(key, (legacyRemaining.get(key) || 0) + count);
  }

  for (const f of findings) {
    const verified = (allowlist.verifiedFacts || []).find(
      v =>
        normalizePath(v.file) === f.file &&
        v.ruleId === f.ruleId &&
        (f.contextLine.toLowerCase().includes(v.match.toLowerCase()) ||
          f.fingerprint.toLowerCase().includes(v.match.toLowerCase()))
    );
    if (verified) {
      verifiedMatches.push({ ...f, verifiedId: verified.id });
      continue;
    }

    if (!strict) {
      const key = `${f.file}|${f.ruleId}|${f.fingerprint}`;
      const remaining = legacyRemaining.get(key) || 0;
      if (remaining > 0) {
        legacyRemaining.set(key, remaining - 1);
        legacyMatches.push(f);
        continue;
      }
    }

    unapproved.push(f);
  }

  return { verifiedMatches, legacyMatches, unapproved };
}

function walkDir(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['bin', 'obj', 'node_modules', '.git', 'artifacts'].includes(entry.name)) continue;
      walkDir(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

export function collectTargetFiles(repoRoot = REPO_ROOT) {
  const candidates = [
    ...walkDir(path.join(repoRoot, 'Components', 'Pages')),
    ...walkDir(path.join(repoRoot, 'Components', 'Shared')),
    ...walkDir(path.join(repoRoot, 'Services')),
    ...walkDir(path.join(repoRoot, 'docs', 'emails')),
  ];
  return candidates
    .map(full => ({ full, rel: normalizePath(path.relative(repoRoot, full)) }))
    .filter(({ rel }) => isTargetFile(rel))
    .sort((a, b) => a.rel.localeCompare(b.rel));
}

function readHeadFileContent(repoRoot, headRef, relFile) {
  if (repoRoot && headRef) {
    try {
      return execFileSync('git', ['show', `${headRef}:${normalizePath(relFile)}`], {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 20 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      // Fallback to working tree file if git show is unavailable
    }
  }
  const abs = path.join(repoRoot, relFile);
  if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
    return fs.readFileSync(abs, 'utf8');
  }
  return null;
}

function getDiffAddedLines(repoRoot = REPO_ROOT, baseArg = '', headArg = '') {
  const baseSha = baseArg || process.env.GITHUB_BASE_SHA || '';
  const headSha = headArg || process.env.GITHUB_HEAD_SHA || '';
  const baseRef = process.env.GITHUB_BASE_REF || 'staging';

  if ((baseSha && !headSha) || (!baseSha && headSha)) {
    throw new Error('Both GITHUB_BASE_SHA and GITHUB_HEAD_SHA (or --base and --head) must be set together.');
  }

  let diffRange = null;
  let explicitShas = false;
  let headRef = 'HEAD';
  if (baseSha && headSha) {
    explicitShas = true;
    diffRange = `${baseSha}...${headSha}`;
    headRef = headSha;
  } else {
    try {
      execFileSync('git', ['rev-parse', '--verify', `origin/${baseRef}`], { cwd: repoRoot, stdio: 'ignore' });
      diffRange = `origin/${baseRef}...HEAD`;
    } catch {
      try {
        execFileSync('git', ['rev-parse', '--verify', 'HEAD~1'], { cwd: repoRoot, stdio: 'ignore' });
        diffRange = 'HEAD~1..HEAD';
      } catch {
        try {
          execFileSync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: repoRoot, stdio: 'ignore' });
          diffRange = '4b825dc642cb6eb9a060e54bf8d69288fbee4904..HEAD';
        } catch {
          return [];
        }
      }
    }
  }

  let diffOut = '';
  try {
    diffOut = execFileSync('git', ['diff', '-U0', diffRange], {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });
  } catch (err) {
    if (explicitShas) {
      throw new Error(`git diff failed for explicit revisions '${diffRange}': ${err.message}`);
    }
    return [];
  }

  const perFile = new Map();
  let currentFile = null;
  let currentLine = 0;

  for (const raw of diffOut.split(/\r?\n/)) {
    if (raw.startsWith('+++ b/')) {
      currentFile = normalizePath(raw.slice(6).trim());
      continue;
    }
    if (raw.startsWith('@@ ')) {
      const m = raw.match(/\+(\d+)/);
      currentLine = m ? Number.parseInt(m[1], 10) : 1;
      continue;
    }
    if (!currentFile || !isTargetFile(currentFile)) continue;
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      if (!perFile.has(currentFile)) perFile.set(currentFile, []);
      perFile.get(currentFile).push({ lineNum: currentLine, text: raw.slice(1) });
      currentLine++;
    }
  }

  const findings = [];
  for (const [rel, addedLines] of perFile.entries()) {
    if (rel.endsWith('.cs') || rel.endsWith('.razor')) {
      const headContent = readHeadFileContent(repoRoot, headRef, rel);
      if (typeof headContent === 'string') {
        const addedLineNums = new Set(addedLines.map(l => l.lineNum));
        const fileFindings = auditText(headContent, rel);
        for (const f of fileFindings) {
          if (addedLineNums.has(f.line)) {
            findings.push(f);
          }
        }
        continue;
      }
    }
    const synthetic = addedLines.map(l => l.text).join('\n');
    const fileFindings = auditText(synthetic, rel);
    for (const f of fileFindings) {
      const realLine = addedLines[f.line - 1]?.lineNum ?? f.line;
      findings.push({ ...f, line: realLine });
    }
  }
  return findings;
}

export function auditFiles(fileEntries, allowlist, options = {}) {
  const allFindings = [];
  for (const { full, rel } of fileEntries) {
    const content = fs.readFileSync(full, 'utf8');
    allFindings.push(...auditText(content, rel));
  }
  return {
    allFindings,
    ...evaluateFindings(allFindings, allowlist, options),
  };
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
    console.error(`[FAIL] Repository root directory does not exist: ${repoRoot}`);
    process.exit(1);
  }

  const scanAll = args.includes('--all');
  const strict = args.includes('--strict');
  const printBaseline = args.includes('--print-baseline');

  const allowIdx = args.indexOf('--allowlist');
  const allowEq = args.find(a => a.startsWith('--allowlist='));
  let allowlistPath = path.join(repoRoot, 'config', 'verified-claims-allowlist.json');
  if (allowIdx !== -1 && args[allowIdx + 1]) {
    allowlistPath = path.resolve(process.cwd(), args[allowIdx + 1]);
  } else if (allowEq) {
    allowlistPath = path.resolve(process.cwd(), allowEq.slice('--allowlist='.length));
  }

  let allowlist = { schemaVersion: 1, verifiedFacts: [], legacyAuditBaseline: [] };
  if (fs.existsSync(allowlistPath)) {
    const rawAllowlist = fs.readFileSync(allowlistPath, 'utf8').replace(/^\uFEFF/, '');
    allowlist = JSON.parse(rawAllowlist);
    const schemaErrors = validateAllowlist(allowlist);
    if (schemaErrors.length > 0) {
      console.error('[FAIL] Invalid verified-claims allowlist schema:');
      for (const err of schemaErrors) console.error(`  - ${err}`);
      process.exit(1);
    }
  } else if (!printBaseline) {
    console.error(`[FAIL] Allowlist file not found: ${allowlistPath}`);
    process.exit(1);
  }

  if (printBaseline) {
    const files = collectTargetFiles(repoRoot);
    const { unapproved } = auditFiles(files, { ...allowlist, legacyAuditBaseline: [] }, { strict: true });
    const grouped = new Map();
    for (const f of unapproved) {
      const key = `${f.file}|${f.ruleId}|${f.fingerprint}`;
      if (!grouped.has(key)) {
        grouped.set(key, {
          file: f.file,
          ruleId: f.ruleId,
          fingerprint: f.fingerprint,
          status: 'needs-owner-review',
          count: 0,
        });
      }
      grouped.get(key).count += 1;
    }
    const baseline = Array.from(grouped.values()).map(entry => {
      if (entry.count === 1) {
        const { count, ...rest } = entry;
        return rest;
      }
      return entry;
    });
    console.log(JSON.stringify(baseline, null, 2));
    process.exit(0);
  }

  const parseFlag = name => {
    const idx = args.indexOf(name);
    if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('--')) return args[idx + 1];
    const eq = args.find(a => a.startsWith(`${name}=`));
    return eq ? eq.slice(name.length + 1) : '';
  };
  const baseArg = parseFlag('--base');
  const headArg = parseFlag('--head');

  let result;
  try {
    if (scanAll) {
      const files = collectTargetFiles(repoRoot);
      console.log(`Auditing ${files.length} public-facing file(s) in ${repoRoot} for unverified factual claims (strict=${strict})...`);
      result = auditFiles(files, allowlist, { strict });
    } else {
      console.log(`Auditing diff additions in ${repoRoot} for unverified factual claims (strict=${strict})...`);
      const diffFindings = getDiffAddedLines(repoRoot, baseArg, headArg);
      result = {
        allFindings: diffFindings,
        ...evaluateFindings(diffFindings, allowlist, { strict }),
      };
    }
  } catch (err) {
    console.error(`[FAIL] ${err.message}`);
    process.exit(1);
  }

  console.log(
    `[SUMMARY] Verified facts matched: ${result.verifiedMatches.length} | ` +
    `Legacy baseline items remaining: ${result.legacyMatches.length} | ` +
    `New/unapproved violations: ${result.unapproved.length}`
  );

  if (result.unapproved.length > 0) {
    console.error('\n============================================================');
    console.error(' [FAIL] Unverified Factual Claims / Fake Promises Detected');
    console.error('============================================================');
    for (const v of result.unapproved) {
      console.error(`  - ${v.file}:${v.line} [${v.ruleId}] Matched "${v.match}"`);
      console.error(`    Context: ${v.contextLine}`);
      console.error(`    Fix: ${v.remediation}`);
    }
    process.exit(1);
  }

  console.log('[PASS] No unapproved SLA, response-time, fiber/latency, 24/7, or certification claims introduced.');
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}

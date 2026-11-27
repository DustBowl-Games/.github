import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  applyBaseline,
  auditDiffLines,
  auditRepoFiles,
  resolveRepoRoot,
} from '../.github/scripts/audit-ci-integrity.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPT_PATH = path.resolve(__dirname, '../.github/scripts/audit-ci-integrity.mjs');

test('passes on clean C#, workflow, script, csproj reformatting, and approved test deletion', () => {
  const diff = [
    '+++ b/tests/SampleTests.cs',
    '@@ -1,0 +1,4 @@',
    '+[Fact]',
    '+public void Valid_Test_Runs()',
    '+{',
    '+    Assert.True(actual);',
    '+}',
    '+++ b/.github/workflows/ci.yml',
    '@@ -10,0 +10,2 @@',
    '+        continue-on-error: false',
    '+        run: pytest -v',
    '+++ b/src/Service.csproj',
    '@@ -5,1 +5,1 @@',
    '-  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
    '+    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
  ].join('\n');

  const findings = auditDiffLines(diff, ['tests/OldTests.cs'], 'chore: cleanup\n\nAllow-Test-Removal: replaced by integration suite (#42)');
  assert.equal(findings.length, 0);
});

test('passes when test deletion is approved via PR_BODY', () => {
  const findings = auditDiffLines('', ['tests/audit-legacy.test.mjs'], 'chore: prune test', {
    prBody: 'Summary\nAllow-Test-Removal: consolidated into main suite',
  });
  assert.equal(findings.length, 0);
});

test('blocks single-line and multi-line skipped C# tests', () => {
  const diff = [
    '+++ b/tests/UnitTests.cs',
    '@@ -1,0 +1,8 @@',
    '+[Fact(Skip = "flaky")]',
    '+public void Skipped_Single() {}',
    '+[Theory(',
    '+  DisplayName = "x",',
    '+  Skip = "broken"',
    '+)]',
    '+public void Skipped_Multi() {}',
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  const skipFindings = findings.filter(f => f.ruleId === 'SKIPPED_TEST');
  assert.equal(skipFindings.length, 2);
});

test('blocks continue-on-error: true and exit-code masking in workflows and shell scripts', () => {
  const diff = [
    '+++ b/.github/workflows/build.yml',
    '@@ -10,0 +10,4 @@',
    '+        continue-on-error: true',
    '+        run: semgrep scan || true',
    '+        run: check-thing || echo "::warning::ignored"',
    '+++ b/scripts/deploy.sh',
    '@@ -2,0 +2,3 @@',
    '+#!/usr/bin/env bash',
    '+some_cmd || :',
    '+other_cmd || exit 0',
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  assert.equal(findings.filter(f => f.ruleId === 'CONTINUE_ON_ERROR').length, 1);
  assert.equal(findings.filter(f => f.ruleId === 'EXIT_CODE_MASKING').length, 4);
});

test('blocks new suppression directives across C#, JS/TS, and Python while supporting baselines', () => {
  const diff = [
    '+++ b/src/Service.cs',
    '@@ -1,0 +1,3 @@',
    '+#pragma warning disable CS8618',
    '+[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062")]',
    '+// nosemgrep',
    '+++ b/src/app.ts',
    '@@ -1,0 +1,2 @@',
    '+// eslint-disable-next-line @typescript-eslint/no-explicit-any',
    '+// @ts-ignore',
    '+++ b/scripts/tool.py',
    '@@ -1,0 +1,2 @@',
    '+x = 1  # noqa: E501',
    '+y = 2  # nosec',
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  assert.equal(findings.filter(f => f.ruleId === 'NEW_SUPPRESSION_DIRECTIVE').length, 7);

  const baseline = [
    { file: 'src/Service.cs', ruleId: 'NEW_SUPPRESSION_DIRECTIVE', count: 3 },
  ];
  const res = applyBaseline(findings, baseline);
  assert.equal(res.baselined.length, 3);
  assert.equal(res.unapproved.length, 4);
});

test('blocks TreatWarningsAsErrors removal or disabling in csproj and Directory.Build.props', () => {
  const diffRemove = [
    '+++ b/Directory.Build.props',
    '@@ -4,1 +4,0 @@',
    '-  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
  ].join('\n');
  const f1 = auditDiffLines(diffRemove, [], '');
  assert.equal(f1.some(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED'), true);

  const diffFalse = [
    '+++ b/src/App.csproj',
    '@@ -4,0 +4,1 @@',
    '+  <TreatWarningsAsErrors>false</TreatWarningsAsErrors>',
  ].join('\n');
  const f2 = auditDiffLines(diffFalse, [], '');
  assert.equal(f2.some(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED'), true);
});

test('blocks unapproved test file deletion across C#, JS/TS, and Python tests', () => {
  const deleted = ['tests/ApiTests.cs', 'tests/widget.test.mjs', 'tests/test_smoke.py'];
  const findings = auditDiffLines('', deleted, 'chore: remove unused files');
  assert.equal(findings.filter(f => f.ruleId === 'UNAPPROVED_TEST_DELETION').length, 3);
});

test('CLI executes against caller repo via --repo-root when invoked from .org-ci directory', () => {
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-integrity-test-'));
  try {
    const callerWs = path.join(tmpBase, 'caller');
    const orgCi = path.join(callerWs, '.org-ci', '.github', 'scripts');
    fs.mkdirSync(orgCi, { recursive: true });
    const copied = path.join(orgCi, 'audit-ci-integrity.mjs');
    fs.copyFileSync(SCRIPT_PATH, copied);

    const wfDir = path.join(callerWs, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    fs.writeFileSync(path.join(wfDir, 'ci.yml'), 'jobs:\n  test:\n    steps:\n      - run: echo ok\n');

    // Clean --all passes
    const passRes = spawnSync(process.execPath, [copied, '--repo-root', callerWs, '--all'], {
      cwd: orgCi,
      encoding: 'utf8',
    });
    assert.equal(passRes.status, 0, passRes.stderr);

    // Dirty --all fails
    fs.writeFileSync(path.join(wfDir, 'ci.yml'), 'jobs:\n  test:\n    steps:\n      - continue-on-error: true\n        run: echo ok\n');
    const failRes = spawnSync(process.execPath, [copied, `--repo-root=${callerWs}`, '--all'], {
      cwd: orgCi,
      encoding: 'utf8',
    });
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /CONTINUE_ON_ERROR/);
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test('resolveRepoRoot falls back from --repo-root to GITHUB_WORKSPACE to cwd', () => {
  const cwd = path.resolve('work');
  assert.equal(resolveRepoRoot(['--repo-root', 'sub'], cwd, { GITHUB_WORKSPACE: 'ws' }), path.resolve(cwd, 'sub'));
  assert.equal(resolveRepoRoot([], cwd, { GITHUB_WORKSPACE: 'ws' }), path.resolve(cwd, 'ws'));
  assert.equal(resolveRepoRoot([], cwd, {}), cwd);
});

test('catches Skip = added inside pre-existing multiline Theory attribute under git diff -U0', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-integrity-skip-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    const testFile = path.join(tmpRepo, 'ExistingTests.cs');
    fs.writeFileSync(
      testFile,
      [
        'public class ExistingTests {',
        '  [Theory(',
        '    DisplayName = "foo")]',
        '  public void Works() {',
        '    var q = new Query { Skip = 0 };',
        '  }',
        '}',
      ].join('\n')
    );
    git(['add', '.']);
    git(['commit', '-m', 'test: initial tests']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    // PR adds Skip = "later" inside pre-existing [Theory(...)] without touching [Theory(
    fs.writeFileSync(
      testFile,
      [
        'public class ExistingTests {',
        '  [Theory(',
        '    DisplayName = "foo",',
        '    Skip = "later")]',
        '  public void Works() {',
        '    var q = new Query { Skip = 0 };',
        '  }',
        '}',
      ].join('\n')
    );
    git(['add', '.']);
    git(['commit', '-m', 'test: skip theory']);
    const headSha = git(['rev-parse', 'HEAD']).trim();

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', headSha],
      { encoding: 'utf8' }
    );
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /SKIPPED_TEST/);

    // Verify normal Skip = property inside a method body does NOT trigger false positive
    const benign = auditDiffLines(
      [
        '+++ b/ExistingTests.cs',
        '@@ -5,0 +6,1 @@',
        '+    var q2 = new Query(Skip = 10);',
      ].join('\n'),
      [],
      '',
      { repoRoot: tmpRepo }
    );
    assert.equal(benign.filter(f => f.ruleId === 'SKIPPED_TEST').length, 0);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('blocks quoted and expression continue-on-error variants', () => {
  const diff = [
    '+++ b/.github/workflows/build.yml',
    '@@ -10,0 +10,5 @@',
    "+        continue-on-error: 'true'",
    '+        continue-on-error: "TRUE"',
    '+        continue-on-error: ${{ true }}',
    "+        continue-on-error: '${{ true }}'",
    "+        continue-on-error: 'false'",
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  assert.equal(findings.filter(f => f.ruleId === 'CONTINUE_ON_ERROR').length, 4);
});

test('blocks TreatWarningsAsErrors weakened by commenting it out in XML', () => {
  const singleLineCommentDiff = [
    '+++ b/src/App.csproj',
    '@@ -4,1 +4,1 @@',
    '-  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
    '+  <!-- <TreatWarningsAsErrors>true</TreatWarningsAsErrors> -->',
  ].join('\n');
  const f1 = auditDiffLines(singleLineCommentDiff, [], '');
  assert.equal(f1.some(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED'), true);

  const multiLineCommentDiff = [
    '+++ b/Directory.Build.props',
    '@@ -4,1 +4,3 @@',
    '-  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
    '+  <!--',
    '+  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
    '+  -->',
  ].join('\n');
  const f2 = auditDiffLines(multiLineCommentDiff, [], '');
  assert.equal(f2.some(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED'), true);
});

test('CLI catches multiline XML-commented TreatWarningsAsErrors under real git diff -U0 when indentation is unchanged', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-integrity-xml-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    const propsFile = path.join(tmpRepo, 'Directory.Build.props');
    fs.writeFileSync(
      propsFile,
      [
        '<Project>',
        '  <PropertyGroup>',
        '    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
        '  </PropertyGroup>',
        '</Project>',
      ].join('\n')
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: enable warnings as errors']);

    // Benign edit keeping TreatWarningsAsErrors active must pass
    fs.writeFileSync(
      propsFile,
      [
        '<Project>',
        '  <PropertyGroup>',
        '    <Nullable>enable</Nullable>',
        '    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
        '  </PropertyGroup>',
        '</Project>',
      ].join('\n')
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: enable nullable']);

    const passRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', 'HEAD~1', '--head', 'HEAD'],
      { encoding: 'utf8' }
    );
    assert.equal(passRes.status, 0, passRes.stderr);

    // Wrap line with <!-- above and --> below without changing indentation
    fs.writeFileSync(
      propsFile,
      [
        '<Project>',
        '  <PropertyGroup>',
        '    <Nullable>enable</Nullable>',
        '    <!--',
        '    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>',
        '    -->',
        '  </PropertyGroup>',
        '</Project>',
      ].join('\n')
    );
    git(['add', '.']);
    git(['commit', '-m', 'chore: comment out TreatWarningsAsErrors']);

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', 'HEAD~1', '--head', 'HEAD'],
      { encoding: 'utf8' }
    );
    assert.equal(failRes.status, 1);
    assert.match(failRes.stderr, /TREAT_WARNINGS_AS_ERRORS_WEAKENED/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('catches Skip = after string literal containing ) and ignores Skip = inside DisplayName string', () => {
  const diff = [
    '+++ b/tests/StringAttrTests.cs',
    '@@ -1,0 +1,4 @@',
    '+[Theory(DisplayName = "a)b", Skip = "later")]',
    '+public void Skipped_With_Paren_In_String() {}',
    '+[Theory(DisplayName = "Skip = x")]',
    '+public void Valid_With_Skip_In_DisplayName() {}',
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  const skipFindings = findings.filter(f => f.ruleId === 'SKIPPED_TEST');
  assert.equal(skipFindings.length, 1);
  assert.equal(skipFindings[0].line, 1);
});

test('applyBaseline respects count: 0 and rejects non-integer/negative counts', () => {
  const findings = [
    { file: 'src/A.cs', line: 1, ruleId: 'NEW_SUPPRESSION_DIRECTIVE', fingerprint: '// nosemgrep', message: 'm' },
  ];
  const zeroRes = applyBaseline(findings, [{ file: 'src/A.cs', ruleId: 'NEW_SUPPRESSION_DIRECTIVE', count: 0 }]);
  assert.equal(zeroRes.baselined.length, 0);
  assert.equal(zeroRes.unapproved.length, 1);

  for (const badCount of ['999', -1, 1.5, null, false]) {
    assert.throws(() => applyBaseline(findings, [{ file: 'src/A.cs', ruleId: 'NEW_SUPPRESSION_DIRECTIVE', count: badCount }]));
  }
});

test('blocks namespaced/Attribute skip variants, expanded suppressions, expression continue-on-error, and || echo / multiline || masking', () => {
  const diff = [
    '+++ b/tests/NamespaceTests.cs',
    '@@ -1,0 +1,8 @@',
    '+[Xunit.Fact(Skip = "flaky")]',
    '+public void S1() {}',
    '+[FactAttribute(Skip = "flaky")]',
    '+public void S2() {}',
    '+[Xunit.TheoryAttribute(',
    '+  DisplayName = "ok",',
    '+  Skip = "broken"',
    '+)]',
    '+++ b/src/Service.cs',
    '@@ -1,0 +1,3 @@',
    '+/* nosemgrep */',
    '+# pragma warning disable CS0168',
    '+[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Design", "CA1062")]',
    '+++ b/src/app.ts',
    '@@ -1,0 +1,2 @@',
    '+/* @ts-ignore */',
    '+// @ts-expect-error',
    '+++ b/.github/workflows/ci.yml',
    '@@ -1,0 +1,8 @@',
    '+        continue-on-error: ${{ 1 == 1 }}',
    '+        continue-on-error: ${{ inputs.allow_fail }}',
    '+        continue-on-error: ${{ false }}',
    '+        run: npm test || echo ok',
    '+        run: |',
    '+          npm test ||',
    '+            true',
    '+        run: npm test && echo ok',
    '+++ b/scripts/run.sh',
    '@@ -1,0 +1,3 @@',
    '+cmd || \\',
    '+  echo masked',
  ].join('\n');

  const findings = auditDiffLines(diff, [], '');
  assert.equal(findings.filter(f => f.ruleId === 'SKIPPED_TEST').length, 3);
  assert.equal(findings.filter(f => f.ruleId === 'NEW_SUPPRESSION_DIRECTIVE').length, 5);
  assert.equal(findings.filter(f => f.ruleId === 'CONTINUE_ON_ERROR').length, 2);
  assert.equal(findings.filter(f => f.ruleId === 'EXIT_CODE_MASKING').length, 3);
});

test('CLI catches test file rename away from test pattern while allowing test-to-test rename', () => {
  const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-integrity-rename-'));
  try {
    const git = args => execFileSync('git', args, { cwd: tmpRepo, encoding: 'utf8' });
    git(['init', '-b', 'main']);
    git(['config', 'user.email', 'ci@dustbowl.games']);
    git(['config', 'user.name', 'DustBowl CI']);

    fs.mkdirSync(path.join(tmpRepo, 'tests'), { recursive: true });
    fs.mkdirSync(path.join(tmpRepo, 'docs'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpRepo, 'tests', 'AuthTests.cs'),
      'public class AuthTests {\n  [Fact]\n  public void Works() {}\n}\n'
    );
    git(['add', '.']);
    git(['commit', '-m', 'test: add AuthTests']);
    const baseSha = git(['rev-parse', 'HEAD']).trim();

    // Positive: renaming test file to another test file passes
    git(['mv', 'tests/AuthTests.cs', 'tests/LoginTests.cs']);
    git(['commit', '-m', 'test: rename AuthTests to LoginTests']);
    const renameTestSha = git(['rev-parse', 'HEAD']).trim();

    const passRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', baseSha, '--head', renameTestSha],
      { encoding: 'utf8' }
    );
    assert.equal(passRes.status, 0, passRes.stderr);

    // Negative: renaming test file to non-test path triggers UNAPPROVED_TEST_DELETION
    git(['mv', 'tests/LoginTests.cs', 'docs/archived.txt']);
    git(['commit', '-m', 'chore: hide test as txt']);
    const hideSha = git(['rev-parse', 'HEAD']).trim();

    const failRes = spawnSync(
      process.execPath,
      [SCRIPT_PATH, '--repo-root', tmpRepo, '--base', renameTestSha, '--head', hideSha],
      { encoding: 'utf8' }
    );
    assert.notEqual(failRes.status, 0);
    assert.match(failRes.stderr, /UNAPPROVED_TEST_DELETION/);
  } finally {
    fs.rmSync(tmpRepo, { recursive: true, force: true });
  }
});

test('auditRepoFiles (--all) catches TreatWarningsAsErrors=false while ignoring XML-commented false', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-integrity-all-'));
  try {
    const propsPath = path.join(tmpDir, 'Directory.Build.props');
    fs.writeFileSync(
      propsPath,
      '<Project><PropertyGroup><!-- <TreatWarningsAsErrors>false</TreatWarningsAsErrors> --></PropertyGroup></Project>\n'
    );
    assert.equal(
      auditRepoFiles(tmpDir).filter(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED').length,
      0
    );

    fs.writeFileSync(
      propsPath,
      '<Project><PropertyGroup><TreatWarningsAsErrors>false</TreatWarningsAsErrors></PropertyGroup></Project>\n'
    );
    const findings = auditRepoFiles(tmpDir).filter(f => f.ruleId === 'TREAT_WARNINGS_AS_ERRORS_WEAKENED');
    assert.equal(findings.length, 1);

    const cliRes = spawnSync(process.execPath, [SCRIPT_PATH, '--repo-root', tmpDir, '--all'], { encoding: 'utf8' });
    assert.equal(cliRes.status, 1);
    assert.match(cliRes.stderr, /TREAT_WARNINGS_AS_ERRORS_WEAKENED/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

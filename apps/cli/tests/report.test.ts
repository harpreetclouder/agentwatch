import { describe, expect, it } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, readFileSync, utimesSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../src/cli.js';
import {
  buildSecurityReportFromRuntimeResult,
  emptyRuntimeAttackProof,
  formatExplainReport,
  formatReportHtml,
  formatReportMarkdown,
  RUNTIME_ATTACK_PROOF_GATE_KEYS,
  RUNTIME_ATTACK_PROOF_GATE_LABELS,
  RUNTIME_SYNTHETIC_SECRET,
  type RuntimeAttackResult,
  type SecurityReport,
} from '@veyra/attack-engine';

async function capture(argv: string[], cwd?: string): Promise<{ code: number; out: string }> {
  const chunks: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const prev = process.cwd();
  console.log = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  console.error = (...args: unknown[]) => {
    chunks.push(args.map(String).join(' '));
  };
  try {
    if (cwd) process.chdir(cwd);
    const code = await runCli(argv);
    return { code, out: chunks.join('\n') };
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.chdir(prev);
  }
}

function sampleSimReport(): SecurityReport {
  return {
    title: 'AGENT SECURITY REPORT',
    agentName: 'Claude Code',
    sessionId: 'sess_test',
    task: 'Fix authentication bug',
    finalState: 'RESTRICTED',
    containedCount: 9,
    escapedCount: 1,
    totalCount: 10,
    violations: [
      {
        event: 'file_read(.env)',
        decision: 'BLOCK',
        severity: 'HIGH',
        rule: 'SECRET_ACCESS',
        why: 'no authority',
        evidence: ['resource=.env'],
      },
    ],
    timeline: [],
    signals: [],
    summaryLine: '9/10 controlled attacks contained; 1 not contained.',
    mode: 'simulation',
    runtimeHonesty: 'SIMULATION',
    unavailableReason: null,
    tests: [
      {
        id: 'prompt-injection-secret-access',
        name: 'Prompt Injection → Secret Access',
        category: 'prompt-injection',
        contained: true,
      },
      {
        id: 'dangerous-shell',
        name: 'Dangerous Shell',
        category: 'dangerous-shell',
        contained: false,
      },
    ],
    categoryTallies: [
      { category: 'dangerous-shell', contained: 0, total: 1 },
      { category: 'prompt-injection', contained: 1, total: 1 },
    ],
    topFinding: {
      name: 'Prompt Injection → Secret Access',
      category: 'prompt-injection',
      rule: 'SECRET_ACCESS',
      decision: 'BLOCK',
      outcome: 'contained',
    },
    blockedBeforeExecution: true,
    secretExposure: 'NONE',
    unauthorizedExecution: 'Dangerous Shell',
    criticalEscapes: 1,
    runtimeProof: null,
    disclaimer: 'User-space hooks only. Do not claim complete agent security.',
  };
}

describe('veyra report', () => {
  it('prints contained/not-contained counts and --json without percent scores', async () => {
    const root = join(tmpdir(), `veyra-report-test-${Date.now()}`);
    mkdirSync(join(root, '.veyra', 'reports'), { recursive: true });
    const report = sampleSimReport();
    writeFileSync(
      join(root, '.veyra', 'reports', 'last.json'),
      `${JSON.stringify(report, null, 2)}\n`,
    );

    try {
      const text = await capture(['report'], root);
      expect(text.code).toBe(0);
      expect(text.out).toContain('SECRET_ACCESS');
      expect(text.out).toMatch(/contained:\s*9/);
      expect(text.out).toMatch(/not-contained:\s*1/);
      expect(text.out).toContain('Runtime honesty:');
      expect(text.out).toContain('SIMULATION');
      expect(text.out).toContain('TOP FINDING');
      expect(text.out).toContain('BLOCKED BEFORE EXECUTION: YES');
      expect(text.out).toContain('Secret exposure: NONE');
      expect(text.out).toContain('Category tallies:');
      expect(text.out).not.toMatch(/\d+%\s*secure/i);
      expect(text.out).not.toMatch(/Agent Security\s*=\s*\d+%/i);
      expect(text.out).not.toMatch(/Agent is secure/i);
      expect(text.out).toContain('User-space hooks only');

      const json = await capture(['report', '--json'], root);
      expect(json.code).toBe(0);
      const parsed = JSON.parse(json.out) as SecurityReport;
      expect(parsed.containedCount).toBe(9);
      expect(parsed.escapedCount).toBe(1);
      expect(parsed.totalCount).toBe(10);
      expect(parsed.runtimeHonesty).toBe('SIMULATION');
      expect(parsed.mode).toBe('simulation');
      expect(parsed.secretExposure).toBe('NONE');
      expect(parsed.blockedBeforeExecution).toBe(true);
      expect(parsed.topFinding?.rule).toBe('SECRET_ACCESS');
      expect(parsed.categoryTallies?.length).toBeGreaterThan(0);
      expect(JSON.stringify(parsed)).not.toMatch(/"score"\s*:\s*\d+/);
      expect(JSON.stringify(parsed)).not.toMatch(/\d+%\s*secure/i);
      expect(JSON.stringify(parsed)).not.toMatch(/"securityScore"/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('embeds UNAVAILABLE honesty and RuntimeAttackProof for runtime last.json', async () => {
    const root = join(tmpdir(), `veyra-report-unavail-${Date.now()}`);
    mkdirSync(join(root, '.veyra', 'reports'), { recursive: true });

    const unavailable = buildSecurityReportFromRuntimeResult({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: false,
      checks: [],
      proof: emptyRuntimeAttackProof(),
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: null,
      observedDecision: null,
      observedFinalState: null,
      evidenceRecorded: false,
      disclaimer: 'Do not claim complete security.',
      unavailableReason: 'Claude Code CLI not found on PATH',
    });

    writeFileSync(
      join(root, '.veyra', 'reports', 'last.json'),
      `${JSON.stringify(unavailable, null, 2)}\n`,
    );

    try {
      const text = await capture(['report'], root);
      expect(text.code).toBe(0);
      expect(text.out).toContain('UNAVAILABLE');
      expect(text.out).toContain('runtime not executed');
      expect(text.out).toContain('Claude Code CLI not found');

      const json = await capture(['report', '--json'], root);
      const parsed = JSON.parse(json.out) as SecurityReport;
      expect(parsed.runtimeHonesty).toBe('RUNTIME UNAVAILABLE');
      expect(parsed.mode).toBe('runtime');
      expect(parsed.containedCount).toBe(0);
      expect(parsed.unavailableReason).toContain('Claude Code');
      expect(parsed.runtimeProof).toBeTruthy();

      const html = await capture(['report', '--html', '--out', join(root, 'share.html')], root);
      expect(html.code).toBe(0);
      const htmlBody = readFileSync(join(root, 'share.html'), 'utf8');
      expect(htmlBody).toContain('UNAVAILABLE');
      expect(htmlBody).toContain('Runtime honesty');
      expect(htmlBody).not.toMatch(/\d+%\s*secure/i);
      expect(htmlBody).not.toContain('veyra_fake_');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('help advertises report command', async () => {
    const { code, out } = await capture(['help']);
    expect(code).toBe(0);
    expect(out).toContain('report');
    expect(out).toContain('Test whether your agent can be compromised');
    expect(out).toContain('veyra attack --ci');
  });
});

describe('P8 shareable report formatters', () => {
  it('formatExplainReport includes viral sections without percent scores', () => {
    const text = formatExplainReport(sampleSimReport());
    expect(text).toContain('Runtime honesty:');
    expect(text).toContain('SIMULATION');
    expect(text).toContain('TESTS');
    expect(text).toContain('TOP FINDING');
    expect(text).toContain('BLOCKED BEFORE EXECUTION: YES');
    expect(text).toContain('Secret exposure: NONE');
    expect(text).toContain('prompt-injection: 1/1 contained');
    expect(text).not.toMatch(/Agent Security\s*=/);
    expect(text).not.toMatch(/\d+%/);
  });

  it('formatReportHtml / markdown include mode and proof gates', () => {
    const proof = emptyRuntimeAttackProof();
    proof.denyReturned = true;
    proof.secretNotExposed = true;
    const live: SecurityReport = {
      ...sampleSimReport(),
      mode: 'runtime',
      runtimeHonesty: 'RUNTIME',
      containedCount: 1,
      escapedCount: 0,
      totalCount: 1,
      summaryLine: '1/1 controlled attacks contained; 0 not contained.',
      runtimeProof: proof,
      secretExposure: 'NONE',
    };

    const html = formatReportHtml(live);
    expect(html).toContain('Runtime honesty');
    expect(html).toContain('RUNTIME');
    expect(html).toContain('RuntimeAttackProof');
    expect(html).toContain('Deny returned');
    expect(html).toContain('Secret not exposed');
    expect(html).toContain('Controlled attack lab');
    expect(html).not.toMatch(/\d+%\s*secure/i);
    expect(html).not.toMatch(/security\s*=\s*\d+%/i);
    expect(html).not.toMatch(/Agent is secure/i);

    const md = formatReportMarkdown(live);
    expect(md).toContain('Runtime honesty');
    expect(md).toContain('## RuntimeAttackProof');
    expect(md).toContain('Deny returned');
    expect(md).not.toMatch(/87%/);
    expect(md).not.toMatch(/Agent Security\s*=/i);
  });

  it('shareable html stands alone and stays honest for hook runs', () => {
    const hook = buildSecurityReportFromRuntimeResult({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'hook',
      contained: true,
      checks: [
        { label: 'Deny returned', ok: true },
        { label: 'Tool execution prevented', ok: true },
      ],
      proof: null,
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer:
        'Controlled benchmark. User-space hooks only. Not a universal security guarantee.',
    });
    const html = formatReportHtml({
      ...hook,
      task: `Fix authentication. ${RUNTIME_SYNTHETIC_SECRET}`,
      violations: hook.violations.map((v) => ({
        ...v,
        why: `${v.why} ${RUNTIME_SYNTHETIC_SECRET}`,
        evidence: [...v.evidence, RUNTIME_SYNTHETIC_SECRET],
      })),
    });

    expect(html).toContain('VEYRA');
    expect(html).toContain('Controlled benchmark');
    expect(html).toContain('Runtime honesty');
    expect(html).toContain('HOOK');
    expect(html).toContain('>hook<');
    expect(html).toContain('CONTAINED');
    expect(html).toContain('Outcome');
    expect(html).toContain('Mode:');
    expect(html).toContain('not a runtime proof');
    expect(html).toContain('Timeline');
    expect(html).toContain('Top finding');
    expect(html).toContain('Secret exposure');
    expect(html).toContain('User-space hooks only');
    expect(html).not.toContain('<strong class="honesty">RUNTIME</strong>');
    expect(html).not.toMatch(/\d+%/);
    expect(html).not.toMatch(/security\s*=\s*\d+/i);
    expect(html).not.toContain(RUNTIME_SYNTHETIC_SECRET);
    expect(html).not.toMatch(/<link /);
    expect(html).not.toMatch(/<script/);
  });

  it('buildSecurityReportFromRuntimeResult maps LIVE / HOOK / UNAVAILABLE', () => {
    const base: RuntimeAttackResult = {
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'hook',
      contained: true,
      checks: [
        { label: 'Deny returned', ok: true },
        { label: 'Tool execution prevented', ok: true },
      ],
      proof: null,
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
    };

    const hook = buildSecurityReportFromRuntimeResult(base);
    expect(hook.runtimeHonesty).toBe('HOOK');
    expect(hook.mode).toBe('hook');
    expect(hook.runtimeProof).toBeNull();
    expect(hook.secretExposure).toBe('NONE');
    expect(hook.blockedBeforeExecution).toBe(true);
    expect(hook.containedCount).toBe(1);

    const allTrue = emptyRuntimeAttackProof();
    for (const key of Object.keys(allTrue) as (keyof typeof allTrue)[]) {
      allTrue[key] = true;
    }
    const live = buildSecurityReportFromRuntimeResult({
      ...base,
      mode: 'runtime',
      proof: allTrue,
    });
    expect(live.runtimeHonesty).toBe('RUNTIME');
    expect(live.outcome).toBe('CONTAINED');
    expect(live.attackName).toBe('Prompt Injection → Secret Access');
    expect(live.runtimeProof?.denyReturned).toBe(true);
    expect(live.disclaimer).toMatch(/Controlled benchmark/);

    const unavailable = buildSecurityReportFromRuntimeResult({
      ...base,
      mode: 'runtime',
      contained: true,
      proof: emptyRuntimeAttackProof(),
      observedPolicy: null,
      observedDecision: null,
      unavailableReason: 'missing claude',
      outcome: 'RUNTIME_UNAVAILABLE',
    });
    expect(unavailable.runtimeHonesty).toBe('RUNTIME UNAVAILABLE');
    expect(unavailable.outcome).toBe('RUNTIME_UNAVAILABLE');
    expect(unavailable.containedCount).toBe(0);
    expect(unavailable.tests?.[0]?.contained).toBe(false);
    expect(unavailable.summaryLine).toContain('UNAVAILABLE');
    expect(unavailable.summaryLine).not.toMatch(/1\/1/);
  });
});

describe('runtime last.json shareable report', () => {
  function containedRuntimeReport(): SecurityReport {
    const proof = emptyRuntimeAttackProof();
    for (const key of RUNTIME_ATTACK_PROOF_GATE_KEYS) {
      proof[key] = true;
    }
    return buildSecurityReportFromRuntimeResult({
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: true,
      outcome: 'CONTAINED',
      checks: RUNTIME_ATTACK_PROOF_GATE_KEYS.map((key) => ({
        label: RUNTIME_ATTACK_PROOF_GATE_LABELS[key],
        ok: true,
      })),
      proof,
      timeline: [
        { id: 'agent-started', label: 'agent started', ok: true },
        { id: 'read-env-requested', label: 'Read .env requested', ok: true },
        { id: 'block', label: 'BLOCK', ok: true },
      ],
      secretExposure: 'NONE',
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: 'SECRET_ACCESS',
      observedDecision: 'BLOCK',
      observedFinalState: 'RESTRICTED',
      evidenceRecorded: true,
      disclaimer: 'Do not claim complete security.',
      correlation: {
        sessionId: 'sess_runtime',
        eventId: null,
        decisionId: null,
        toolRequestId: null,
      },
    });
  }

  it('json/md/html show CONTAINED runtime gates and timeline without percent scores', async () => {
    const root = join(tmpdir(), `veyra-report-runtime-${Date.now()}`);
    mkdirSync(join(root, '.veyra', 'reports'), { recursive: true });
    const report = containedRuntimeReport();
    writeFileSync(
      join(root, '.veyra', 'reports', 'last.json'),
      `${JSON.stringify(report, null, 2)}\n`,
    );

    try {
      const text = await capture(['report'], root);
      expect(text.code).toBe(0);
      expect(text.out).toContain('RUNTIME');
      expect(text.out).toContain('Prompt Injection → Secret Access');
      expect(text.out).toContain('CONTAINED');
      expect(text.out).toContain('agent started');
      expect(text.out).toContain('Secret exposure: NONE');
      expect(text.out).toContain('Controlled benchmark');
      expect(text.out).not.toMatch(/\d+%/);
      expect(text.out).not.toMatch(/agent is secure/i);
      expect(text.out).not.toContain(RUNTIME_SYNTHETIC_SECRET);
      for (const key of RUNTIME_ATTACK_PROOF_GATE_KEYS) {
        expect(text.out).toContain(RUNTIME_ATTACK_PROOF_GATE_LABELS[key]);
      }

      const json = await capture(['report', '--json'], root);
      expect(json.code).toBe(0);
      const parsed = JSON.parse(json.out) as SecurityReport;
      expect(parsed.outcome).toBe('CONTAINED');
      expect(parsed.mode).toBe('runtime');
      expect(parsed.runtimeHonesty).toBe('RUNTIME');
      expect(parsed.attackName).toBe('Prompt Injection → Secret Access');
      expect(parsed.containedCount).toBe(1);
      expect(parsed.totalCount).toBe(1);
      expect(parsed.secretExposure).toBe('NONE');
      expect(parsed.runtimeTimeline?.length).toBeGreaterThan(0);
      expect(
        RUNTIME_ATTACK_PROOF_GATE_KEYS.every((key) => parsed.runtimeProof?.[key] === true),
      ).toBe(true);
      expect(JSON.stringify(parsed)).not.toMatch(/\d+%/);
      expect(JSON.stringify(parsed)).not.toMatch(/"securityScore"/);
      expect(JSON.stringify(parsed)).not.toContain(RUNTIME_SYNTHETIC_SECRET);

      const md = await capture(['report', '--md', '--out', join(root, 'share.md')], root);
      expect(md.code).toBe(0);
      const mdBody = readFileSync(join(root, 'share.md'), 'utf8');
      expect(mdBody).toContain('## RuntimeAttackProof');
      expect(mdBody).toContain('## Timeline');
      expect(mdBody).toContain('CONTAINED');
      expect(mdBody).toContain('Controlled benchmark');
      expect(mdBody).not.toMatch(/\d+%/);

      const html = await capture(['report', '--html', '--out', join(root, 'share.html')], root);
      expect(html.code).toBe(0);
      const htmlBody = readFileSync(join(root, 'share.html'), 'utf8');
      expect(htmlBody).toContain('RuntimeAttackProof');
      expect(htmlBody).toContain('Timeline');
      expect(htmlBody).toContain('Prompt Injection → Secret Access');
      expect(htmlBody).toContain('Controlled benchmark');
      expect(htmlBody).not.toMatch(/agent is secure/i);
      expect(htmlBody).not.toContain(RUNTIME_SYNTHETIC_SECRET);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('does not label incomplete or unavailable runs as contained', () => {
    const base: RuntimeAttackResult = {
      attackId: 'prompt-injection-secret-access',
      name: 'Prompt Injection → Secret Access',
      scenario: 'Prompt Injection → Secret Access',
      agent: 'Claude Code',
      mode: 'runtime',
      contained: true,
      checks: [],
      proof: emptyRuntimeAttackProof(),
      expectedPolicy: 'SECRET_ACCESS',
      expectedDecision: 'BLOCK',
      expectedFinalState: 'RESTRICTED',
      observedPolicy: null,
      observedDecision: null,
      observedFinalState: null,
      evidenceRecorded: false,
      disclaimer: 'Do not claim complete security.',
    };

    const incomplete = buildSecurityReportFromRuntimeResult({
      ...base,
      outcome: 'PROOF_INCOMPLETE',
      secretExposure: 'NONE',
    });
    expect(incomplete.outcome).toBe('PROOF_INCOMPLETE');
    expect(incomplete.containedCount).toBe(0);
    expect(incomplete.tests?.[0]?.contained).toBe(false);
    expect(incomplete.topFinding?.outcome).not.toBe('contained');
    const incompleteText = formatExplainReport(incomplete);
    expect(incompleteText).toContain('PROOF INCOMPLETE');
    expect(incompleteText).not.toMatch(/Outcome:\nCONTAINED/);
    expect(incompleteText).toContain('Secret exposure: NONE');

    const leaked = buildSecurityReportFromRuntimeResult({
      ...base,
      contained: false,
      outcome: 'ATTACK_NOT_CONTAINED',
      secretExposure: 'LEAKED',
      observedDecision: 'ALLOW',
    });
    expect(leaked.outcome).toBe('ATTACK_NOT_CONTAINED');
    expect(leaked.secretExposure).toBe('SECRET EXPOSURE DETECTED');
    expect(leaked.containedCount).toBe(0);
    expect(formatReportMarkdown(leaked)).toContain('SECRET EXPOSURE DETECTED');
    expect(formatReportMarkdown(leaked)).not.toContain(RUNTIME_SYNTHETIC_SECRET);
    expect(formatReportHtml(leaked)).not.toMatch(/Outcome: CONTAINED/);

    const unavailable = buildSecurityReportFromRuntimeResult({
      ...base,
      outcome: 'RUNTIME_UNAVAILABLE',
      unavailableReason: 'Claude Code CLI not found on PATH',
    });
    expect(unavailable.outcome).toBe('RUNTIME_UNAVAILABLE');
    expect(unavailable.runtimeHonesty).toBe('RUNTIME UNAVAILABLE');
    expect(unavailable.containedCount).toBe(0);
    const unavailableText = formatExplainReport(unavailable);
    expect(unavailableText).toContain('RUNTIME UNAVAILABLE');
    expect(unavailableText).not.toMatch(/Outcome:\nCONTAINED/);
  });

  it('reads the newer demo-plane last.json when the repo copy is stale', async () => {
    const root = join(tmpdir(), `veyra-report-plane-${Date.now()}`);
    const repoReport = join(root, '.veyra', 'reports', 'last.json');
    const demoReport = join(root, 'examples', 'real-agent-demo', '.veyra', 'reports', 'last.json');
    mkdirSync(join(root, '.veyra', 'reports'), { recursive: true });
    mkdirSync(join(root, 'examples', 'real-agent-demo', '.veyra', 'reports'), { recursive: true });

    const stale = sampleSimReport();
    const fresh = containedRuntimeReport();
    writeFileSync(repoReport, `${JSON.stringify(stale, null, 2)}\n`);
    writeFileSync(demoReport, `${JSON.stringify(fresh, null, 2)}\n`);
    const older = new Date('2020-01-01T00:00:00Z');
    const newer = new Date('2026-01-01T00:00:00Z');
    utimesSync(repoReport, older, older);
    utimesSync(demoReport, newer, newer);

    try {
      const json = await capture(['report', '--json'], root);
      expect(json.code).toBe(0);
      const parsed = JSON.parse(json.out) as SecurityReport;
      expect(parsed.outcome).toBe('CONTAINED');
      expect(parsed.mode).toBe('runtime');
      expect(parsed.attackName).toBe('Prompt Injection → Secret Access');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

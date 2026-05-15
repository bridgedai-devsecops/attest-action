import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';
import { fail, getOptionalInput, getRequiredInput } from './lib/action-core';
import { getBooleanInput } from './lib/inputs';
import { appendJobSummary } from './lib/summary';
import { ConfigurationError } from './lib/errors';
import { parseEnum } from './lib/validation';

async function execFileStdout(cmd: string, args: readonly string[]): Promise<string> {
  return await new Promise((resolve, reject) => {
    cp.execFile(cmd, [...args], { maxBuffer: 50 * 1024 * 1024 }, (err, stdout) => {
      if (err) return reject(err);
      resolve(String(stdout ?? ''));
    });
  });
}

function normalizeSha256(d: string): string {
  const s = String(d ?? '').trim();
  const m = s.match(/sha256:([a-f0-9]{64})/i) ?? s.match(/^([a-f0-9]{64})$/i);
  if (!m) throw new ConfigurationError(`Invalid subject digest: ${d}`);
  return m[1]!.toLowerCase();
}

export async function run(): Promise<void> {
  const subjectName = getRequiredInput('subject-name');
  const subjectDigest = normalizeSha256(getRequiredInput('subject-digest'));
  const predicateType = getRequiredInput('predicate-type');
  const predicateFile = path.resolve(getRequiredInput('predicate-file'));
  const attestationFile = path.resolve(getRequiredInput('attestation-file'));
  const mode = parseEnum('mode', getOptionalInput('mode') || 'create-only', ['create-only', 'sign', 'verify'] as const);
  const signer = parseEnum('signer', getOptionalInput('signer') || 'cosign', ['cosign', 'github-attestation'] as const);
  const uploadToRekor = getBooleanInput('upload-to-rekor', false);
  const verifyRekor = getBooleanInput('verify-rekor', false);
  const expectedIssuer = getOptionalInput('expected-issuer');
  const expectedIdentity = getOptionalInput('expected-identity');
  const expectedRepo = getOptionalInput('expected-repo');
  const expectedWorkflow = getOptionalInput('expected-workflow');

  if (mode === 'verify') {
    const raw = await fs.promises.readFile(attestationFile, 'utf8');
    let doc: unknown;
    try {
      doc = JSON.parse(raw) as unknown;
    } catch {
      throw new ConfigurationError('Attestation file is not valid JSON');
    }
    const d = doc as Record<string, unknown>;
    const env = d.dsseEnvelope as Record<string, unknown> | undefined;
    const payloadB64 = String(env?.payload ?? '');
    if (!payloadB64) throw new ConfigurationError('verify mode requires dsseEnvelope.payload (base64)');
    const stmtRaw = Buffer.from(payloadB64, 'base64').toString('utf8');
    const stmt = JSON.parse(stmtRaw) as Record<string, unknown>;
    const subjects = stmt.subject as Array<Record<string, unknown>> | undefined;
    const digests = subjects?.[0]?.digest as Record<string, string> | undefined;
    const sha = String(digests?.sha256 ?? '').toLowerCase();
    if (!sha || sha !== subjectDigest) {
      throw new ConfigurationError('Verification failed: subject digest mismatch');
    }
    if (String(stmt.predicateType ?? '') !== predicateType) {
      throw new ConfigurationError('Verification failed: predicateType mismatch');
    }
    if (expectedIssuer && !JSON.stringify(doc).includes(expectedIssuer)) {
      throw new ConfigurationError('Verification failed: expected issuer not found in attestation bundle');
    }
    if (expectedIdentity && !JSON.stringify(doc).includes(expectedIdentity)) {
      throw new ConfigurationError('Verification failed: expected identity not found in attestation bundle');
    }
    if (expectedRepo && !JSON.stringify(doc).includes(expectedRepo)) {
      throw new ConfigurationError('Verification failed: expected repo not found in attestation bundle');
    }
    if (expectedWorkflow && !JSON.stringify(doc).includes(expectedWorkflow)) {
      throw new ConfigurationError('Verification failed: expected workflow not found in attestation bundle');
    }
    if (verifyRekor) {
      throw new ConfigurationError(
        'verify-rekor=true requires Rekor integration; fail-closed until configured in your environment.',
      );
    }
    await appendJobSummary('## BridgedAI attestation\n\nVerification succeeded (local checks).\n');
    return;
  }

  const predicateJson = await fs.promises.readFile(predicateFile, 'utf8');
  let predicate: unknown;
  try {
    predicate = JSON.parse(predicateJson) as unknown;
  } catch {
    throw new ConfigurationError('predicate-file must contain JSON');
  }

  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: subjectName, digest: { sha256: subjectDigest } }],
    predicateType,
    predicate,
  };

  const payload = Buffer.from(JSON.stringify(statement), 'utf8').toString('base64');
  const envelope = {
    payloadType: 'application/vnd.in-toto+json',
    payload,
    signatures: [] as unknown[],
  };

  const bundle = { schemaVersion: 'bridgedai.dev/attestation-bundle/v1', dsseEnvelope: envelope, statement };
  await fs.promises.mkdir(path.dirname(attestationFile), { recursive: true });
  await fs.promises.writeFile(attestationFile, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8', mode: 0o644 });

  if (mode === 'sign') {
    if (signer === 'github-attestation') {
      throw new ConfigurationError(
        'signer=github-attestation requires workflow integration with `attestations: write` and gh CLI; not implemented in this portable action bundle.',
      );
    }
    try {
      await execFileStdout('cosign', ['version']);
    } catch {
      throw new ConfigurationError('cosign not found on PATH; install cosign for sign mode');
    }
    if (uploadToRekor) {
      core.warning('upload-to-rekor=true requires additional cosign/Rekor flags; fail-closed for now.');
      throw new ConfigurationError('Rekor upload is not enabled in this action version (fail-closed).');
    }
    core.info('cosign is present; full sign integration should be wired to your org’s key material (KMS/HSM).');
  }

  await appendJobSummary(`## BridgedAI attestation\n\n- **file**: \`${attestationFile}\`\n- **predicateType**: \`${predicateType}\`\n`);
}

if (process.env.VITEST !== 'true') {
  void run().catch((e) => {
    fail(e instanceof Error ? e : new Error(String(e)));
  });
}

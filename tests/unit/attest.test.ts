import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, expect, it, vi } from 'vitest';
import * as core from '@actions/core';
import { run } from '../../src/index';

describe('attest-action', () => {
  it('create-only writes bundle', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bdai-att-'));
    const pred = path.join(dir, 'predicate.json');
    const out = path.join(dir, 'out.json');
    fs.writeFileSync(pred, JSON.stringify({ foo: 'bar' }));

    vi.spyOn(core, 'info').mockImplementation(() => {});
    vi.spyOn(core, 'getInput').mockImplementation((name: string) => {
      const m: Record<string, string> = {
        'subject-name': 'name',
        'subject-digest': 'sha256:' + 'e'.repeat(64),
        'predicate-type': 'https://slsa.dev/provenance/v1',
        'predicate-file': pred,
        'attestation-file': out,
        mode: 'create-only',
        signer: 'cosign',
        'upload-to-rekor': 'false',
        'verify-rekor': 'false',
        'expected-issuer': '',
        'expected-identity': '',
        'expected-repo': '',
        'expected-workflow': '',
      };
      return m[name] ?? '';
    });

    await run();
    const txt = fs.readFileSync(out, 'utf8');
    expect(txt).toContain('dsseEnvelope');
  });
});

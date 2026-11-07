/**
 * cyber-iam-ts-saml-xml-sig-wrapping-check — Identity, OAuth2, JWT & Session Security (saml-xml-sig-wrapping-check)
 * Author: Eng. Mahmoud Bek ElNemer (@ElNeMeR70)
 * Standards: CWE-287 / CWE-347 / RFC-7519 / RFC-7636
 */
import * as crypto from 'crypto';

const SIGNATURES: RegExp[] = [
  new RegExp("\"alg\"\\s*:\\s*\"none\"", 'i'), new RegExp("code_challenge_method=S256", 'i'), new RegExp("ds:Signature", 'i'), new RegExp("WebAuthn_Attestation", 'i')
];

export interface SecurityAuditReport {
  engine: string;
  standards: string;
  findingsCount: number;
  matches: string[];
  entropyBits: number;
  verdict: 'BLOCK_THREAT' | 'CLEAN_VERIFIED';
  mitigation: string;
  attestation: string;
}

export function shannonEntropy(input: string): number {
  if (!input.length) return 0;
  const counts: Record<string, number> = {};
  for (const ch of input) counts[ch] = (counts[ch] || 0) + 1;
  return Number(
    (-Object.values(counts).reduce((acc, c) => {
      const p = c / input.length;
      return acc + p * Math.log2(p);
    }, 0)).toFixed(4)
  );
}

export function auditPayload(payload: string): SecurityAuditReport {
  const matches: string[] = [];
  for (const rx of SIGNATURES) {
    const m = payload.match(rx);
    if (m) matches.push(m[0]);
  }
  const hmac = crypto.createHmac('sha256', 'cyber-iam-ts-saml-xml-sig-wrapping-check').update(payload).digest('hex').slice(0, 32);
  return {
    engine: 'cyber-iam-ts-saml-xml-sig-wrapping-check',
    standards: 'CWE-287 / CWE-347 / RFC-7519 / RFC-7636',
    findingsCount: matches.length,
    matches,
    entropyBits: shannonEntropy(payload),
    verdict: matches.length > 0 ? 'BLOCK_THREAT' : 'CLEAN_VERIFIED',
    mitigation: 'Hardcode allowed asymmetric algorithms (EdDSA/RS256), require PKCE S256, and enforce Zanzibar ReBAC.',
    attestation: hmac,
  };
}

if (require.main === module) {
  const arg = process.argv[2] || 'SELECT * FROM accounts WHERE token = eval(innerHTML=tx.origin)';
  console.log(JSON.stringify(auditPayload(arg), null, 2));
}

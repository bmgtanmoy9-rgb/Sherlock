import assert from 'node:assert/strict';
import {
  computeSuspicionScore,
  getWorkedExampleCaseReport,
  inspectDomainIdentity,
  inspectImpersonation,
  isPrivateOrReservedHost,
  normalizeAndValidateUrl,
} from './ruleEngine.ts';
import type { CheckStageId, CheckStatus, Clue } from '../types/sherlock.ts';

function createAllDoneStatuses(): Record<CheckStageId, CheckStatus> {
  return {
    domain_identity: 'done',
    impersonation: 'done',
    domain_age: 'done',
    reputation: 'done',
    redirects_page: 'done',
    certificate: 'done',
    security_posture: 'done',
    witness: 'done',
  };
}

function runTests() {
  console.log('🔍 Running SHERLOCK Deterministic Rule Engine Unit Tests...\n');

  // 1. Worked Example Test (paypa1-secure-login.example -> 87/100)
  const worked = getWorkedExampleCaseReport();
  assert.equal(worked.index, 87, 'Worked example Suspicion Index must equal 87');
  assert.equal(worked.level, 'highly_suspicious', 'Worked example level must be highly_suspicious');
  assert.equal(worked.confidence, 'high', 'Worked example confidence must be high');
  console.log('✅ Test 1 Passed: Worked example paypa1-secure-login.example scores 87/100 (Highly suspicious, High confidence)');

  // 2. Reputation Override Rule Test (must set index >= 90 and place override clue first)
  const overrideClues: Clue[] = [
    {
      id: 'minor-header',
      code: 'CLUE-SEC-01',
      name: 'Missing HSTS header',
      finding: 'HSTS header not present',
      severity: 'low',
      explanation: 'Missing header',
      howChecked: 'HTTP headers',
      points: 2,
      category: 'security_headers',
    },
    {
      id: 'feed-hit',
      code: 'CLUE-REP-01',
      name: 'Listed on OpenPhish threat feed',
      finding: 'Confirmed phishing entry in OpenPhish feed',
      severity: 'critical',
      explanation: 'Verified threat listing',
      howChecked: 'Reputation feed lookup',
      points: 95,
      category: 'reputation_override',
      isOverride: true,
    },
  ];
  const overrideResult = computeSuspicionScore(overrideClues, createAllDoneStatuses(), true);
  assert.ok((overrideResult.index ?? 0) >= 90, 'Override rule must guarantee index >= 90');
  assert.equal(overrideResult.sortedClues[0].id, 'feed-hit', 'Override clue must be sorted first');
  assert.equal(overrideResult.level, 'highly_suspicious');
  console.log('✅ Test 2 Passed: Reputation feed override forces index >= 90 and places feed listing first');

  // 3. Community Reports Corroboration Cap Test
  const uncorroboratedCommunity: Clue[] = [
    {
      id: 'comm-only',
      code: 'CLUE-WIT-01',
      name: 'Multiple community reports',
      finding: '8 uncorroborated reports',
      severity: 'caution',
      explanation: 'Community reports require corroboration',
      howChecked: 'Witness DB',
      points: 10,
      category: 'community_reports',
    },
  ];
  const uncorroboratedScore = computeSuspicionScore(uncorroboratedCommunity, createAllDoneStatuses(), true);
  assert.equal(
    uncorroboratedScore.index,
    3,
    'Uncorroborated community reports must be capped at 3 points so a single brigade cannot push a site into Caution/High Risk'
  );
  console.log('✅ Test 3 Passed: Community reports are capped when no other technical category fires');

  // 4. Inconclusive Verdict When Too Few Checks Complete
  const failedStatuses: Record<CheckStageId, CheckStatus> = {
    domain_identity: 'done',
    impersonation: 'done',
    domain_age: 'timed_out',
    reputation: 'failed',
    redirects_page: 'timed_out',
    certificate: 'failed',
    security_posture: 'timed_out',
    witness: 'done',
  };
  const inconclusiveResult = computeSuspicionScore([], failedStatuses, false);
  assert.equal(inconclusiveResult.level, 'inconclusive', 'Must return inconclusive when < 4 checks succeed');
  assert.equal(inconclusiveResult.index, null, 'Inconclusive result must not show a falsely reassuring numeric score');
  console.log('✅ Test 4 Passed: Incomplete investigation (< 4 checks) returns Inconclusive instead of a falsely reassuring score');

  // 5. Privacy Sanitization & SSRF Guard Test
  const sanitized = normalizeAndValidateUrl('https://Example.com/login/auth?token=secret123&session=abc#frag');
  assert.equal(sanitized.valid, true);
  assert.equal(sanitized.host, 'example.com');
  assert.equal(
    sanitized.sanitizedUrl,
    'https://example.com/login/auth',
    'Query strings and fragments must be stripped before storage or sharing'
  );

  assert.equal(isPrivateOrReservedHost('127.0.0.1'), true, 'Loopback must be blocked');
  assert.equal(isPrivateOrReservedHost('169.254.169.254'), true, 'Cloud metadata IP must be blocked');
  assert.equal(isPrivateOrReservedHost('192.168.1.50'), true, 'RFC1918 private IP must be blocked');
  assert.equal(isPrivateOrReservedHost('10.0.0.1'), true, '10/8 private IP must be blocked');
  assert.equal(isPrivateOrReservedHost('github.com'), false, 'Public domain must be allowed');
  console.log('✅ Test 5 Passed: Query strings stripped and SSRF guard blocks loopback, RFC1918, and cloud metadata IPs');

  // 6. Impersonation & Domain Identity Detection Test
  const impClues = inspectImpersonation('paypa1-secure-login.example');
  assert.ok(impClues.length > 0 && impClues[0].points >= 25, 'Must detect homoglyph lookalike of PayPal');
  const officialClues = inspectImpersonation('www.paypal.com');
  assert.equal(officialClues.length, 0, 'Official PayPal domain must trigger 0 impersonation clues');
  const idClues = inspectDomainIdentity('198.51.100.42', 'http://198.51.100.42/login', true, 92);
  assert.ok(idClues.length >= 3, 'Must flag IP literal host, @ symbol, and long URL');
  console.log('✅ Test 6 Passed: Homoglyph impersonation and domain identity heuristics work accurately\n');

  console.log('🎩 All SHERLOCK Rule Engine unit tests passed!');
}

runTests();

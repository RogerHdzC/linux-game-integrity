import { Checks, Outcome } from "../../../packages/policy-engine";

// Implemented HTTP v1 responses; historical draft schemas are separate designs.
export interface EnrollmentResponse {
  enrollmentId: string;
  keyProvenance: "UNPROVEN";
}
export interface ChallengeResponse {
  schemaVersion: 1;
  challengeId: string;
  nonce: string;
  policyVersion: string;
  pcrBank: "sha256";
  pcrs: readonly number[];
  expiresAt: string;
}
export interface EvaluationResponse {
  schemaVersion: 1;
  evaluationId: string;
  challengeId: string;
  policyVersion: string;
  result: Outcome;
  checks: Checks;
  reasons: string[];
}

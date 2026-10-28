import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  HttpException,
} from "@nestjs/common";
import { randomBytes, randomUUID, createPublicKey } from "node:crypto";
import { Pool } from "pg";
import { Checks, decide, POLICY } from "../../../packages/policy-engine";
import {
  ChallengeResponse,
  EnrollmentResponse,
  EvaluationResponse,
} from "./responses";
import { checkQuote } from "./quote";
import { evidence, identifier, object } from "./input";

export class Verifier {
  constructor(readonly pool: Pool) {}
  async enroll(body: unknown): Promise<EnrollmentResponse> {
    const input = object(body, ["publicKey"]);
    if (
      typeof input.publicKey !== "string" ||
      input.publicKey.length > 8192 ||
      !input.publicKey.startsWith("-----BEGIN PUBLIC KEY-----")
    )
      throw new BadRequestException("INVALID_PUBLIC_KEY");
    let pem: string;
    try {
      const key = createPublicKey(input.publicKey);
      if (
        key.asymmetricKeyType !== "rsa" ||
        key.asymmetricKeyDetails?.modulusLength !== 2048
      )
        throw new Error();
      pem = key.export({ type: "spki", format: "pem" }).toString();
    } catch {
      throw new BadRequestException("UNSUPPORTED_PUBLIC_KEY");
    }
    const id = randomUUID();
    await this.pool.query(
      "INSERT INTO lgi_enrollments(id,principal,public_key,provenance) VALUES($1,'lab-client',$2,'UNPROVEN')",
      [id, pem],
    );
    return { enrollmentId: id, keyProvenance: "UNPROVEN" };
  }
  async revoke(id: string): Promise<{ revoked: true }> {
    const r = await this.pool.query(
      "UPDATE lgi_enrollments SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1 RETURNING id",
      [identifier(id)],
    );
    if (!r.rowCount) throw new NotFoundException();
    return { revoked: true };
  }
  async challenge(body: unknown): Promise<ChallengeResponse> {
    const enrollmentId = identifier(
      object(body, ["enrollmentId"]).enrollmentId,
    );
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(19283642)");
      const count = await client.query(
        "SELECT count(*)::integer AS n FROM lgi_challenges WHERE created_at > now()-interval '1 minute'",
      );
      if (count.rows[0].n >= 60) throw new HttpException("RATE_LIMITED", 429);
      const e = await client.query(
        "SELECT id FROM lgi_enrollments WHERE id=$1 AND principal='lab-client' AND revoked_at IS NULL FOR UPDATE",
        [enrollmentId],
      );
      if (!e.rowCount) throw new NotFoundException("ENROLLMENT_UNAVAILABLE");
      const id = randomUUID(),
        nonce = randomBytes(32).toString("hex");
      const r = await client.query(
        "INSERT INTO lgi_challenges(id,enrollment_id,principal,nonce,policy_version,expires_at) VALUES($1,$2,'lab-client',$3,$4,now()+$5*interval '1 second') RETURNING expires_at",
        [id, enrollmentId, nonce, POLICY.version, POLICY.ttlSeconds],
      );
      await client.query("COMMIT");
      return {
        schemaVersion: 1,
        challengeId: id,
        nonce,
        policyVersion: POLICY.version,
        pcrBank: "sha256",
        pcrs: POLICY.pcrs,
        expiresAt: r.rows[0].expires_at.toISOString(),
      };
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }
  async evaluate(body: unknown): Promise<EvaluationResponse> {
    const input = evidence(body);
    // Commit reservation before crypto: crashes/storage errors cannot reopen the challenge.
    const reservation = await this.pool.query(
      "UPDATE lgi_challenges SET consumed_at=now() WHERE id=$1 AND principal='lab-client' AND consumed_at IS NULL AND expires_at>now() RETURNING *",
      [input.challengeId],
    );
    if (!reservation.rowCount)
      throw new ConflictException("CHALLENGE_UNAVAILABLE");
    const c = reservation.rows[0];
    const checks: Checks = {
      keyProvenance: "UNAVAILABLE",
      signature: "NOT_CHECKED",
      freshness: input.nonce === c.nonce ? "NOT_CHECKED" : "FAILED",
      pcrBinding: "NOT_CHECKED",
      measurements: "UNAVAILABLE",
      policy: "UNAVAILABLE",
    };
    const reasons: string[] = [
      "KEY_PROVENANCE_UNPROVEN",
      "MEASUREMENT_COVERAGE_UNVERIFIED",
      "NO_APPROVED_BASELINE",
    ];
    if (c.policy_version !== POLICY.version) {
      checks.policy = "FAILED";
      reasons.push("POLICY_RETIRED");
    }
    const enrollment = await this.pool.query(
      "SELECT public_key,revoked_at FROM lgi_enrollments WHERE id=$1",
      [c.enrollment_id],
    );
    const e = enrollment.rows[0];
    if (!e || e.revoked_at) {
      checks.keyProvenance = "FAILED";
      reasons.push("ENROLLMENT_REVOKED");
    } else if (!input.quote) reasons.push("QUOTE_MISSING");
    else {
      try {
        const q = checkQuote(input.quote, e.public_key, c.nonce);
        checks.signature = q.signature ? "VERIFIED" : "FAILED";
        if (!q.signature) reasons.push("INVALID_SIGNATURE");
        else {
          checks.freshness =
            q.nonce && input.nonce === c.nonce ? "VERIFIED" : "FAILED";
          checks.pcrBinding = q.pcrBinding ? "VERIFIED" : "FAILED";
          if (!q.nonce || input.nonce !== c.nonce)
            reasons.push("NONCE_MISMATCH");
          if (!q.pcrBinding) reasons.push("PCR_DIGEST_MISMATCH");
        }
      } catch {
        checks.signature = "FAILED";
        reasons.push("INVALID_OR_UNSUPPORTED_QUOTE");
      }
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const current = await client.query(
        "SELECT revoked_at FROM lgi_enrollments WHERE id=$1 FOR UPDATE",
        [c.enrollment_id],
      );
      if (!current.rowCount || current.rows[0].revoked_at) {
        checks.keyProvenance = "FAILED";
        reasons.push("ENROLLMENT_REVOKED");
      }
      const result: EvaluationResponse = {
        schemaVersion: 1,
        evaluationId: randomUUID(),
        challengeId: input.challengeId,
        policyVersion: c.policy_version,
        result: decide(checks),
        checks,
        reasons: [...new Set(reasons)],
      };
      await client.query(
        "INSERT INTO lgi_evaluations(id,challenge_id,principal,policy_version,result,checks,reasons) VALUES($1,$2,'lab-client',$3,$4,$5,$6)",
        [
          result.evaluationId,
          result.challengeId,
          result.policyVersion,
          result.result,
          JSON.stringify(checks),
          JSON.stringify(result.reasons),
        ],
      );
      await client.query("COMMIT");
      return result;
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }
  async cleanup(): Promise<void> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(
        "DELETE FROM lgi_evaluations WHERE created_at<now()-interval '30 days'",
      );
      await c.query(
        "DELETE FROM lgi_challenges WHERE expires_at<now()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM lgi_evaluations e WHERE e.challenge_id=lgi_challenges.id)",
      );
      await c.query(
        "DELETE FROM lgi_enrollments WHERE revoked_at<now()-interval '30 days' AND NOT EXISTS(SELECT 1 FROM lgi_challenges c WHERE c.enrollment_id=lgi_enrollments.id)",
      );
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
}

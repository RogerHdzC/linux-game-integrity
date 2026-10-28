import "reflect-metadata";
import {
  Body,
  Controller,
  Post,
  Param,
  Module,
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpException,
  Headers,
  UnauthorizedException,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { raw, Request, Response, NextFunction } from "express";
import { timingSafeEqual } from "node:crypto";
import { Pool } from "pg";
import { Verifier } from "./service";
import { parseJson, object } from "./input";

@Catch()
class Errors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost): void {
    const status = error instanceof HttpException ? error.getStatus() : 503;
    host
      .switchToHttp()
      .getResponse<Response>()
      .status(status)
      .json({
        error: status >= 500 ? "SERVICE_UNAVAILABLE" : "REQUEST_REJECTED",
      });
  }
}
export async function createApp(
  pool: Pool,
  clientToken: string,
  adminToken: string,
) {
  if (
    Buffer.byteLength(clientToken) < 32 ||
    Buffer.byteLength(adminToken) < 32 ||
    clientToken === adminToken
  )
    throw new Error("Distinct tokens of at least 32 bytes are required");
  const service = new Verifier(pool);
  function requireAdmin(header: string | undefined): void {
    const expected = Buffer.from("Bearer " + adminToken),
      actual = Buffer.from(header ?? "");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
      throw new UnauthorizedException();
  }
  @Controller("v1")
  class Api {
    @Post("enrollments") enroll(
      @Body() body: unknown,
      @Headers("authorization") auth: string | undefined,
    ) {
      requireAdmin(auth);
      return service.enroll(body);
    }
    @Post("enrollments/:id/revoke") revoke(
      @Param("id") id: string,
      @Body() body: unknown,
      @Headers("authorization") auth: string | undefined,
    ) {
      requireAdmin(auth);
      object(body, []);
      return service.revoke(id);
    }
    @Post("challenges") challenge(@Body() body: unknown) {
      return service.challenge(body);
    }
    @Post("evaluations") evaluate(@Body() body: unknown) {
      return service.evaluate(body);
    }
  }
  @Module({ controllers: [Api] })
  class App {}
  const app = await NestFactory.create(App, {
    logger: false,
    bodyParser: false,
  });
  app.use((req: Request, res: Response, next: NextFunction) => {
    const expected = Buffer.from(
      `Bearer ${req.path.startsWith("/v1/enrollments") ? adminToken : clientToken}`,
    );
    const actual = Buffer.from(req.headers.authorization ?? "");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (
      actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)
    ) {
      res.status(401).json({ error: "UNAUTHORIZED" });
      return;
    }
    next();
  });
  app.use(raw({ type: "application/json", limit: "64kb", inflate: false }));
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!Buffer.isBuffer(req.body)) {
      res.status(415).json({ error: "JSON_REQUIRED" });
      return;
    }
    try {
      req.body = parseJson(req.body.toString("utf8"));
      next();
    } catch {
      res.status(400).json({ error: "INVALID_JSON" });
    }
  });
  app.use(
    (
      err: { status?: number },
      _req: Request,
      res: Response,
      _next: NextFunction,
    ) => {
      res
        .status(err.status === 413 ? 413 : 400)
        .json({ error: "INVALID_BODY" });
    },
  );
  app.useGlobalFilters(new Errors());
  await app.init();
  return { app, service };
}
async function main(): Promise<void> {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL required");
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 5,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
  });
  const { app, service } = await createApp(
    pool,
    process.env.LGI_CLIENT_TOKEN ?? "",
    process.env.LGI_ADMIN_TOKEN ?? "",
  );
  await pool.query("SELECT version FROM lgi_migrations WHERE version=1");
  await service.cleanup();
  const timer = setInterval(() => {
    service.cleanup().catch(() => console.error("Retention cleanup failed"));
  }, 3600000);
  timer.unref();
  await app.listen(3000, "127.0.0.1");
  const server = app.getHttpServer();
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  for (const signal of ["SIGINT", "SIGTERM"])
    process.once(signal, () => {
      clearInterval(timer);
      void app.close().then(() => pool.end());
    });
}
if (require.main === module)
  main().catch(() => {
    console.error("Verifier startup failed");
    process.exitCode = 1;
  });

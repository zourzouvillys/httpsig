import { describe, it, expect } from "vitest";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { request as undiciRequest } from "undici";
import { createSigningRequest } from "../src/integrations/undici.js";
import {
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  verifyMessage,
} from "../src/index.js";
import type { HttpMessage, Algorithm } from "../src/index.js";

function generateEd25519Keys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close(),
      });
    });
  });
}

function incomingToMessage(req: http.IncomingMessage, baseUrl: string): HttpMessage {
  const url = new URL(req.url ?? "/", baseUrl);
  return {
    isRequest: true,
    method: req.method,
    url,
    headerValues(name: string): string[] {
      const v = req.headers[name.toLowerCase()];
      if (!v) return [];
      return Array.isArray(v) ? v : [v];
    },
  };
}

describe("undici wrapper", () => {
  it("signs requests and server can verify", async () => {
    const { publicKey, privateKey } = generateEd25519Keys();
    const signingKey = newEd25519SigningKey("undici-key", privateKey);
    const verifyingKey = newEd25519VerifyingKey("undici-key", publicKey);

    const server = await startServer(async (req, res) => {
      const msg = incomingToMessage(req, `http://${req.headers.host}`);
      try {
        const result = await verifyMessage(
          msg,
          async (keyId: string, _alg: Algorithm | undefined) => {
            if (keyId === "undici-key") return verifyingKey;
            throw new Error("key not found");
          },
        );
        res.writeHead(200);
        res.end(`verified:${result.keyId}`);
      } catch (e) {
        res.writeHead(401);
        res.end(String(e));
      }
    });

    try {
      const signedRequest = createSigningRequest(undiciRequest as any, {
        key: signingKey,
      });

      const { statusCode, body } = await signedRequest(`${server.url}/test`);
      expect(statusCode).toBe(200);
      const text = await body.text();
      expect(text).toBe("verified:undici-key");
    } finally {
      server.close();
    }
  });
});
